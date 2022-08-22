// Axel '0vercl0k' Souchet - December 18 2020
#include "resource.h"
#include <array>
#include <optional>
#include <shobjidl.h>
#include <windows.h>

DWORD WINAPI PayloadThread(LPVOID Module_) {
  const HMODULE Module = HMODULE(Module_);
  char CommandLine[] = R"(c:\windows\system32\notepad.exe)";
  STARTUPINFOA Si = {};
  Si.cb = sizeof(Si);
  PROCESS_INFORMATION Pi = {};
  if (CreateProcessA(nullptr, CommandLine, nullptr, nullptr, false, 0, nullptr,
                     nullptr, &Si, &Pi)) {
    CloseHandle(Pi.hThread);
    CloseHandle(Pi.hProcess);
  }

  std::array<wchar_t, MAX_PATH + 1> WallpaperFilePath;
  const wchar_t *Path = LR"(C:\ProgramData\ICONICS)";
  if (!GetTempFileNameW(Path, L"paracosme", 0, WallpaperFilePath.data())) {
    ExitThread(EXIT_FAILURE);
    return EXIT_FAILURE;
  }

  FILE *WallpaperFile = nullptr;
  _wfopen_s(&WallpaperFile, WallpaperFilePath.data(), L"wb");
  if (WallpaperFile == nullptr) {
    ExitThread(EXIT_FAILURE);
    return EXIT_FAILURE;
  }

  HRSRC ResourceHandle =
      FindResourceW(Module, MAKEINTRESOURCE(IDB_BITMAP1), L"JPG");
  HGLOBAL hLoaded = LoadResource(Module, ResourceHandle);
  LPVOID WallpaperContent = LockResource(hLoaded);
  DWORD WallpaperSize = SizeofResource(Module, ResourceHandle);
  fwrite(WallpaperContent, WallpaperSize, 1, WallpaperFile);
  fclose(WallpaperFile);
  FreeResource(hLoaded);

  if (hLoaded == nullptr || WallpaperSize == 0) {
    ExitThread(EXIT_FAILURE);
    return EXIT_FAILURE;
  }

  IDesktopWallpaper *Wallpaper = nullptr;
  HRESULT Hr = CoCreateInstance(__uuidof(DesktopWallpaper), nullptr, CLSCTX_ALL,
                                IID_PPV_ARGS(&Wallpaper));

  if (SUCCEEDED(Hr)) {
    Wallpaper->SetWallpaper(nullptr, WallpaperFilePath.data());
    Wallpaper->Release();
    Wallpaper = nullptr;
  }

  return true;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved) {
  if (fdwReason == DLL_PROCESS_ATTACH) {
    PayloadThread(hModule);
    TerminateThread(GetCurrentThread(), 0);
    return false;
  }

  return false;
}
