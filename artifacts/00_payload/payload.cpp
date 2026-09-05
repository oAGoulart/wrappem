#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

void Dummy()
{
}

BOOL WINAPI DllMain(HMODULE, ULONG reason, PVOID)
{
  if (reason == DLL_PROCESS_ATTACH)
  {
    MessageBox(nullptr, "Payload injected successfully!", "WrappEm", MB_ICONEXCLAMATION);
    return TRUE;
  }
  return FALSE;
}
