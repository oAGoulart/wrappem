#include <Windows.h>
#include <iostream>
#pragma pack(1)

#pragma comment(lib, "User32.lib")

HINSTANCE hInst = 0;
HINSTANCE hL = 0;

extern "C" FARPROC address[17] = {0};

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		MessageBox(NULL, "This program has been hooked", "Hooked", MB_ICONEXCLAMATION | MB_YESNO);
		std::cout << "hooked\n";
		hInst = hinstDLL;
		hL = LoadLibrary(".\\versionHooked.dll");
		if (!hL) return FALSE;
		
		address[0] = GetProcAddress(hL, "GetFileVersionInfoA");
		address[1] = GetProcAddress(hL, "GetFileVersionInfoByHandle");
		address[2] = GetProcAddress(hL, "GetFileVersionInfoExA");
		address[3] = GetProcAddress(hL, "GetFileVersionInfoExW");
		address[4] = GetProcAddress(hL, "GetFileVersionInfoSizeA");
		address[5] = GetProcAddress(hL, "GetFileVersionInfoSizeExA");
		address[6] = GetProcAddress(hL, "GetFileVersionInfoSizeExW");
		address[7] = GetProcAddress(hL, "GetFileVersionInfoSizeW");
		address[8] = GetProcAddress(hL, "GetFileVersionInfoW");
		address[9] = GetProcAddress(hL, "VerFindFileA");
		address[10] = GetProcAddress(hL, "VerFindFileW");
		address[11] = GetProcAddress(hL, "VerInstallFileA");
		address[12] = GetProcAddress(hL, "VerInstallFileW");
		address[13] = GetProcAddress(hL, "VerLanguageNameA");
		address[14] = GetProcAddress(hL, "VerLanguageNameW");
		address[15] = GetProcAddress(hL, "VerQueryValueA");
		address[16] = GetProcAddress(hL, "VerQueryValueW");
		break;

	case DLL_PROCESS_DETACH:
		FreeLibrary(hL);
		break;

	default:
		return FALSE;
	}
	return TRUE;
}
