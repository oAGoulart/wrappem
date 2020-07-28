#include <Windows.h>
#include <iostream>

#pragma comment(lib, "Version.lib")

int main() {
  DWORD pot;
  DWORD pop = GetFileVersionInfoSizeW(
    (LPCWSTR)L"exports.txt",
    &pot
  );
  std::cout << pop;
  std::cin.get();
}
