extern _address

section .text
	global GetFileVersionInfoA_
	global GetFileVersionInfoByHandle_
	global GetFileVersionInfoExA_
	global GetFileVersionInfoExW_
	global GetFileVersionInfoSizeA_
	global GetFileVersionInfoSizeExA_
	global GetFileVersionInfoSizeExW_
	global GetFileVersionInfoSizeW_
	global GetFileVersionInfoW_
	global VerFindFileA_
	global VerFindFileW_
	global VerInstallFileA_
	global VerInstallFileW_
	global VerLanguageNameA_
	global VerLanguageNameW_
	global VerQueryValueA_
	global VerQueryValueW_

GetFileVersionInfoA_:
	jmp [_address + 0]

GetFileVersionInfoByHandle_:
	jmp [_address + 4]

GetFileVersionInfoExA_:
	jmp [_address + 8]

GetFileVersionInfoExW_:
	jmp [_address + 12]

GetFileVersionInfoSizeA_:
	jmp [_address + 16]

GetFileVersionInfoSizeExA_:
	jmp [_address + 20]

GetFileVersionInfoSizeExW_:
	jmp [_address + 24]

GetFileVersionInfoSizeW_:
	jmp [_address + 28]

GetFileVersionInfoW_:
	jmp [_address + 32]

VerFindFileA_:
	jmp [_address + 36]

VerFindFileW_:
	jmp [_address + 40]

VerInstallFileA_:
	jmp [_address + 44]

VerInstallFileW_:
	jmp [_address + 48]

VerLanguageNameA_:
	jmp [_address + 52]

VerLanguageNameW_:
	jmp [_address + 56]

VerQueryValueA_:
	jmp [_address + 60]

VerQueryValueW_:
	jmp [_address + 64]
