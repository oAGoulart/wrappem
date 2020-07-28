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
	mov eax, _address
	jmp [eax + 0]

GetFileVersionInfoByHandle_:
	mov eax, _address
	jmp [eax + 4]

GetFileVersionInfoExA_:
	mov eax, _address
	jmp [eax + 8]

GetFileVersionInfoExW_:
	mov eax, _address
	jmp [eax + 12]

GetFileVersionInfoSizeA_:
	mov eax, _address
	jmp [eax + 16]

GetFileVersionInfoSizeExA_:
	mov eax, _address
	jmp [eax + 20]

GetFileVersionInfoSizeExW_:
	mov eax, _address
	jmp [eax + 24]

GetFileVersionInfoSizeW_:
	mov eax, _address
	jmp [eax + 28]

GetFileVersionInfoW_:
	mov eax, _address
	jmp [eax + 32]

VerFindFileA_:
	mov eax, _address
	jmp [eax + 36]

VerFindFileW_:
	mov eax, _address
	jmp [eax + 40]

VerInstallFileA_:
	mov eax, _address
	jmp [eax + 44]

VerInstallFileW_:
	mov eax, _address
	jmp [eax + 48]

VerLanguageNameA_:
	mov eax, _address
	jmp [eax + 52]

VerLanguageNameW_:
	mov eax, _address
	jmp [eax + 56]

VerQueryValueA_:
	mov eax, _address
	jmp [eax + 60]

VerQueryValueW_:
	mov eax, _address
	jmp [eax + 64]
