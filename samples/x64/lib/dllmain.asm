extern address

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
	mov rax, address
	jmp [rax + 0]

GetFileVersionInfoByHandle_:
	mov rax, address
	jmp [rax + 8]

GetFileVersionInfoExA_:
	mov rax, address
	jmp [rax + 16]

GetFileVersionInfoExW_:
	mov rax, address
	jmp [rax + 24]

GetFileVersionInfoSizeA_:
	mov rax, address
	jmp [rax + 32]

GetFileVersionInfoSizeExA_:
	mov rax, address
	jmp [rax + 40]

GetFileVersionInfoSizeExW_:
	mov rax, address
	jmp [rax + 48]

GetFileVersionInfoSizeW_:
	mov rax, address
	jmp [rax + 56]

GetFileVersionInfoW_:
	mov rax, address
	jmp [rax + 64]

VerFindFileA_:
	mov rax, address
	jmp [rax + 72]

VerFindFileW_:
	mov rax, address
	jmp [rax + 80]

VerInstallFileA_:
	mov rax, address
	jmp [rax + 88]

VerInstallFileW_:
	mov rax, address
	jmp [rax + 96]

VerLanguageNameA_:
	mov rax, address
	jmp [rax + 104]

VerLanguageNameW_:
	mov rax, address
	jmp [rax + 112]

VerQueryValueA_:
	mov rax, address
	jmp [rax + 120]

VerQueryValueW_:
	mov rax, address
	jmp [rax + 128]
