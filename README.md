![WrappEm](assets/logo_wide.png)

![Platform](https://img.shields.io/badge/platform-win--32%20%7C%20win--64-blue)
![GitHub release (latest by date)](https://img.shields.io/github/v/release/oAGoulart/wrappem?color=green)
[![License](https://img.shields.io/badge/License-MS--RL-blue)](./LICENSE)

This tool explores three distinctive methods of Windows Image
Loader subversion for adversarial payload execution. These methods leverage
byte-based manipulation techniques to modify a binary file’s Import Directory
and, when necessary, its Import Section. This forces Windows to load an additional
executable binary into the host process virtual address space. These methods –-
which rely on importing an external payload –- can be used as alternatives for
traditional export forwarding techniques that rely on structurally empty binaries.

## Building

No dependencies, all `PE Format` structs are defined within `PEFormat.h`.

**MinGW build:**
```sh
g++ -g main.cpp -Og -o WrappEm.exe -std=c++17
```

**LLVM-clang build:**
```sh
clang++ -g main.cpp -Og -o WrappEm.exe -std=c++17
```

**MSVC build:**
```sh
cl main.cpp /std:c++17 /EHsc /out:WrappEm.exe /Debug /Og
```

## Artifacts

Resulting artifacts from using this tool (at `/artifacts`):

> [!CAUTION]
> Use it at your own risk!

- Payload -- sample source and binaries for the code to execute at runtime.
- DLLs -- subverting Windows Image Loader to load `payload.dll` by the byte-manipulated DLL `version.dll` (modified by this tool) which is loaded by `benignTarget.exe`.
- Executable -- directly modifying an executable (`main.exe`, manipulated by this tool) to load `payload.dll`.
- Proxy -- manually building an export-forwarding DLL (for comparison with byte manipulation).

## Target manipulation steps

![Activity diagram](assets/act.png)
