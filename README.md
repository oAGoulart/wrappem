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

## Explored methods

- Method I: Intra-section `Import Directory` relocation
- Method II: In-place `Import Section` reconstruction
- Method III: End-of-file `Import section` relocation

> [!WARNING]
> Currently, only [Method I](#method-i) and [Method III](#method-iii) are implemented.

## Target manipulation steps

![Activity diagram](assets/act.png)
