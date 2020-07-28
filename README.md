[![WrappEm](https://live.staticflickr.com/65535/50160792103_f5ee23cefd_h.jpg)]()

[![License](https://img.shields.io/badge/license-MIT-informational.svg)](https://opensource.org/licenses/MIT)

This is a small tool that can automatically generate the code necessary to create a proxy DLL.
This is useful to make a starting point or if you just want to hook the original DLL.
I took inspiration to make this tool from Michael Chourdakis' [article], but his implementation was not suited for my needs, so after some research and testing I created this tool.

## Requirements

To use this tool you will need to:

+ have **Visual Studio 2019** development environment
+ have [nasm] >= **2.15** installed and on your PATH

## Usage

Given an DLL exports file, this tool will generate a C++ source file, an Assembly file and a DEF file to link the code together.

```sh
wrappem [--help] <dll> <exports> <original> <out>
```

### Generate exports file

To generate an exports file, open **Native Tools Command Prompt**, go to the original DLL path and run the command below:

```sh
dumpbin /exports some.dll > exports.txt
```

Where `some.dll` is the one you want to scan the exported functions.

## Binaries

You can find pre-compiled binaries in the [releases] page.

## Building the command line interface

If you don't want to use the pre-compiled binaries or if they didn't work for you, there's only one file to be compiled, just open **Native Tools Command Prompt** (the binary architecture will depend on the terminal environment) and then run the command below:

```sh
cl /EHsc wrappem.cpp
```

**NOTE:**
If you want to use this tool without text colors (or if your terminal doesn't support it), add `/DNOCOLOR` to the command above.

## Building generated files

Building can be done manually with the following commands on **Native Tools Command Prompt**:

```sh
nasm -f win64 dllmain.asm -o asm.obj
cl /c /Focpp dllmain.cpp
link /nologo /dll asm.obj cpp.obj /def:dllmain.def /out:main.dll
```

**NOTES:**
If you are using `Win32` change the option `-f win64` accordingly.
Also, change  the option `/out:` with the name of the proxy DLL.

---

# Contributions

Feel free to leave your contribution here, I would really appreciate it!
Also, if you have any doubts or troubles using this tool just contact me or leave an issue.


[releases]: https://github.com/oAGoulart/wrappem/releases
[article]: https://www.codeproject.com/articles/16541/create-your-proxy-dlls-automatically
[nasm]: https://nasm.us/
