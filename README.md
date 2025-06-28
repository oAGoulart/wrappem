[![WrappEm](https://live.staticflickr.com/65535/50212827266_ecedc91f80_h.jpg)]()

![Platform](https://img.shields.io/badge/platform-win--32%20%7C%20win--64-blue)
![GitHub release (latest by date)](https://img.shields.io/github/v/release/oAGoulart/wrappem?color=green)
[![License](https://img.shields.io/badge/License-MS--RL-blue)](./LICENSE)

**WARNING:** This version replaces the last import on the table, since expanding the import table requires modifying all *RVAs* inside `.idata`. I am, as of June 2025, working on a version that can do this.

This is a small tool that can generate a hooked PE file which will import your custom DLL into its process.
With this you can inject a payload into a process using a DLL.

I took inspiration to make this tool from Michael Chourdakis' [article], but his implementation was not suited for my needs, so after some research and testing I created this tool.

The first implementation I made used the same method described in the article to create a proxy DLL, this version however modifies a DLL/Exe imports table to force Windows to import your payload DLL into the process.

If you're interested in this method you can learn more about [PE Format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format) and the [Import Table](http://sandsprite.com/CodeStuff/Understanding_imports.html) (it's a lot of stuff tho, so get some coffee first). Also, consider checking my brief explanation on how this tool works here: [Injecting payloads in DLLs](https://oagoulart.github.io/rambles/injecting-payloads-in-dlls).

**UPDATE (May 27, 2025):** v1.0.0 is a refactored version of the same method used in v0.2.2. This code was originally written in 2021, but was forgotten on one of my backup drives.

## Usage

If you already have the binaries:

```sh
wrappem [--help] <target> <payload> <dummyname> <output>
```

An example of how this would look like if I wanted to import `myPayload.dll` payload into the virtual memory of a process that imports `dinput8.dll`:

```sh
wrappem dinput8.dll myPayload.dll dummy out/dinput8.dll
```

Then, put `out/dinput8.dll` at that process' executable root folder. When Windows tries to import it, your payload should be loaded into the process virtual memory (your payload should also be at the root folder).

*NOTE:* The _dummy_ is just an empty function, but it must be exported by your DLL.

## Binaries

You can find pre-compiled binaries on the [releases] page.


[releases]: https://github.com/oAGoulart/wrappem/releases
[article]: https://www.codeproject.com/articles/16541/create-your-proxy-dlls-automatically
