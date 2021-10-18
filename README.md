[![WrappEm](https://live.staticflickr.com/65535/50212827266_ecedc91f80_h.jpg)]()

[![MSBuild](https://github.com/oAGoulart/wrappem/actions/workflows/msbuild.yml/badge.svg)](https://github.com/oAGoulart/wrappem/actions/workflows/msbuild.yml)
![Platform](https://img.shields.io/badge/platform-win--32%20%7C%20win--64-blue)
![GitHub release (latest by date)](https://img.shields.io/github/v/release/oAGoulart/wrappem?color=green)
[![License](https://img.shields.io/badge/license-MIT-informational.svg)](https://opensource.org/licenses/MIT)

This is a small tool that can generate a hooked PE file which will import your custom DLL into its process.
With this you can inject a payload into a process using a DLL.

I took inspiration to make this tool from Michael Chourdakis' [article], but his implementation was not suited for my needs, so after some research and testing I created this tool.

The first implementation I made used the same method described in the article to create a proxy DLL, this version however modifies a DLL/Exe imports table to force Windows to import your payload DLL into the process.

If you're interested in this method you can learn more about [PE Format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format) and the [Import Address Table](http://sandsprite.com/CodeStuff/Understanding_imports.html) (it's a lot of stuff tho, so get some coffee first).

## Usage

If you already have the binaries:

```sh
wrappem [--help] <target> <payloadDll> <dummyFunc> <outPath>
```

An example of how that would look like if I wanted to load `myPayload.dll` payload into `dinput8.dll` process (actually the process which imports it):

**NOTES:**
  1. The _dummy_ is just a empty function but must be exported by your DLL.
  2. Also, the target file will not be edited, the output is a modified copy of it.
  3. If you are using a `amd64` binary, it might not work when your target architecture doesn't match yours.

```sh
wrappem dinput8.dll myPayload.dll dummy out\\dinput8.dll
```

## Binaries

You can find pre-compiled (Debug x86) binaries in the [releases] page.
The x86 binaries can be used for both archtectures.

---

# Contributions

Feel free to leave your contribution here, I would really appreciate it!
Also, if you have any doubts or troubles using this tool just contact me or leave an issue.


[releases]: https://github.com/oAGoulart/wrappem/releases
[article]: https://www.codeproject.com/articles/16541/create-your-proxy-dlls-automatically
