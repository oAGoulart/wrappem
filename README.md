[![WrappEm](https://live.staticflickr.com/65535/50212827266_ecedc91f80_h.jpg)]()

![Platform](https://img.shields.io/badge/platform-win--32%20%7C%20win--64-blue)
![GitHub release (latest by date)](https://img.shields.io/github/v/release/oAGoulart/wrappem?color=green)
[![License](https://img.shields.io/badge/License-MS--RL-blue)](./LICENSE)

> [!WARNING]
> Currently, only [Method I](#method-i) and [Method III](#method-iii) are implemented.

From old version:
> This is a small tool that can generate a hooked PE file which will import your custom DLL into its process.
> With this you can inject a payload into a process using a DLL.
> I took inspiration to make this tool from Michael Chourdakis' [article], but his implementation was not suited for my needs, so after some research and testing I created this tool.
> The first implementation I made used the same method described in the article to create a proxy DLL, this version however modifies a DLL/Exe imports table to force Windows to import your payload DLL into the process.
> If you're interested in this method you can learn more about [PE Format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format) and the [Import Table](http://sandsprite.com/CodeStuff/Understanding_imports.html) (it's a lot of stuff tho, so get some coffee first).

### Why "WrappEm"?
Because the first version of this tool would literally "wrap" its target to be used as a proxy DLL, so this "wrap" would serve only to redirect its exported calls to the original DLL. This is no longer the method used by this tool.

## Building

No dependencies, all PE Format structs are defined within `PEFormat.h`.

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

## Method I

**Requirements:**
1. Enough padding space for import table size plus one entry;
2. Import table size bigger or equal to payload data size.

<details>
  <summary>Method I: import table relocation</summary>
  ```text
  standard idata section structure               after relocation
  ────────┬──────────────────┬──────    ────────┬──────────────────┬──────
  .idata │                  │ start     .idata │                  │ start
  section │  address tables  │          section │  address tables  │
          │     (thunk)      │                  │     (thunk)      │
      ┌──┼                  ◄─┐           ┌────►                  ┼─┐
      │  ├──────────────────┤ │           │    ├──────────────────┤ │
      │  │                  ┼─┘           │    +                  + │
      │  │   import table   ┼──┐          │    +   payload data   + │
      │  │                  ┼─┐│          │┌───►                  + │
      │  ├──────────────────┤ ││          ││   ├──────────────────┤ │
      │  │                  ◄─┘│          ││   │                  │ │
      │  │   lookup tables  │  │          ││   │   lookup tables  │ │
      │  │      (32/64)     │  │          ││┌──►      (32/64)     │ │
      │┌─┼                  │  │          │││┌─┼                  │ │
      ││ ├──────────────────┤  │          ││││ ├──────────────────┤ │
      │└─►                  ◄──┘          │││└─►                  ◄─┘
      │  │names and ordinals│             │││  │names and ordinals│
      └──►                  │             │││  │                  ◄─┐
          └──────────────────┘             │││  ├──────────────────┤ │
          :                  :             ││└──┼                  ┼─┘
          :     padding      :             │└───┼   import table   │
          :                  : end         └────┼                  │ end 
  ──────────────────────────────────    ────────┴──────────────────┴──────
  ```
</details>

## Method II

> [!CAUTION]
> **NOT IMPLEMENTED YET**

**Requirements:**
1. Enough padding space for one table entry plus data;
2. All relative virtual addresses (RVAs) in `idata` must be re-calculated.

<details>
  <summary>Method II: import section raw size expansion</summary>
  ```text
  ────────┬──────────────────┬──────
  .idata │  address tables  │ start
  section │     (thunk)      │
          │- - - - - - - - - │
      ┌──┼     payload      ◄─┐
      │  ├──────────────────┤ │
      │  │   import table   ┼─┘
      │  │- - - - - - - - - ┼──┐
      │  │     payload      ┼─┐│
      │  ├──────────────────┤ ││
      │  │   lookup tables  ◄─┘│
      │┌─┼      (32/64)     │  │
      ││ │- - - - - - - - - │  │
      ││ │     payload      │  │
      ││ ├──────────────────┤  │
      │└─►                  ◄──┘
      │  │names and ordinals│
      │  │- - - - - - - - - │
      │  │     payload      │
      └──►                  │
          └──────────────────┘
          :     padding      : end
  ──────────────────────────────────
  ```
</details>

## Method III

**Requirements:**
1. Offset of new section entry must be less than section alignment;
2. All RVAs must be incremented by virtual offset.

<details>
  <summary>Method III: import data section relocation</summary>
  ```text
              before append                           after append
          ┌──────────────────┐                   ┌──────────────────┐
  PE file │      headers     │           PE file │      headers     │
          │                  │                   │                  │
  ─────────┼──────────────────┼──────    ─────────┼──────────────────┼──────
  sections │                  │ start    sections │                  │ start
          │      .rsrc       │                   │      .rsrc       │
          ├──────────────────┤                   ├──────────────────┤
          │                  │                   │                  │
          │      .data       │                   │      .data       │
          ├──────────────────┤                   ├──────────────────┤
          │                  │                   │                  │
          │      .idata      │                   │     (empty)      │
          ├──────────────────┤                   ├──────────────────┤
          :                  :                   :                  :
          :       ...        :                   :       ...        :
          :                  :                   :                  :
          ├──────────────────┤                   ├──────────────────┤
          │                  │                   │                  │
          │                  │                   │                  │
          │      .text       │                   │      .text       │
          │                  │                   │                  │
          │                  │ end               │                  │
  ────────┴──────────────────┴──────     - - - - ┼──────────────────┼ - - -
                                                  │                  │
                                                  │      .idata      │ end
                                          ────────┴──────────────────┴──────
  ```
</details>

[article]: https://www.codeproject.com/articles/16541/create-your-proxy-dlls-automatically
