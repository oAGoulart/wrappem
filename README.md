[![WrappEm](https://live.staticflickr.com/65535/50212827266_ecedc91f80_h.jpg)]()

![Platform](https://img.shields.io/badge/platform-win--32%20%7C%20win--64-blue)
![GitHub release (latest by date)](https://img.shields.io/github/v/release/oAGoulart/wrappem?color=green)
[![License](https://img.shields.io/badge/License-MS--RL-blue)](./LICENSE)

**WARNING:** This version can only work if there's enough empty space on `idata` section. Two more methods are being worked on to allow for cases where not enough space is available.

From old version:
> This is a small tool that can generate a hooked PE file which will import your custom DLL into its process.
> With this you can inject a payload into a process using a DLL.
> I took inspiration to make this tool from Michael Chourdakis' [article], but his implementation was not suited for my needs, so after some research and testing I created this tool.
> The first implementation I made used the same method described in the article to create a proxy DLL, this version however modifies a DLL/Exe imports table to force Windows to import your payload DLL into the process.
> If you're interested in this method you can learn more about [PE Format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format) and the [Import Table](http://sandsprite.com/CodeStuff/Understanding_imports.html) (it's a lot of stuff tho, so get some coffee first). Also, consider checking my brief explanation on how this tool works here: [Injecting payloads in DLLs](https://oagoulart.github.io/rambles/injecting-payloads-in-dlls).

## Method I: import table relocation

**Requirements:**
1. Enough padding space for import table size plus one entry;
1. Import table size bigger or equal to payload data size.

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

## Method II: import table expansion

**NOT IMPLEMENTED YET**

**Requirements:**
1. Enough padding space for one table entry plus data;
1. All relative virtual addresses (RVAs) in `idata` must be re-calculated.

After import table expansion and re-building:
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

## Method III: import data section relocation

**NOT IMPLEMENTED YET**

**Requirements:**
1. Offset of new section entry must be less than section alignment;
1. All RVAs must be incremented by virtual offset.

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


[article]: https://www.codeproject.com/articles/16541/create-your-proxy-dlls-automatically
