/*
  Copyright (c) 2021 Augusto Goulart
  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:
  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.
  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
*/
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <imagehlp.h>
#include <iostream>
#include <fstream>
#include <string>
#include <list>
#include <cstdint>
#include <filesystem>

#pragma comment(lib, "Imagehlp.lib");

#define PROJECT_NAME "WrappEm"
#define PROJECT_VERSION "v0.2.0"

#define _STR(a) #a

#if !defined(NOCOLOR)
#define _C(c, str) "\033[" _STR(c) "m" str "\033[m"
#else
#define _C(c, str) str
#endif

using namespace std;
using namespace std::filesystem;

inline uint32_t Align(uint32_t value, PIMAGE_SECTION_HEADER section)
{
  return (value == 0) ? value :
    value - section->VirtualAddress + section->PointerToRawData;
}

inline uint32_t AlignSize(const uint32_t length, const uint32_t align)
{
  uint32_t n = 0;
  while (n < length)
    n += align;
  return n;
}

inline ptrdiff_t FindOffset(void* first, void* second)
{
  return reinterpret_cast<char*>(second) - reinterpret_cast<char*>(first);
}
