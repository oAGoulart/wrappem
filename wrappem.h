/*
  Copyright (c) 2020 Augusto Goulart

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
#include "Windows.h"
#include "direct.h"
#include <iostream>
#include <vector>
#include <fstream>
#include <string>
#include <cstdio>
#include <cctype>

#define PROJECT_NAME "WrappEm"
#define PROJECT_VERSION "v0.1.6"

#define _STR(a) #a

#if !defined(NOCOLOR)
  #define _C(c, str) "\033[" _STR(c) "m" str "\033[m"
#else
  #define _C(c, str) str
#endif

using namespace std;

class Export
{
public:
  DWORD hint_;
  DWORD index_;
  string* name_;
  DWORD ordinal_;
  BOOL only_ordinal_;
  DWORD rva_;

  Export(const DWORD ordinal, const DWORD hint, const DWORD rva, const char* name, const DWORD index);
  ~Export();
};

inline string CstrToUpper(const string str);
inline DWORD GetDword(WORD high, WORD low);
inline void Mkdir(char* path);
inline string RemoveFileExt(char* filename);
