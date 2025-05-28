#pragma once

#include <cstddef>
#include <cstdio>
#include <filesystem>

#define __str(s) #s
#define __xstr(s) __str(s)
#define __c(c, str) "\033[" __str(c) "m" str "\033[m"

inline uintmax_t FileSize(const char* filename)
{
  return std::filesystem::file_size(filename);
}

inline void MkDir(const char* filename)
{
  std::filesystem::create_directory(filename);
}
