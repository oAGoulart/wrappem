#pragma once

#include <cstddef>
#include <cstdio>
#include <filesystem>

#define __str(s) #s
#define __xstr(s) __str(s)
#define __c(c, str) "\033[" __str(c) "m" str "\033[m"
