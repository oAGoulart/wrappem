#pragma once

#include <cstring>

#define PROJECT_NAME "WrappEm"
#define PROJECT_VERSION "v1.0.1"
#define PROJECT_LICENSE "MS-RL License"
#define PROJECT_COPYRIGHT "Copyright (c) 2025. Augusto Goulart."

#define __str(s) #s
#define __xstr(s) __str(s)
#define __c(c, str) "\033[" __str(c) "m" str "\033[m"

using std::memcmp;
using std::memset;
using std::strcmp;
