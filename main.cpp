#include "PEFile.h"
#include <memory>

int main()
{
  auto f = std::make_unique<PEFile>("main.exe");

  return 0;
}
