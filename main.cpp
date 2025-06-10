#include "PEFormat.h"
#include <memory>

int main()
{
  auto f = std::make_unique<wrappem::PatchPE>(
           "./version.dll", "yasl.dll", "Dummy");

  return 0;
}
