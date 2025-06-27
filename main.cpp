#include <memory>
#include "PEFormat.h"

int main()
{
  auto f = std::make_unique<wrappem::PatchPE>(
           "./version.dll", "yasl.dll", "Dummy");
  f->Save("./version-p.dll");
  return 0;
}
