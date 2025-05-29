#include "PEFormat.h"
//#include "PEFile.h"
#include <memory>

int main()
{
  auto f = std::make_unique<wrappem::PatchPE>(
           "./version.dll", "yasl.dll", "Dummy");
  //auto f = std::make_unique<PEFile>("./dinput8.dll");
  //f->CreateNewImport("yasl.dll", "Dummy");
  //f->Save("./dinput8-payload.dll");

  return 0;
}
