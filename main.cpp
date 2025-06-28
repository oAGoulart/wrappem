#include <memory>
#include "PEFormat.h"
#include "shared.h"

int
main(int argc, char* argv[])
{
  try
  {
    std::cout << std::endl << "\t\t" << __c(36, PROJECT_NAME) << ' '
              << __c(36, PROJECT_VERSION) << std::endl
              << "\tCopyright (C) 2025. Augusto Goulart." << std::endl
              << "\tMicrosoft Reciprocal License (Ms-RL)" << std::endl;

  
    std::cout << std::endl << "    Parsing arguments..." << std::endl;
    if (argc > 1)
    {
      if (!strcmp(argv[1], "--help"))
      {
        std::cout << std::endl << "Usage: wrappem [--help] "
                  << __c(95, "<target> <payload> <dummyname> <output>")
                  << std::endl
                  << "  --help\t  show this help message" << std::endl
                  << "  " << __c(95, "target")
                  << "\t  filename of the targeted PE file" << std::endl
                  << "  " << __c(95, "payload")
                  << "\t  name of the DLL to be imported by the target"
                  << std::endl
                  << "  " << __c(95, "dummyname") << "\t  dummy function name"
                  << std::endl
                  << "  " << __c(95, "output") << "\t  output filename"
                  << std::endl;
        exit(EXIT_SUCCESS);
      }
      else if (argc < 5)
      {
        throw std::runtime_error("Not enough arguments, use --help");
      }
    }
    else
    {
      throw std::runtime_error("Arguments must be provided, use --help");
    }
    auto f = std::make_unique<wrappem::PatchPE>(argv[1], argv[2], argv[3]);
    f->Save(argv[4]);
    std::cout << __c(32, "    DONE!") << std::endl;
  }
  catch(const std::exception& e)
  {
    std::cerr << "    " << __c(41, " Error: ") << "  " << e.what() << std::endl;
    exit(EXIT_FAILURE);
  }
  exit(EXIT_SUCCESS);
}
