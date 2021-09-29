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
#include "wrappem.h"

int main(int argc, char* argv[])
{
  try {
    cout << "\n\t\t" << _C(36, PROJECT_NAME) << ' ' << _C(36, PROJECT_VERSION) << '\n'
         << "\tCopyright (C) 2021 Augusto Goulart\n\n";

    if (argc > 1) {
      if (!strcmp(argv[1], "--help")) {
        cout << "Usage: wrappem [--help] "
             << _C(95, "<target> <payloadDll> <dummyFunc> <outPath>") << "\n\n"
             << "\t--help\t\tshow this help message\n"
             << '\t' << _C(95, "target") << "\t\tpath to original DLL to be edited\n"
             << '\t' << _C(95, "payloadDll") << "\tname of DLL to be loaded by target\n"
             << '\t' << _C(95, "dummyFunc") << "\tdummy function name from payloadDLL\n"
             << '\t' << _C(95, "outPath") << "\t\toutput path\n";
        exit(EXIT_SUCCESS);
      }
      else if (argc < 4)
        throw invalid_argument("Incorrect use of params, use --help");
    }
    else
      throw invalid_argument("Not enough arguments, use --help");

    PatchImportTable(argv[1], string(argv[2]), string(argv[3]), argv[4]);
  }
  catch (const exception& e) {
    cerr << "\t\t" << _C(41, " Error: ") << '\t' << e.what() << "\n\n";
    exit(EXIT_FAILURE);
  }
  exit(EXIT_SUCCESS);
}

static void PatchImportTable(const char* target, const string payloadDll,
                             const string dummyFunc, char* outPath)
{
  LOADED_IMAGE image;
  if (!MapAndLoad(target, NULL, &image, TRUE, FALSE))
    throw runtime_error("Could not map PE file");

  bool is64 = false; // NOTE: unused for the moment
  if ((image.FileHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) &&
      (image.FileHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC))
    is64 = true;
  else if ((image.FileHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) &&
           (image.FileHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC))
    throw runtime_error("Unknown computer architecture type");

  // copy original file data to memory
  cout << "\t- Read PE file\n";
  flush(cout);

  ifstream ifile;
  ifile.open(target, ifile.binary | ifile.in);
  const size_t dataSize = static_cast<size_t>(image.SizeOfImage);
  unique_ptr<char[]> data(new char[dataSize]);
  ifile.read(&data[0], dataSize);
  ifile.close();

  // add strings to last section
  cout << "\t- Parse data for last section\n";
  flush(cout);

  unique_ptr<char[]> newData(new char[dataSize]);
  uint32_t newDataIndex = 0;
  memcpy(&newData[newDataIndex], payloadDll.data(), payloadDll.length());
  newDataIndex += static_cast<uint32_t>(payloadDll.length());
  memset(&newData[newDataIndex], '\0', 3);
  newDataIndex += 3;
  memcpy(&newData[newDataIndex], dummyFunc.data(), dummyFunc.length());
  newDataIndex += static_cast<uint32_t>(dummyFunc.length());
  memset(&newData[newDataIndex], '\0', 19);
  newDataIndex += 19;

  // move original Directory Table to last section
  const uint32_t newDataPos = newDataIndex;
  bool foundSection = false;
  for (size_t i = 0; i < image.NumberOfSections; ++i) {
    if (!memcmp(image.Sections[i].Name, ".idata", IMAGE_SIZEOF_SHORT_NAME)) {
      cout << "\t\t+ Parse data directory table content\n";
      flush(cout);

      uint32_t length = image.FileHeader->OptionalHeader.DataDirectory[1].Size;
      uint32_t offset = Align(
        image.FileHeader->OptionalHeader.DataDirectory[1].VirtualAddress,
        &image.Sections[i]);
      memcpy(&newData[newDataPos], &data[offset], length);
      memset(&data[offset], '\0', length);
      newDataIndex += length;
      foundSection = true;
      break;
    }
  }
  if (!foundSection)
    throw runtime_error("Unable to find .idata section");

  // add new entry to Directory Table
  cout << "\t- Append generated data\n";
  flush(cout);

  PIMAGE_SECTION_HEADER lastSection = &image.Sections[image.NumberOfSections - 1];
  uint32_t offset = static_cast<uint32_t>(newDataIndex + 36 +
                                          lastSection->VirtualAddress +
                                          lastSection->SizeOfRawData); // thunk*
  memcpy(&newData[newDataIndex - 20], &offset, 4);
  offset = lastSection->VirtualAddress + lastSection->SizeOfRawData;
  memcpy(&newData[newDataIndex - 8], &offset, 4);
  offset = static_cast<uint32_t>(newDataIndex + 20 +
                                 lastSection->VirtualAddress +
                                 lastSection->SizeOfRawData); // thunk*
  memcpy(&newData[newDataIndex - 4], &offset, 4);
  memset(&newData[newDataIndex], '\0', 20);
  newDataIndex += 20;
  offset = static_cast<uint32_t>(payloadDll.length() + 1 +
                                 lastSection->VirtualAddress +
                                 lastSection->SizeOfRawData);
  memcpy(&newData[newDataIndex], &offset, 4);  // first thunk
  newDataIndex += 4;
  memset(&newData[newDataIndex], '\0', 12);
  newDataIndex += 12;
  memcpy(&newData[newDataIndex], &offset, 4); // second thunk
  newDataIndex += 4;
  memset(&newData[newDataIndex], '\0', 12);
  newDataIndex += 12;

  // patch Headers values
  cout << "\t- Patch Header values\n";
  flush(cout);

  uint32_t length = newDataPos + lastSection->VirtualAddress +
                    lastSection->SizeOfRawData;
  *reinterpret_cast<uint32_t*>(&data[0x170]) = length; // DataDir[1].rva
  length = image.FileHeader->OptionalHeader.DataDirectory[1].Size;
  *reinterpret_cast<uint32_t*>(&data[0x174]) = length + 0x14; // DataDir[1].size

  offset = 0x1E8 + (IMAGE_SIZEOF_SECTION_HEADER * (image.NumberOfSections - 1));
  length = lastSection->Misc.VirtualSize;
  *reinterpret_cast<uint32_t*>(&data[offset + 0x8]) = length + newDataIndex;
  length = lastSection->SizeOfRawData;
  *reinterpret_cast<uint32_t*>(&data[offset + 0x10]) = length + newDataIndex;
  length = *reinterpret_cast<uint32_t*>(&data[offset + 0x24]); // characteristics
  *reinterpret_cast<uint32_t*>(&data[offset + 0x24]) = length | 0xC0000000;

  length = lastSection->VirtualAddress + lastSection->SizeOfRawData + newDataIndex;
  if (length % 0x1000)
    length = ((length / 0x1000) + 1) * 0x1000;
  *reinterpret_cast<uint32_t*>(&data[0x140]) = length; // SizeOfImage

  cout << "\t- Flush output and clean up\n";
  flush(cout);

  string dirPath = RemoveFileExt(outPath, '\\');
  if (dirPath.empty())
    dirPath = RemoveFileExt(outPath, '/');
  if (!dirPath.empty())
    MkDir(&dirPath[0]);

  ofstream ofile;
  ofile.open(outPath, ofile.binary | ofile.out);
  ofile.write(&data[0], dataSize);
  ofile.write(&newData[0], newDataIndex);
  ofile.close();

  UnMapAndLoad(&image);
}
