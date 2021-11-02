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
    cout << endl
         << "\t\t" << _C(36, PROJECT_NAME) << ' ' << _C(36, PROJECT_VERSION) << endl
         << "\tCopyright (C) 2021 Augusto Goulart" << endl << endl << flush;

    if (argc > 1) {
      if (!strcmp(argv[1], "--help")) {
        cout << "Usage: wrappem [--help] "
             << _C(95, "<target> <payloadDll> <dummyFunc> <outPath>") << endl << endl
             << "\t--help\t\tshow this help message" << endl
             << '\t' << _C(95, "target") << "\t\tpath to original DLL to be edited" << endl
             << '\t' << _C(95, "payloadDll") << "\tname of DLL to be loaded by target" << endl
             << '\t' << _C(95, "dummyFunc") << "\tdummy function name from payloadDLL" << endl
             << '\t' << _C(95, "outPath") << "\t\toutput path" << endl << flush;
        exit(EXIT_SUCCESS);
      }
      else if (argc < 4)
        throw invalid_argument("Incorrect use of params, use --help");
    }
    else
      throw invalid_argument("Not enough arguments, use --help");

    PatchImportTable(argv[1], argv[2], argv[3], argv[4]);
  }
  catch (const exception& e) {
    cerr << "\t\t" << _C(41, " Error: ") << '\t' << e.what() << endl << endl << flush;
    exit(EXIT_FAILURE);
  }
  exit(EXIT_SUCCESS);
}

void PatchImportTable(const char* target, const string payloadDll,
                      const string dummyFunc, char* outPath)
{
  LOADED_IMAGE image;
  if (!MapAndLoad(target, nullptr, &image, TRUE, FALSE))
    throw runtime_error("Could not map PE file");

  auto is64 = false;
  if ((image.FileHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) &&
      (image.FileHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC))
    is64 = true;
  else if ((image.FileHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) &&
           (image.FileHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC))
    throw runtime_error("Unknown computer architecture type");

  ifstream ifile;
  ifile.open(target, ifile.binary | ifile.in);

  const auto dataSize = static_cast<size_t>(image.SizeOfImage);
  auto data = make_unique_for_overwrite<char[]>(dataSize);

  cout << "\t- Read PE file" << endl << flush;
  ifile.read(&data[0], dataSize);
  ifile.close();

  auto newData = make_unique_for_overwrite<char[]>(dataSize);
  uint32_t newDataIndex = 0;

  cout << "\t- Append new string and thunk data to last section" << endl << flush;
  memcpy(&newData[newDataIndex], payloadDll.data(), payloadDll.length());
  newDataIndex += static_cast<uint32_t>(payloadDll.length());
  memset(&newData[newDataIndex], '\0', 3);
  newDataIndex += 3;
  memcpy(&newData[newDataIndex], dummyFunc.data(), dummyFunc.length());
  newDataIndex += static_cast<uint32_t>(dummyFunc.length());
  memset(&newData[newDataIndex], '\0', 19);
  newDataIndex += 19;

  const auto newDataPos = newDataIndex;
  const auto dataDir = &image.FileHeader->OptionalHeader.DataDirectory[1];
  bool foundSection = false;

  cout << "\t- Move import table to last section" << endl << flush;
  for (size_t i = 0; i < image.NumberOfSections; ++i) {
    // find which section the import table is located (needed to calculate offset from file start)
    if ((image.Sections[i].VirtualAddress < dataDir->VirtualAddress) &&
        (image.Sections[i].VirtualAddress +
         image.Sections[i].SizeOfRawData > dataDir->VirtualAddress)) {
      auto offset = FindOffsetFromFile(dataDir->VirtualAddress, &image.Sections[i]);
      memcpy(&newData[newDataPos], &data[offset], dataDir->Size);
      memset(&data[offset], '\0', dataDir->Size);
      newDataIndex += dataDir->Size;
      foundSection = true;
      break;
    }
  }
  if (!foundSection)
    throw runtime_error("Unable to find import table");

  cout << "\t- Append new entry to import table" << endl << flush;
  auto lastSection = &image.Sections[image.NumberOfSections - 1];

  // thunk* data
  auto offset = static_cast<uint32_t>(newDataIndex + 36 +
                                      lastSection->VirtualAddress +
                                      lastSection->SizeOfRawData);
  memcpy(&newData[newDataIndex - 20], &offset, 4);
  offset = lastSection->VirtualAddress + lastSection->SizeOfRawData;
  memcpy(&newData[newDataIndex - 8], &offset, 4);

  // thunk* data
  offset = static_cast<uint32_t>(newDataIndex + 20 +
                                 lastSection->VirtualAddress +
                                 lastSection->SizeOfRawData);
  memcpy(&newData[newDataIndex - 4], &offset, 4);

  // fill other data with zeros
  memset(&newData[newDataIndex], '\0', 20);
  newDataIndex += 20;

  // first thunk reference
  offset = static_cast<uint32_t>(payloadDll.length() + 1 +
                                 lastSection->VirtualAddress +
                                 lastSection->SizeOfRawData);
  memcpy(&newData[newDataIndex], &offset, 4);
  newDataIndex += 4;
  memset(&newData[newDataIndex], '\0', 12);
  newDataIndex += 12;

  // second thunk reference
  memcpy(&newData[newDataIndex], &offset, 4);
  newDataIndex += 4;
  memset(&newData[newDataIndex], '\0', 12);
  newDataIndex += 12;

  cout << "\t- Patch NT_HEADERS values and references" << endl << flush;
  const auto headerOffset = *reinterpret_cast<uint32_t*>(&data[0x3C]);
  uint32_t sectionOffset = headerOffset;
  sectionOffset += (is64) ? sizeof(IMAGE_NT_HEADERS64) : sizeof(IMAGE_NT_HEADERS32);

  auto importDataOffset = FindDifference(&image.FileHeader->OptionalHeader, dataDir);
  uint32_t length = newDataPos + lastSection->VirtualAddress + lastSection->SizeOfRawData;
  *reinterpret_cast<uint32_t*>(
    &data[headerOffset + 4 + sizeof(IMAGE_FILE_HEADER) + importDataOffset]
  ) = length;

  length = dataDir->Size;
  *reinterpret_cast<uint32_t*>(
    &data[headerOffset + 4 + sizeof(IMAGE_FILE_HEADER) + importDataOffset + 4]
  ) = length + 0x14;

  offset = sectionOffset + (IMAGE_SIZEOF_SECTION_HEADER * (image.NumberOfSections - 1));
  length = lastSection->Misc.VirtualSize;
  *reinterpret_cast<uint32_t*>(&data[offset + 0x8]) = length + newDataIndex;
  length = lastSection->SizeOfRawData;
  *reinterpret_cast<uint32_t*>(&data[offset + 0x10]) = length + newDataIndex;
  length = *reinterpret_cast<uint32_t*>(&data[offset + 0x24]);
  *reinterpret_cast<uint32_t*>(&data[offset + 0x24]) = length | 0xC0000000;

  length = lastSection->VirtualAddress + lastSection->SizeOfRawData + newDataIndex;
  if (length % 0x1000)
    length = ((length / 0x1000) + 1) * 0x1000;

  auto imageSizeOffset = FindDifference(&image.FileHeader->OptionalHeader,
                                        &image.FileHeader->OptionalHeader.SizeOfImage);
  *reinterpret_cast<uint32_t*>(
    &data[headerOffset + 4 + sizeof(IMAGE_FILE_HEADER) + imageSizeOffset]
  ) = length;

  cout << "\t- Write output to file and clean up" << endl << flush;
  path outDir = outPath;
  create_directories(outDir.remove_filename());

  ofstream ofile;
  ofile.open(outPath, ofile.binary | ofile.out);
  ofile.write(&data[0], dataSize);
  ofile.write(&newData[0], newDataIndex);
  ofile.close();

  UnMapAndLoad(&image);
}
