#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include "shared.h"

#pragma warning(disable: 4267)

namespace wrappem {

inline constexpr const char*
MachineType(const uint16_t machine)
{
  switch (machine)
  {
  case 0x014c:
    return "pe32";
    break;
  case 0x8664:
    return "pe64";
    break;
  default:
    return "unknown";
    break;
  }
}

inline constexpr uint32_t
Align(const uint32_t value, const uint32_t alignment)
{
  uint32_t result = alignment;
  while (result < value)
  {
    result += alignment;
  }
  return result;
}

struct DosHeader
{
  uint8_t  e_magic[2];
  uint16_t e_cblp;
  uint16_t e_cp;
  uint16_t e_crlc;
  uint16_t e_cparhdr;
  uint16_t e_minalloc;
  uint16_t e_maxalloc;
  uint16_t e_ss;
  uint16_t e_sp;
  uint16_t e_csum;
  uint16_t e_ip;
  uint16_t e_cs;
  uint16_t e_lfarlc;
  uint16_t e_ovno;
  uint16_t e_res1[4];
  uint16_t e_oemid;
  uint16_t e_oeminfo;
  uint16_t e_res2[10];
  uint32_t e_lfanew; // -> NtHeader
};

struct FileHeader
{
  uint16_t Machine;
  uint16_t NumberOfSections;
  uint32_t TimeDateStamp;
  uint32_t PointerToSymbolTable;
  uint32_t NumberOfSymbols;
  uint16_t SizeOfOptionalHeader;
  uint16_t Characteristics;
};

struct NtHeader
{
  uint8_t Signature[4];
  FileHeader FileHeader;
};

struct DataDirectory
{
  uint32_t VirtualAddress; // last entry must be empty
  uint32_t Size; // in bytes
};

struct ImportDirectory
{
  uint32_t rvaImportLookupTable;
  uint32_t TimeDateStamp;
  uint32_t ForwarderChain;
  uint32_t rvaModuleName;
  uint32_t rvaImportAddressTable;
};

constexpr uint32_t
IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;

struct OptionalHeader32
{
  uint16_t Magic;
  uint8_t MajorLinkerVersion;
  uint8_t MinorLinkerVersion;
  uint32_t SizeOfCode;
  uint32_t SizeOfInitializedData;
  uint32_t SizeOfUninitializedData;
  uint32_t AddressOfEntryPoint;
  uint32_t BaseOfCode;
  uint32_t BaseOfData;
  uint32_t ImageBase;
  uint32_t SectionAlignment;
  uint32_t FileAlignment;
  uint16_t MajorOperatingSystemVersion;
  uint16_t MinorOperatingSystemVersion;
  uint16_t MajorImageVersion;
  uint16_t MinorImageVersion;
  uint16_t MajorSubsystemVersion;
  uint16_t MinorSubsystemVersion;
  uint32_t Win32VersionValue;
  uint32_t SizeOfImage;
  uint32_t SizeOfHeaders;
  uint32_t CheckSum;
  uint16_t Subsystem;
  uint16_t DllCharacteristics;
  uint32_t SizeOfStackReserve;
  uint32_t SizeOfStackCommit;
  uint32_t SizeOfHeapReserve;
  uint32_t SizeOfHeapCommit;
  uint32_t LoaderFlags;
  uint32_t NumberOfRvaAndSizes;
  DataDirectory DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

struct OptionalHeader64
{
  uint16_t Magic;
  uint8_t MajorLinkerVersion;
  uint8_t MinorLinkerVersion;
  uint32_t SizeOfCode;
  uint32_t SizeOfInitializedData;
  uint32_t SizeOfUninitializedData;
  uint32_t AddressOfEntryPoint;
  uint32_t BaseOfCode;
  uint64_t ImageBase;
  uint32_t SectionAlignment;
  uint32_t FileAlignment;
  uint16_t MajorOperatingSystemVersion;
  uint16_t MinorOperatingSystemVersion;
  uint16_t MajorImageVersion;
  uint16_t MinorImageVersion;
  uint16_t MajorSubsystemVersion;
  uint16_t MinorSubsystemVersion;
  uint32_t Win32VersionValue;
  uint32_t SizeOfImage;
  uint32_t SizeOfHeaders;
  uint32_t CheckSum;
  uint16_t Subsystem;
  uint16_t DllCharacteristics;
  uint64_t SizeOfStackReserve;
  uint64_t SizeOfStackCommit;
  uint64_t SizeOfHeapReserve;
  uint64_t SizeOfHeapCommit;
  uint32_t LoaderFlags;
  uint32_t NumberOfRvaAndSizes;
  DataDirectory DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

struct SectionParams
{
  char Name[8];
  uint32_t VirtualSize;
  uint32_t VirtualAddress;
  uint32_t SizeOfRawData;
  uint32_t PointerToRawData;
  uint32_t PointerToRelocations;
  uint32_t PointerToLinenumbers;
  uint16_t NumberOfRelocations;
  uint16_t NumberOfLinenumbers;
  uint32_t Characteristics;
};

class PatchPE
{
private:
  DosHeader* dos_;
  NtHeader* nt_;
  union Optional
  {
    OptionalHeader32* u32;
    OptionalHeader64* u64;
  } optional_;
  bool is32_;
  uint8_t* fileBytes_;
  uintmax_t fileSize_;
  uint8_t* sectionBytes_;
  uintmax_t sectionSize_;

public:
  PatchPE(const std::filesystem::path& filename,
          const std::string& payload, const std::string& dummyname)
  {
    try
    {
      std::ifstream file;
      file.open(filename, std::ios::binary);

      std::cout << "    Parsing file..." << std::endl;
      fileSize_ = std::filesystem::file_size(filename);
      fileBytes_ = new uint8_t[fileSize_];
      file.read(reinterpret_cast<char*>(fileBytes_), fileSize_);

      dos_ = reinterpret_cast<DosHeader*>(fileBytes_);
      if (dos_->e_magic[0] != 'M' || dos_->e_magic[1] != 'Z')
      {
        throw std::runtime_error("file has invalid DOS header.");
      }

      nt_ = reinterpret_cast<NtHeader*>(fileBytes_ + dos_->e_lfanew);
      if (nt_->Signature[0] != 'P' || nt_->Signature[1] != 'E' ||
          nt_->Signature[2] != '\0' || nt_->Signature[3] != '\0')
      {
        throw std::runtime_error("file has invalid NT header.");
      }

      std::cout << __c(42, "[+]") << " Machine: "
                << MachineType(nt_->FileHeader.Machine) << std::endl;
      std::cout << __c(42, "[+]") << " Number of section: "
                << nt_->FileHeader.NumberOfSections << std::endl;
      std::cout << __c(42, "[+]") << " Size of optional header: "
                << nt_->FileHeader.SizeOfOptionalHeader << std::endl;
      
      if (nt_->FileHeader.SizeOfOptionalHeader == sizeof(OptionalHeader32))
      {
        is32_ = true;
        optional_.u32 = reinterpret_cast<OptionalHeader32*>(
          fileBytes_ + dos_->e_lfanew + sizeof(NtHeader));
      }
      else
      {
        is32_ = false;
        optional_.u64 = reinterpret_cast<OptionalHeader64*>(
          fileBytes_ + dos_->e_lfanew + sizeof(NtHeader));
      }

      DataDirectory* importTable = (is32_) ?
        &optional_.u32->DataDirectory[1] : &optional_.u64->DataDirectory[1];
      if (importTable->VirtualAddress == 0 || importTable->Size == 0)
      {
        throw std::runtime_error("file has no import table directory.");
      }
      std::cout << __c(42, "[+]") << " Import table size (bytes): "
                << importTable->Size << std::endl;
      
      // IMPORTANT: find which section the import table is in
      uint32_t itable = 0;
      SectionParams* idata = nullptr;
      SectionParams* sections = reinterpret_cast<SectionParams*>(
        fileBytes_ + dos_->e_lfanew + sizeof(NtHeader) +
        nt_->FileHeader.SizeOfOptionalHeader);
      for (uint16_t i = 0; i < nt_->FileHeader.NumberOfSections - 1; i++)
      {
        if (sections->VirtualAddress <= importTable->VirtualAddress &&
            sections->VirtualAddress + sections->VirtualSize >=
            importTable->VirtualAddress + importTable->Size)
        {
          idata = sections;
          itable = importTable->VirtualAddress - idata->VirtualAddress +
                   idata->PointerToRawData;
          std::cout << __c(42, "[+]") << " Import table at section: "
                    << idata->Name << std::endl;
          std::cout << __c(42, "[+]") << " Import table address: "
                    << itable << std::endl;
        }
        sections++;
      }
      if (idata == nullptr)
      {
        throw std::runtime_error("could not find .idata section.");
      }

      std::cout << "    Updating section..." << std::endl;
      /*uint32_t alignment = (is32_) ?
        optional_.u32->FileAlignment : optional_.u64->FileAlignment;
      std::cout << __c(42, "[+]") << " File alignment: "
                << alignment << std::endl;*/

      std::cout << "    Placing strings and lookup table..."
                << std::endl;
      uint32_t index = idata->VirtualSize + idata->PointerToRawData;
      memset(fileBytes_ + index, 1, 2);
      index += 2;
      memcpy(fileBytes_ + index, dummyname.data(), dummyname.length());
      index += dummyname.length();
      memset(fileBytes_ + index, 0, 1);
      index += 1;
      memcpy(fileBytes_ + index, payload.data(), payload.length());
      index += payload.length();
      memset(fileBytes_ + index, 0, 2);
      index += 2;
      uint32_t offset = idata->VirtualAddress + idata->VirtualSize;
      memcpy(fileBytes_ + index, &offset, 4);
      index += 4;
      memset(fileBytes_ + index, 0, 4);

      std::cout << "    Placing new import entry..." << std::endl;
      offset = idata->VirtualAddress + idata->VirtualSize +
               payload.length() + dummyname.length() + 5;
      index = itable + importTable->Size - sizeof(ImportDirectory) * 2;
      memcpy(fileBytes_ + index, &offset, 4);
      index += 4;
      memset(fileBytes_ + index, 0, 8);
      index += 8;
      offset = idata->VirtualAddress + idata->VirtualSize +
               dummyname.length() + 3;
      memcpy(fileBytes_ + index, &offset, 4);
      index += 4;
      offset = idata->VirtualAddress + idata->VirtualSize;
      memcpy(fileBytes_ + index, &offset, 4);
      index += 4;
      //memset(fileBytes_ + index, 0, sizeof(ImportDirectory));
      
      std::cout << "    Patching size..." << std::endl;
      //importTable->Size += sizeof(ImportDirectory);
      /*uint32_t* endOfFile = (is32_) ?
        &optional_.u32->SizeOfImage : &optional_.u64->SizeOfImage;
      idata->PointerToRawData = *endOfFile;
      *endOfFile = static_cast<uint32_t>(fileSize_ + sectionSize_);*/
      idata->VirtualSize += dummyname.length() + payload.length() + 13;
    }
    catch (const std::exception& e)
    {
      std::string err = "PEFormat ctor: ";
      err.append(e.what());
      throw std::runtime_error(err);
    }
  }

  ~PatchPE()
  {
    if (fileBytes_ != nullptr)
    {
      delete fileBytes_;
    }
    if (sectionBytes_ != nullptr)
    {
      free(sectionBytes_);
    }
  }

  void
  Save(std::filesystem::path filename)
  {
    std::cout << "    Saving to output file..." << std::endl;
    std::filesystem::path dir = filename;
    if (!std::filesystem::exists(dir.remove_filename()))
    {
      std::filesystem::create_directories(dir);
    }

    std::ofstream ofile(filename, std::ios::binary | std::ios::out);
    ofile.write(reinterpret_cast<char*>(fileBytes_), fileSize_);
    //ofile.write(reinterpret_cast<char*>(sectionBytes_), sectionSize_);
    ofile.close();
  }
};

}
