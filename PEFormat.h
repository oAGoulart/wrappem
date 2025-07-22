#pragma once

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

inline constexpr uint32_t
Pad(const uint32_t size, const uint32_t padding)
{
  return size + (padding - (size % padding));
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
  // NOTE: file offset of NtHeader
  uint32_t e_lfanew;
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
  uint32_t VirtualAddress;
  uint32_t Size; // in bytes
};

// NOTE: import table must be terminated by an empty ImportDirectory
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
  // NOTE: last entry must be an empty DataDirectory
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
  // NOTE: last entry must be an empty DataDirectory
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
  enum class EmptySpace {
    SPACE_NONE,
    SPACE_EXPAND,
    SPACE_RELOCATE,
    SPACE_CREATE
  };

  const char magic_[2] = { 'M', 'Z' };
  const char sig_[4] = { 'P', 'E', '\0', '\0' };

  bool is32_;
  EmptySpace hasSpace_;
  // NOTE: references
  DosHeader* dos_;
  NtHeader* nt_;
  union Optional
  {
    OptionalHeader32* u32;
    OptionalHeader64* u64;
  } optional_;
  DataDirectory* importTable_;
  ImportDirectory* iaTable_;
  SectionParams* idataSection_;
  SectionParams* lastSection_;
  // NOTE: buffers
  uint8_t* fileBytes_;
  uintmax_t fileSize_;

  EmptySpace FindEmptySpace_(const std::size_t min);
  bool HasSpaceForNewSection_();

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
      file.close();

      dos_ = reinterpret_cast<DosHeader*>(fileBytes_);
      if (memcmp(dos_->e_magic, magic_, 2) != 0)
      {
        throw std::runtime_error("file has invalid DOS header.");
      }
      nt_ = reinterpret_cast<NtHeader*>(fileBytes_ + dos_->e_lfanew);
      if (memcmp(nt_->Signature, sig_, 4) != 0)
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

      importTable_ = (is32_) ?
        &optional_.u32->DataDirectory[1] : &optional_.u64->DataDirectory[1];
      if (importTable_->VirtualAddress == 0 || importTable_->Size == 0)
      {
        throw std::runtime_error("file has no import table directory.");
      }
      std::cout << __c(42, "[+]") << " Import table size (bytes): "
                << importTable_->Size << std::endl;
      
      const uint32_t ltSize = 4 * ((is32_) ? 4 : 8);
      uint32_t minSize = sizeof(ImportDirectory) + ltSize;
      minSize += Pad(dummyname.length() + 3, 2);
      minSize += Pad(payload.length() + 1, 2);
      EmptySpace method = FindEmptySpace_(minSize);

      std::cout << "    Method chosen: ";
      if (method == EmptySpace::SPACE_RELOCATE)
      {
        std::cout << "relocate import table..." << std::endl;
        ImportDirectory* dest = reinterpret_cast<ImportDirectory*>(
          fileBytes_ + idataSection_->PointerToRawData +
          idataSection_->VirtualSize);
        memcpy(dest + 1, iaTable_, importTable_->Size);
        uint8_t* tmp = reinterpret_cast<uint8_t*>(iaTable_);
        iaTable_ = dest;
        iaTable_->ForwarderChain = 0;
        iaTable_->TimeDateStamp = 0;
        memset(tmp, 0, 2); // FIXME: this assumes ordinal is 0
        uint32_t offset = 2;
        memcpy(tmp + offset, dummyname.c_str(), dummyname.length());
        offset += dummyname.length();
        uint32_t padding = Pad(dummyname.length() + 1, 2);
        memset(tmp + offset, 0, padding);
        offset += padding;
        memcpy(tmp + offset, payload.c_str(), payload.length());
        iaTable_->rvaModuleName = importTable_->VirtualAddress + offset;
        offset += payload.length();
        padding = Pad(payload.length() + 1, 2);
        memset(tmp + offset, 0, padding);
        offset += padding;
        uint32_t rva = importTable_->VirtualAddress;
        memcpy(tmp + offset, &rva, 4);
        iaTable_->rvaImportLookupTable = importTable_->VirtualAddress + offset;
        offset += 4;
        if (!is32_)
        {
          memset(tmp + offset, 0, 8);
          offset += 8;
        }
        memset(tmp + offset, 0, 4);
        offset += 4;
        // NOTE: thunk data, same as above
        memcpy(tmp + offset, &rva, 4);
        iaTable_->rvaImportAddressTable = importTable_->VirtualAddress + offset;
        offset += 4;
        if (!is32_)
        {
          memset(tmp + offset, 0, 8);
          offset += 8;
        }
        memset(tmp + offset, 0, 4 + sizeof(ImportDirectory));
        // offset += 4 + sizeof(ImportDirectory);
        // NOTE: patch addresses and sizes
        importTable_->VirtualAddress = idataSection_->VirtualSize +
                                       idataSection_->VirtualAddress;
        idataSection_->VirtualSize += minSize + importTable_->Size;
        importTable_->Size += sizeof(ImportDirectory);
      }
      else if (method == EmptySpace::SPACE_EXPAND)
      {
        std::cout << "expand import table..." << std::endl;
        // TODO: copy all resources, iterate import table,
        //       relocate each rva resource
        throw std::runtime_error("unavailable EXPAND method");
      }
      else if (HasSpaceForNewSection_())
      {
        std::cout << "move import data section..." << std::endl;
        // TODO: create new section entry, move import table and resources
        //       re-use code from EXPAND
        throw std::runtime_error("unavailable CREATE method");
      }
      else
      {
        throw std::runtime_error("no method is suitable for import injection");
      }
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
    ofile.close();
  }
};

}
