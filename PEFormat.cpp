#include "PEFormat.h"

wrappem::PatchPE::EmptySpace
wrappem::PatchPE::FindEmptySpace_(const std::size_t min)
{
  idataSection_ = reinterpret_cast<SectionParams*>(
    fileBytes_ + dos_->e_lfanew + sizeof(NtHeader) +
    nt_->FileHeader.SizeOfOptionalHeader);
  lastSection_ = &idataSection_[nt_->FileHeader.NumberOfSections - 1];
  for (uint16_t i = 0; i < nt_->FileHeader.NumberOfSections; i++)
  {
    if (lastSection_->VirtualAddress <= importTable_->VirtualAddress &&
        lastSection_->VirtualAddress + lastSection_->VirtualSize >=
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
      if (idataSection_->SizeOfRawData - idataSection_->VirtualSize <= min)
      {
        return EmptySpace::SPACE_IDATA;
      }
      break;
    }
    idataSection_++;
  }
  if (idataSection_ == nullptr)
  {
    throw std::runtime_error("could not find .idata section.");
  }
  return EmptySpace::SPACE_SECTION;
}

bool wrappem::PatchPE::HasSpaceForNewSection_()
{
  const uint32_t sectionAlign = (is32_) ?
    optional_.u32->SectionAlignment : optional_.u64->SectionAlignment;
  const uint32_t offset = dos_->e_lfanew +
    sizeof(NtHeader) + nt_->FileHeader.SizeOfOptionalHeader +
    nt_->FileHeader.NumberOfSections * sizeof(SectionParams);
  return offset < sectionAlign;
}
