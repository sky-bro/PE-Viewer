#ifndef PEVIEWER_H

#include <iostream>

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned long DWORD;
typedef unsigned long long ULONGLONG;
typedef long LONG;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES		16
#define IMAGE_SIZEOF_SHORT_NAME 			 8

// DOS header: 0x40 bytes (64 bytes)
#define DOS_HEADER_SIZE 0x40
typedef struct _IMAGE_DOS_HEADER
{ WORD			e_magic; // MZ
  WORD			e_cblp;
  WORD			e_cp;
  WORD			e_crlc;
  WORD			e_cparhdr;
  WORD			e_minalloc;
  WORD			e_maxalloc;
  WORD			e_ss;
  WORD			e_sp;
  WORD			e_csum;
  WORD			e_ip;
  WORD			e_cs;
  WORD			e_lfarlc;
  WORD			e_ovno;
  WORD			e_res[4];
  WORD			e_oemid;
  WORD			e_oeminfo;
  WORD			e_res2[10];
  LONG			e_lfanew; // offset of NT header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

// image file header 0x14 bytes (20 bytes)
#define FILE_HEADER_SIZE 0x14
typedef struct _IMAGE_FILE_HEADER
{ WORD			Machine;
  WORD			NumberOfSections;
  DWORD 		TimeDateStamp;
  DWORD 		PointerToSymbolTable;
  DWORD 		NumberOfSymbols;
  WORD			SizeOfOptionalHeader;
  WORD			Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

// data directory
typedef struct _IMAGE_DATA_DIRECTORY
{ DWORD 		VirtualAddress;
  DWORD 		Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define OPTIONAL_HEADER_SIZE 0xE0
typedef struct _IMAGE_OPTIONAL_HEADER
{ WORD			Magic;
  BYTE			MajorLinkerVersion;
  BYTE			MinorLinkerVersion;
  DWORD 		SizeOfCode;
  DWORD 		SizeOfInitializedData;
  DWORD 		SizeOfUninitializedData;
  DWORD 		AddressOfEntryPoint;
  DWORD 		BaseOfCode;
  DWORD 		BaseOfData;
  DWORD 		ImageBase;
  DWORD 		SectionAlignment;
  DWORD 		FileAlignment;
  WORD			MajorOperatingSystemVersion;
  WORD			MinorOperatingSystemVersion;
  WORD			MajorImageVersion;
  WORD			MinorImageVersion;
  WORD			MajorSubsystemVersion;
  WORD			MinorSubsystemVersion;
  DWORD 		Win32VersionValue;
  DWORD 		SizeOfImage;
  DWORD 		SizeOfHeaders;
  DWORD 		CheckSum;
  WORD			Subsystem;
  WORD			DllCharacteristics;
  DWORD 		SizeOfStackReserve;
  DWORD 		SizeOfStackCommit;
  DWORD 		SizeOfHeapReserve;
  DWORD 		SizeOfHeapCommit;
  DWORD 		LoaderFlags;
  DWORD 		NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY	DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_OPTIONAL_HEADER64
{ WORD			Magic;
  BYTE			MajorLinkerVersion;
  BYTE			MinorLinkerVersion;
  DWORD 		SizeOfCode;
  DWORD 		SizeOfInitializedData;
  DWORD 		SizeOfUninitializedData;
  DWORD 		AddressOfEntryPoint;
  DWORD 		BaseOfCode;
  ULONGLONG		ImageBase;
  DWORD 		SectionAlignment;
  DWORD 		FileAlignment;
  WORD			MajorOperatingSystemVersion;
  WORD			MinorOperatingSystemVersion;
  WORD			MajorImageVersion;
  WORD			MinorImageVersion;
  WORD			MajorSubsystemVersion;
  WORD			MinorSubsystemVersion;
  DWORD 		Win32VersionValue;
  DWORD 		SizeOfImage;
  DWORD 		SizeOfHeaders;
  DWORD 		CheckSum;
  WORD			Subsystem;
  WORD			DllCharacteristics;
  ULONGLONG		SizeOfStackReserve;
  ULONGLONG		SizeOfStackCommit;
  ULONGLONG		SizeOfHeapReserve;
  ULONGLONG		SizeOfHeapCommit;
  DWORD 		LoaderFlags;
  DWORD 		NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY	DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

#define IMPORT_DESCRIPTOR_SIZE 0x14
typedef struct _IMAGE_IMPORT_DESCRIPTOR
{
    union
    {
        DWORD Characteristics;
        DWORD OriginalFirstThunk; // INT
    };
    DWORD TimeDateStamp;
    DWORD ForwarderChain;
    DWORD Name;
    DWORD FirstThunk; // IAT
} IMAGE_IMPORT_DESCRIPTOR, *PIMAGE_IMPORT_DESCRIPTOR;

// NT header
typedef struct _IMAGE_NT_HEADERS
{ DWORD 			Signature;
  IMAGE_FILE_HEADER		FileHeader;
  IMAGE_OPTIONAL_HEADER32	OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

// section header
#define SECTION_HEADER_SIZE 0x28
typedef struct _IMAGE_SECTION_HEADER
{ BYTE		Name[IMAGE_SIZEOF_SHORT_NAME];
  union
  { DWORD	  PhysicalAddress;
    DWORD	  VirtualSize;
  }		Misc;
  DWORD 	VirtualAddress;
  DWORD 	SizeOfRawData;
  DWORD 	PointerToRawData;
  DWORD 	PointerToRelocations;
  DWORD 	PointerToLinenumbers;
  WORD		NumberOfRelocations;
  WORD		NumberOfLinenumbers;
  DWORD 	Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

// read nbytes bytes into _buf
void load_buf(int fd, void *buf, size_t nbytes, long pointer=-1) {
    if (pointer >= 0) {
        lseek(fd, pointer, SEEK_SET);
    }
    read(fd, buf, nbytes);
}

// conver Relative Virtual Address to RawOffset
DWORD RVA2RAW(DWORD rva, PIMAGE_SECTION_HEADER psection_header=nullptr, WORD number_of_sections=0) {
    static PIMAGE_SECTION_HEADER _psection_header = nullptr;
    static WORD _number_of_sections = 0;
    if (psection_header) {
        _psection_header = psection_header;
        _number_of_sections = number_of_sections;
    }

    for (int i = 0; i < _number_of_sections; ++i) {
        if (_psection_header[i].VirtualAddress <= rva && 
        _psection_header[i].VirtualAddress + _psection_header[i].Misc.VirtualSize > rva) {
            rva  = rva - _psection_header[i].VirtualAddress + _psection_header[i].PointerToRawData;
            return rva;
        }
    }
    // 0xFFFFFFFF
    return -1;
}

// temporary solution
void load_string(int fd, char *buf, int nbytes, long offset) {
    lseek(fd, offset, SEEK_SET);
    read(fd, buf, nbytes);
    buf[nbytes-1] = 0;
}

WORD load_word(int fd, long offset) {
    lseek(fd, offset, SEEK_SET);
    // char buf[3] = {0};
    // read(fd, buf, 2);
    // WORD result = atoi(buf);
    WORD result;
    read(fd, &result, 2);
    return result;
}

DWORD load_dword(int fd, long offset) {
    
    lseek(fd, offset, SEEK_SET);
    // char buf[5] = {0};
    // read(fd, buf, 4);
    // DWORD result = atol(buf);
    DWORD result;
    read(fd, &result, 4);
    return result;
}


#endif