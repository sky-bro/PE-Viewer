// PE and PE32+
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "peviewer++.h"
// #include<winnt.h>

char pe_name[100];
char tmp_buf[0x100];

int main(int argc, char const *argv[])
{
    printf("Please input path to your PE file: ");
    scanf("%s", pe_name);
    if (strlen(pe_name) >= 100) {
        perror("Accept length of PE name under 100 char's only!\n");
        return 1;
    }
    int pe_file = open(pe_name, O_RDONLY);
    if (pe_file <= 0) {
        perror("Cannot open PE file!\n");
        return 1;
    }
    // read dos header
    read(pe_file, tmp_buf, DOS_HEADER_SIZE);
    PIMAGE_DOS_HEADER pdos_header = tmp_buf;

    // read image file header
    LONG file_header_offset = pdos_header->e_lfanew + 4; // PE magic took 4 bytes
    lseek(pe_file, file_header_offset, SEEK_SET);
    read(pe_file, tmp_buf, FILE_HEADER_SIZE);
    PIMAGE_FILE_HEADER pfile_header = tmp_buf;
    // get number of sections
    WORD section_number = pfile_header->NumberOfSections;
    // get section header offset
    WORD opt_header_size = pfile_header->SizeOfOptionalHeader;
    LONG section_header_offset = file_header_offset + FILE_HEADER_SIZE + opt_header_size;

    // read optional header
    read(pe_file, tmp_buf, opt_header_size);
    PIMAGE_OPTIONAL_HEADER32 popt_header = tmp_buf;

    // read import data directory
    IMAGE_DATA_DIRECTORY *pimport_directory = popt_header->DataDirectory+1;
    DWORD import_offset = pimport_directory->VirtualAddress; // now it's actually virtual offset
    DWORD import_size = pimport_directory->Size;

    // read section headers
    lseek(pe_file, section_header_offset, SEEK_SET);
    read(pe_file, tmp_buf, SECTION_HEADER_SIZE*section_number);
    IMAGE_SECTION_HEADER *psection_header = tmp_buf;
    
    // read import descriptors
    int i = 0;
    for (; i < section_number; ++i) {
        DWORD start = psection_header[i].VirtualAddress;
        if (start <= import_offset && start + psection_header[i].Misc.VirtualSize > import_offset) {
            // may better use file alignment to justify RawOffset
            import_offset = import_offset - start + psection_header[i].PointerToRawData;
            break;
        }
    }
    lseek(pe_file, import_offset, SEEK_SET);
    read(pe_file, tmp_buf, import_size);
    IMAGE_IMPORT_DESCRIPTOR *pimport_descriptor = tmp_buf;
    for (int i = 0; i < import_size/IMPORT_DESCRIPTOR_SIZE; ++i) {
        // pimport_descriptor[i].
    }
    

    // IMAGE_IMPORT_DESCRIPTOR *pimport_descriptor = ;

    // calculate file (raw) offset
    // 1. section VA

    return 0;
}
