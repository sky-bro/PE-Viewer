// PE and PE32+
#include <iostream>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "peviewer.h"
// #include<winnt.h>

using namespace std;
const int buf_size = 0x100;
char pe_name[100];
char tmp_buf[buf_size];

void printbytes(char *buf, ssize_t nbytes) {
    printf("--------------------\n");
    for (int i = 0; i < nbytes; ++i){
        if (i%16 == 0) {
            printf("\n");
        }
        printf("%02X ", buf[i]);
    }
    printf("\n--------------------\n");
}

int main(int argc, char const *argv[])
{
    // 1. Get PE File Path
    printf("Please input path to your PE file: ");
    scanf("%s", pe_name);
    if (strlen(pe_name) >= 100) { // file name too long
        cout<<"Accept length of PE name under 100 char's only!\n";
        return 1;
    }

    // 2. Open PE File
    int pe_file = open(pe_name, O_RDONLY);
    if (pe_file <= 0) {
        perror("Cannot open PE file!\n");
        return 1;
    }

    // read dos header
    PIMAGE_DOS_HEADER pdos_header = new IMAGE_DOS_HEADER;
    load_buf(pe_file, pdos_header, DOS_HEADER_SIZE, 0);
    // printbytes((char *)pdos_header, DOS_HEADER_SIZE);
    // return 0;
    
    // read image file header
    LONG file_header_offset = pdos_header->e_lfanew + 4; // PE magic took 4 bytes
    PIMAGE_FILE_HEADER pfile_header = new IMAGE_FILE_HEADER;
    load_buf(pe_file, pfile_header, FILE_HEADER_SIZE, file_header_offset);
    

    // read section headers
    // 1. get number of sections
    WORD number_of_sections = pfile_header->NumberOfSections;
    // 2. get section header offset
    WORD opt_header_size = pfile_header->SizeOfOptionalHeader;
    LONG section_header_offset = file_header_offset + FILE_HEADER_SIZE + opt_header_size;
    // 3. load buffer
    PIMAGE_SECTION_HEADER psection_header = new IMAGE_SECTION_HEADER[number_of_sections];
    load_buf(pe_file, psection_header, number_of_sections*SECTION_HEADER_SIZE, section_header_offset);

    // read optional header
    PIMAGE_OPTIONAL_HEADER32 popt_header = new IMAGE_OPTIONAL_HEADER32;
    load_buf(pe_file, popt_header, OPTIONAL_HEADER_SIZE, file_header_offset+FILE_HEADER_SIZE);

    // read import data directory
    IMAGE_DATA_DIRECTORY *pimport_directory = popt_header->DataDirectory+1;
    DWORD import_offset = pimport_directory->VirtualAddress; // now it's actually virtual offset
    import_offset = RVA2RAW(import_offset, psection_header, number_of_sections); // convert to RawOffset
    DWORD import_size = pimport_directory->Size;
    DWORD import_num = import_size / IMPORT_DESCRIPTOR_SIZE;

    PIMAGE_IMPORT_DESCRIPTOR pimport_descriptor = new IMAGE_IMPORT_DESCRIPTOR[import_num];
    load_buf(pe_file, pimport_descriptor, import_size, import_offset);
    
    for (int i = 0; i < import_num; ++i) {
        if (!pimport_descriptor[i].Name) break;
        printf("DLL\tOriginalFirstThunk\tTimeDateStamp\tForwarderChain\tName\tFirstThunk\n");
        LONG dll_name_offset = RVA2RAW(pimport_descriptor[i].Name, psection_header, number_of_sections);
        load_string(pe_file, tmp_buf, buf_size, dll_name_offset);

        printf("%s\t%08X\t%08X\t%08X\t%08X\t%08X\n\n", tmp_buf, pimport_descriptor[i].OriginalFirstThunk,
         pimport_descriptor[i].TimeDateStamp, 
         pimport_descriptor[i].ForwarderChain, 
         pimport_descriptor[i].Name, 
         pimport_descriptor[i].FirstThunk);
        
        printf("ThunkRVA\tThunkOffset\tThunkVal\tordinal\tAPIname\n");
        DWORD int_rva = pimport_descriptor[i].OriginalFirstThunk;
        DWORD int_offset = RVA2RAW(int_rva);
        for (DWORD i = 0; ; ++i) {
            DWORD import_by_name_offset = load_dword(pe_file, int_offset + i*4);
            // printf("%08X--------%08X\n", int_offset + i*4, import_by_name_offset);
            if (!import_by_name_offset) break;
            printf("%08X\t%08X\t%08X\t", int_rva+i*4, int_offset+i*4, import_by_name_offset);
            import_by_name_offset = RVA2RAW(import_by_name_offset);
            WORD hint = load_word(pe_file, import_by_name_offset);
            printf("%04X\t", hint);
            if (hint & 0x8000) { // load by ordinal
                printf("null\n");
            } else { // load by name
                load_string(pe_file, tmp_buf, buf_size, import_by_name_offset+2);
                printf("%s\n", tmp_buf);
            }
        }
        printf("------------------------------------------------------------------\n");
    }
    delete [] pimport_descriptor;
    delete popt_header;
    delete [] psection_header;
    delete pdos_header;
    delete pfile_header;

    return 0;
}
