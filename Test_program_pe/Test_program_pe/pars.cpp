#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <fstream>
#include <math.h>
#include <iostream>
#include <stdlib.h>
#include <io.h>
#include <fcntl.h>
typedef struct {
    WORD _id_reserved;
    WORD _id_type;
    WORD _id_count;
    BYTE _width;
    BYTE _height;
    BYTE _color_count;
    BYTE _reserved;
    WORD _planes;
    WORD _bit_count;
    DWORD _bytes_in_resource;
    DWORD _image_offset;
}ICON_ENTRY;

void seticon(const char* exefile, const char* icofile) {


    HANDLE resourse_handle = BeginUpdateResourceA(exefile, FALSE);
    char* buffer;
    size_t buffer_size;

    std::ifstream icon(icofile, std::ios::in | std::ios::binary);
    if (icon.good()) {
        printf("FILE ICO OPEN!");
        icon.seekg(0, icon.end);
        buffer_size = icon.tellg();
        buffer = new char[buffer_size];
        icon.seekg(0, icon.beg);
        icon.read(buffer, buffer_size);
        UpdateResource(resourse_handle, RT_ICON, MAKEINTRESOURCE(1), MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), buffer + 22, buffer_size - 22);;

        ICON_ENTRY icon_entry;
        icon_entry._id_reserved = 0;
        icon_entry._id_type = 1;
        icon_entry._id_count = 1;
        icon_entry._width = 128;
        icon_entry._height = 128;
        icon_entry._color_count = 0;
        icon_entry._reserved = 0;
        icon_entry._planes = 2;
        icon_entry._bit_count = 32;
        icon_entry._bytes_in_resource = buffer_size - 22;
        icon_entry._image_offset = 1;

        UpdateResource(resourse_handle, RT_GROUP_ICON, L"MAINICON", MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), &icon_entry, sizeof(ICON_ENTRY));

        EndUpdateResourceA(resourse_handle, FALSE);
        delete[] buffer;
    }
    else printf("Not open icon file");
}
int gtfo(const char* text = "")
{
    printf("Error! (%s)\n", text);
    return -1;
}
void show_manual(void) {
    printf("\t\tHelp page\nUse program ./name_program --exe full path exe_file --ico full path .ico file\n\t --help show this manual\n");
}
float calentropy(char* path) {
    FILE* file;
    fopen_s(&file,path,"r");
    int statistics[256] = { 0 };

    int ch = 0;
    while ((ch=fgetc(file))!=EOF) {
        statistics[ch]++;

    }
    fclose(file);

    int total = 0;
    for (int i = 0; i < 256; ++i) total += statistics[i];

    float enthropy = 0;
    for (int i = 0; i < 256; ++i) {
        if (statistics[i] == 0)continue;
        enthropy -= statistics[i] * log(((float)statistics[i]) / total);
    }
    enthropy /= log(2);
    return enthropy;
}
int main(int argc, char* argv[])
{
    int countw = 0;
    int numpathexe=1;
    int numpathico=1;

    //seticon("First_progect_vs.exe", "C:\\Users\\User\\source\\repos\\Test_program_pe\\x64\\Debug\\file4.ico");

    if (argc < 5) { show_manual(); return 0; }
    for (int i = 0; i != argc; i += 1) {
        if (strcmp("--help", argv[i]) == 0) {
            show_manual();
        }
        if (strcmp("--exe", argv[i]) == 0 && i + 1 <= argc) {
            numpathexe= i + 1;
            printf("Name .exe file: %s\n", argv[i + 1]);
        }
        if (strcmp("--ico", argv[i]) == 0 && i + 1 <= argc) {
            numpathico= i + 1;
            printf("Name .ico file: %s\n", argv[i + 1]);}}
    printf("Entropy .ico :%lf\n", calentropy(argv[numpathico]));
    printf("Entropy .exe :%lf\n", calentropy(argv[numpathexe]));
    seticon(argv[numpathexe], argv[numpathico]);
    auto hFile = CreateFileA(argv[numpathexe], GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
        return gtfo("CreateFile ");


    auto hMappedFile = CreateFileMappingA(hFile, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr);
    if (!hMappedFile)
        return gtfo("CreateFileMappingA");

    auto fileMap = MapViewOfFile(hMappedFile, FILE_MAP_READ, 0, 0, 0);
    if (!fileMap)
        return gtfo("MapViewOfFile");

    auto pidh = PIMAGE_DOS_HEADER(fileMap);
    if (pidh->e_magic != IMAGE_DOS_SIGNATURE)
        return gtfo("IMAGE_DOS_SIGNATURE");

    auto pnth = PIMAGE_NT_HEADERS(ULONG_PTR(fileMap) + pidh->e_lfanew);
    if (pnth->Signature != IMAGE_NT_SIGNATURE)
        return gtfo("IMAGE_NT_SIGNATURE");

    //if (pnth->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
    //    return gtfo("IMAGE_FILE_MACHINE_I386");

    if (pnth->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
        return gtfo("IMAGE_NT_OPTIONAL_HDR_MAGIC");

    auto importDir = pnth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    puts("Import Directory");
    printf(" RVA: %08X\n", importDir.VirtualAddress);
    printf("Size: %08X\n\n", importDir.Size);

    if (!importDir.VirtualAddress || !importDir.Size)
        return gtfo("No Import directory!");

    auto importDescriptor = PIMAGE_IMPORT_DESCRIPTOR(ULONG_PTR(fileMap) + importDir.VirtualAddress);
    if (!IsBadReadPtr((char*)fileMap + importDir.VirtualAddress, 0x1000))
    {
        for (; importDescriptor->FirstThunk; importDescriptor++)
        {
            if (!IsBadReadPtr((char*)fileMap + importDescriptor->Name, 0x1000))
                printf("              Name: %08X \"%s\"\n", importDescriptor->Name, (char*)fileMap + importDescriptor->Name);
            else
                printf("              Name: %08X INVALID\n", importDescriptor->Name);
            auto thunkData = PIMAGE_THUNK_DATA(ULONG_PTR(fileMap) + importDescriptor->FirstThunk);
            for (; thunkData->u1.AddressOfData; thunkData++)
            {
                auto rva = ULONG_PTR(thunkData) - ULONG_PTR(fileMap);

                auto data = thunkData->u1.AddressOfData;
                if (data & IMAGE_ORDINAL_FLAG)
                    printf("              Ordinal: %08X\n", data & ~IMAGE_ORDINAL_FLAG);
                else
                {

                    auto importByName = PIMAGE_IMPORT_BY_NAME(ULONG_PTR(fileMap) + data);
                    for (char* p = importByName->Name; *p != '\0'; p += 1) {
                        if (*p == 'W' && *(p + 1) == '\0') countw += 1;
                    }
                    
                    if (!IsBadReadPtr(importByName, 0x1000)) {
                        printf("             Function: %08X \"%s\"\n", data, (char*)importByName->Name);
                    }
                    else
                        printf("             Function: %08X INVALID\n", data);
                      
                    
                }
            }

            puts("");
        }
    }
    else
        puts("INVALID IMPORT DESCRIPTOR");


    printf("Entropy .ico :%lf\n", calentropy(argv[numpathico]));
    printf("Entropy .exe :%lf\n", calentropy(argv[numpathexe]));
    printf("Count file ending W :%i\n", countw);

    printf("\tReplase image ending\n");

    return 0;
}