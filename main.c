#include <stdio.h>
#include <windows.h>


int check_PE_64(LPVOID buffer){
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)buffer;
    if (dos_header->e_magic != 0x5A4D){
        printf("Error! Wrong DOS header signature!\n");
        return -1;
    }        
    PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)(dos_header->e_lfanew + buffer);
    if (nt_header->Signature != 0x4550){
        printf("Error! Wrong NT header signature!\n");
        return -1;
    }
    if (nt_header->FileHeader.Machine == 0x8664)
        return 1;
    return 0;
}

/*
Load PE32+ file
@param LPVOID buffer - buffer, that contains raw PE data
*/
int load_x64(LPVOID buffer){
    printf("Loading x64...\n");
    NTSTATUS status = 0;
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)buffer;
    PIMAGE_NT_HEADERS64 nt_header = (PIMAGE_NT_HEADERS64)(dos_header->e_lfanew + buffer);
    LPVOID image_base = (LPVOID)nt_header->OptionalHeader.ImageBase;
    DWORD size_of_image = nt_header->OptionalHeader.SizeOfImage;
    LPVOID lpvResult = VirtualAlloc(image_base, size_of_image, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (lpvResult == NULL){
        printf("Failed to allocate memory at default address (at ImageBase)\nTrying to allocate memory at random address...");
        lpvResult = VirtualAlloc(NULL, size_of_image, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (lpvResult == NULL){
            printf("Failed to allocate memory!\nExiting.");
            return -1;
        }
    }
    image_base = lpvResult;
    printf("Base address: %p\n", lpvResult);

    // copying headers
    DWORD size_of_headers = nt_header->OptionalHeader.SizeOfHeaders;
    memset(image_base, 0, size_of_image);
    memcpy(image_base, buffer, size_of_headers);

    // place sections to there addresses
    WORD size_of_opt_header = nt_header->FileHeader.SizeOfOptionalHeader;
    PIMAGE_SECTION_HEADER section_header = (PIMAGE_SECTION_HEADER)(
                                            image_base + 
                                            size_of_opt_header + sizeof(IMAGE_FILE_HEADER) +  
                                            dos_header->e_lfanew + 4
                                            ); // add 4, because of PE signature
    while (*(long long*)section_header != 0){
        //printf("Section name: %s\n", section_header->Name);
        DWORD raw_size = section_header->SizeOfRawData;
        DWORD raw_offset = section_header->PointerToRawData;
        DWORD section_rva = section_header->VirtualAddress;
        //printf("Copying %d bytes from raw offset 0x%x to virtual address %x\n", raw_size, raw_offset, section_rva);
        memcpy((LPVOID)((LPBYTE)image_base + section_rva), (LPVOID)((LPBYTE)buffer + raw_offset), raw_size);
        section_header = (PIMAGE_SECTION_HEADER)((LPBYTE)section_header + sizeof(IMAGE_SECTION_HEADER));
    }

    status = VirtualFree(lpvResult, 0, MEM_RELEASE);
    if (status == 0){
        printf("Failed to free memory.\nLast error: 0x%08x", GetLastError());
    }
    return 0;
}


int load_x32(LPVOID buffer){
    printf("Loading x32...\n");
    return 0;
}



int main(int argc, char* argv[]) {
    printf("Step 1!\n Reading...  ");
    HANDLE hFile;
    hFile = CreateFile("D:\\main.exe",            
                       GENERIC_READ,
                       FILE_SHARE_READ, 
                       NULL,             
                       OPEN_EXISTING,        
                       FILE_ATTRIBUTE_NORMAL, 
                       NULL);              
    if (hFile == INVALID_HANDLE_VALUE){
        printf("Cant open file!\nLast error: 0x%08x\n", GetLastError());
        return 1;
    }

    DWORD high_dword_file_size = 0;
    DWORD low_dword_file_size = 0;
    low_dword_file_size = GetFileSize(hFile, &high_dword_file_size);
    if (low_dword_file_size == INVALID_FILE_SIZE){
        printf("Unable to get file size!\nLast error: 0x%08x\n", GetLastError());
        return 2;
    }
    printf("File size: %d\n", low_dword_file_size);
    
    //ignoring high_dword_file_size, I dont need to read big files for now
    LPVOID buffer = malloc(low_dword_file_size);
    LPDWORD lpNumberOfBytesRead = 0;
    if (FALSE == ReadFile(hFile, buffer, low_dword_file_size, lpNumberOfBytesRead, NULL)){
        printf("Unable to read from file.\nLast error: 0x%08x\n", GetLastError());
        free(buffer);
        return 3;
    }

    CloseHandle(hFile);

    switch (check_PE_64(buffer))
    {
    case 1:
        load_x64(buffer);
        break;
    case 0:
        load_x32(buffer);
        break;
    default:
        printf("Failed to load file!");
        break;
    }

    free(buffer);
    return 0;
}
