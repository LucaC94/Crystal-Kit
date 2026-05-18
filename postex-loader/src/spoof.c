#include <windows.h>
#include "spoof.h"
#include "tcg.h"

DECLSPEC_IMPORT HMODULE            WINAPI KERNEL32$GetModuleHandleA       ( LPCSTR );
DECLSPEC_IMPORT RUNTIME_FUNCTION * WINAPI KERNEL32$RtlLookupFunctionEntry ( DWORD64, PDWORD64, PUNWIND_HISTORY_TABLE );
DECLSPEC_IMPORT ULONG              NTAPI  NTDLL$RtlRandomEx               ( PULONG );

#define TEXT_HASH   0xEBC2F9B4
#define RBP_OP_INFO 0x5

typedef struct {
    LPCWSTR   DllPath;
    ULONG     Offset;
    ULONGLONG TotalStackSize;
    BOOL      RequiresLoadLibrary;
    BOOL      SetsFramePointer;
    PVOID     ReturnAddress;
    BOOL      PushRbp;
    ULONG     CountOfCodes;
    BOOL      PushRbpIndex;
} STACK_FRAME;

typedef enum {
    UWOP_PUSH_NONVOL = 0,
    UWOP_ALLOC_LARGE,
    UWOP_ALLOC_SMALL,
    UWOP_SET_FPREG,
    UWOP_SAVE_NONVOL,
    UWOP_SAVE_NONVOL_FAR,
    UWOP_SAVE_XMM128 = 8,
    UWOP_SAVE_XMM128_FAR,
    UWOP_PUSH_MACHFRAME
} UNWIND_CODE_OPS;

typedef unsigned char UBYTE;

typedef union {
    struct {
        UBYTE CodeOffset;
        UBYTE UnwindOp : 4;
        UBYTE OpInfo   : 4;
    };
    USHORT FrameOffset;
} UNWIND_CODE;

typedef struct {
    UBYTE Version : 3;
    UBYTE Flags   : 5;
    UBYTE SizeOfProlog;
    UBYTE CountOfCodes;
    UBYTE FrameRegister : 4;
    UBYTE FrameOffset   : 4;
    UNWIND_CODE UnwindCode [ 1 ];
} UNWIND_INFO;

typedef struct {
    PVOID ModuleAddress;
    PVOID FunctionAddress;
    DWORD Offset;
} FRAME_INFO;

typedef struct {
    FRAME_INFO Frame1;
    FRAME_INFO Frame2;
    PVOID      Gadget;
} SYNTHETIC_STACK_FRAME;

typedef struct {
    FUNCTION_CALL * FunctionCall;
    PVOID           StackFrame;
    PVOID           SpoofCall;
} DRAUGR_FUNCTION_CALL;

typedef enum {
    GADGET_REG_RBX = 0,
    GADGET_REG_RDI,
    GADGET_REG_RSI,
    GADGET_REG_R12,
    GADGET_REG_R13,
    GADGET_REG_R14,
    GADGET_REG_R15,
} GADGET_REGISTER;

typedef struct {
    PVOID           Address;
    GADGET_REGISTER Register;
    INT32           Offset;
} GADGET_INFO;

typedef struct {
    PVOID Fixup;
    PVOID OriginalReturnAddress;
    PVOID Rbx;
    PVOID Rdi;
    PVOID BaseThreadInitThunkStackSize;
    PVOID BaseThreadInitThunkReturnAddress;
    PVOID TrampolineStackSize;
    PVOID RtlUserThreadStartStackSize;
    PVOID RtlUserThreadStartReturnAddress;
    PVOID Ssn;
    PVOID Trampoline;
    PVOID Rsi;
    PVOID R12;
    PVOID R13;
    PVOID R14;
    PVOID R15;
    DWORD GadgetReg;
    INT32 GadgetOffset;
} DRAUGR_PARAMETERS;

extern PVOID draugr_stub ( PVOID, PVOID, PVOID, PVOID, DRAUGR_PARAMETERS *, PVOID, SIZE_T, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID );

#define draugr_arg(i) ( ULONG_PTR ) ( call->args [ i ] )

void init_frame_info ( SYNTHETIC_STACK_FRAME * frame )
{
    PVOID frame1_module = KERNEL32$GetModuleHandleA ( "kernel32.dll" );
    PVOID frame2_module = KERNEL32$GetModuleHandleA ( "ntdll.dll" );

    frame->Frame1.ModuleAddress   = frame1_module;
    frame->Frame1.FunctionAddress = ( PVOID ) GetProcAddress ( ( HMODULE ) frame1_module, "BaseThreadInitThunk" );
    frame->Frame1.Offset          = 0x17;

    frame->Frame2.ModuleAddress   = frame2_module;
    frame->Frame2.FunctionAddress = ( PVOID ) GetProcAddress ( ( HMODULE ) frame2_module, "RtlUserThreadStart" );
    frame->Frame2.Offset          = 0x2c;

    PVOID lib = KERNEL32$GetModuleHandleA ( "combase.dll" );
    if ( lib != NULL ) {
        frame->Gadget = lib;
    } else {
        frame->Gadget = LoadLibraryA ( "combase.dll" );
    }
}

BOOL get_text_section_size ( PVOID module, PDWORD virtual_address, PDWORD size )
{
    IMAGE_DOS_HEADER * dos_header = ( IMAGE_DOS_HEADER * ) ( module );
    
    if ( dos_header->e_magic != IMAGE_DOS_SIGNATURE ) {
        return FALSE;
    }

    IMAGE_NT_HEADERS * nt_headers = ( IMAGE_NT_HEADERS * ) ( ( UINT_PTR ) module + dos_header->e_lfanew );
    
    if ( nt_headers->Signature != IMAGE_NT_SIGNATURE ) {
        return FALSE;
    }

    IMAGE_SECTION_HEADER * section_header = IMAGE_FIRST_SECTION ( nt_headers );
    
    for ( int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++ )
    {
        DWORD h = ror13hash ( ( char * ) section_header[ i ].Name );

        if ( h == TEXT_HASH )
        {
            *virtual_address = section_header[ i ].VirtualAddress;
            *size            = section_header[ i ].SizeOfRawData;
            
            return TRUE;
        }
    }

    return FALSE;
}

PVOID calculate_function_stack_size ( RUNTIME_FUNCTION * runtime_function, const DWORD64 image_base )
{
    UNWIND_INFO * unwind_info = NULL;
    ULONG unwind_operation    = 0;
    ULONG operation_info      = 0;
    ULONG index               = 0;
    ULONG frame_offset        = 0;

    STACK_FRAME stack_frame = { 0 };

    if ( ! runtime_function ) {
        return NULL;
    }

    unwind_info = ( UNWIND_INFO * ) ( runtime_function->UnwindData + image_base );
    
    while ( index < unwind_info->CountOfCodes )
    {
        unwind_operation = unwind_info->UnwindCode[ index ].UnwindOp;
        operation_info   = unwind_info->UnwindCode[ index ].OpInfo;

        /* don't use switch as it produces jump tables */
        if ( unwind_operation == UWOP_PUSH_NONVOL )
        {
            stack_frame.TotalStackSize += 8;

            if ( operation_info == RBP_OP_INFO )
            {
                stack_frame.PushRbp      = TRUE;
                stack_frame.CountOfCodes = unwind_info->CountOfCodes;
                stack_frame.PushRbpIndex = index + 1;
            }
        }
        else if ( unwind_operation == UWOP_SAVE_NONVOL )
        {
            index += 1;
        }
        else if ( unwind_operation == UWOP_ALLOC_SMALL )
        {
            stack_frame.TotalStackSize += ( ( operation_info * 8 ) + 8 );
        }
        else if ( unwind_operation == UWOP_ALLOC_LARGE )
        {
            index += 1;
            frame_offset = unwind_info->UnwindCode[ index ].FrameOffset;

            if (operation_info == 0)
            {
                frame_offset *= 8;
            }
            else
            {
                index += 1;
                frame_offset += ( unwind_info->UnwindCode[ index ].FrameOffset << 16 );
            }

            stack_frame.TotalStackSize += frame_offset;
        }
        else if ( unwind_operation == UWOP_SET_FPREG )
        {
            stack_frame.SetsFramePointer = TRUE;
        }
        else if ( unwind_operation == UWOP_SAVE_XMM128 )
        {
            return NULL;
        }

        index += 1;
    }

    if ( 0 != ( unwind_info->Flags & UNW_FLAG_CHAININFO ) )
    {
        index = unwind_info->CountOfCodes;

        if ( 0 != ( index & 1 ) )
        {
            index += 1;
        }

        runtime_function = ( RUNTIME_FUNCTION * ) ( &unwind_info->UnwindCode [ index ] );
        return calculate_function_stack_size ( runtime_function, image_base );
    }

    stack_frame.TotalStackSize += 8;
    return ( PVOID ) ( stack_frame.TotalStackSize );
}

PVOID calculate_function_stack_size_wrapper ( PVOID return_address )
{
    RUNTIME_FUNCTION      * runtime_function = NULL;
    DWORD64                 image_base       = 0;
    PUNWIND_HISTORY_TABLE   history_table    = NULL;

    if ( ! return_address ) {
        return NULL;
    }

    runtime_function = KERNEL32$RtlLookupFunctionEntry ( ( DWORD64 ) return_address, &image_base, history_table );

    if ( NULL == runtime_function ) {
        return NULL;
    }

    return calculate_function_stack_size ( runtime_function, image_base );
}

/*
 * Returns TRUE if the byte sequence immediately before (section_start + offset)
 * forms a valid CALL instruction, meaning the gadget address is a legitimate
 * return site. Checks the most common x64 CALL encodings:
 *   E8 rel32               (5 bytes, direct near call)
 *   FF /2  mod=11          (2 bytes, CALL reg)
 *   41 FF /2  mod=11       (3 bytes, CALL R8-R15)
 *   FF 15 disp32           (6 bytes, RIP-relative indirect call)
 *   FF /2  mod=00 rm≠4,5   (2 bytes, CALL [reg])
 *   FF /2  mod=01 rm≠4     (3 bytes, CALL [reg+d8])
 *   FF /2  mod=10 rm≠4     (6 bytes, CALL [reg+d32])
 */
static BOOL is_preceded_by_call ( PBYTE section_start, DWORD offset )
{
    PBYTE g = section_start + offset;

    /* E8 rel32 - direct near call (5 bytes) */
    if ( offset >= 5 && g[-5] == 0xE8 ) {
        return TRUE;
    }

    /* FF /2 variants - opcode extension 2: bits [5:3] of ModRM == 010 */
    if ( offset >= 2 && g[-2] == 0xFF && ( g[-1] & 0x38 ) == 0x10 ) {
        BYTE mod = g[-1] >> 6;
        BYTE rm  = g[-1] & 0x07;
        /* mod=11: CALL reg (2 bytes) */
        if ( mod == 3 ) { return TRUE; }
        /* mod=00: CALL [reg], rm not 4 (SIB) or 5 (disp32-only / RIP) */
        if ( mod == 0 && rm != 4 && rm != 5 ) { return TRUE; }
    }

    /* 41 FF /2 mod=11 - CALL R8..R15 (3 bytes) */
    if ( offset >= 3 && g[-3] == 0x41 && g[-2] == 0xFF &&
         ( g[-1] & 0x38 ) == 0x10 && ( g[-1] >> 6 ) == 3 ) {
        return TRUE;
    }

    /* FF /2 mod=01 rm≠4 - CALL [reg+d8] (3 bytes) */
    if ( offset >= 3 && g[-3] == 0xFF &&
         ( g[-2] & 0x38 ) == 0x10 && ( g[-2] >> 6 ) == 1 && ( g[-2] & 0x07 ) != 4 ) {
        return TRUE;
    }

    /* FF 15 disp32 - RIP-relative indirect call (6 bytes) */
    if ( offset >= 6 && g[-6] == 0xFF && g[-5] == 0x15 ) {
        return TRUE;
    }

    /* FF /2 mod=10 rm≠4 - CALL [reg+d32] (6 bytes) */
    if ( offset >= 6 && g[-6] == 0xFF &&
         ( g[-5] & 0x38 ) == 0x10 && ( g[-5] >> 6 ) == 2 && ( g[-5] & 0x07 ) != 4 ) {
        return TRUE;
    }

    return FALSE;
}

/*
 * Tries to match a JMP [REG+offset] gadget at position p (with `remaining'
 * bytes available). Supported registers: RBX (offset=0 only), RSI, RDI,
 * R12, R13, R14, R15. Returns TRUE and fills *info on success.
 */
static BOOL match_gadget_pattern ( PBYTE p, DWORD remaining, GADGET_INFO * info )
{
    if ( remaining < 2 ) return FALSE;

    /* ---- Non-REX forms (RBX, RSI, RDI) ---- */
    if ( p[0] == 0xFF ) {
        BYTE modrm = p[1];

        /* JMP [RBX]  FF 23  (offset=0 only – RBX is the fixup anchor) */
        if ( modrm == 0x23 ) { info->Register = GADGET_REG_RBX; info->Offset = 0; return TRUE; }
        /* JMP [RSI]  FF 26 */
        if ( modrm == 0x26 ) { info->Register = GADGET_REG_RSI; info->Offset = 0; return TRUE; }
        /* JMP [RDI]  FF 27 */
        if ( modrm == 0x27 ) { info->Register = GADGET_REG_RDI; info->Offset = 0; return TRUE; }

        if ( remaining >= 3 ) {
            INT8 d8 = ( INT8 ) p[2];
            /* JMP [RSI+d8]  FF 66 d8 */
            if ( modrm == 0x66 ) { info->Register = GADGET_REG_RSI; info->Offset = d8; return TRUE; }
            /* JMP [RDI+d8]  FF 67 d8 */
            if ( modrm == 0x67 ) { info->Register = GADGET_REG_RDI; info->Offset = d8; return TRUE; }
        }

        if ( remaining >= 6 ) {
            INT32 d32 = ( INT32 ) ( p[2] | ( ( DWORD ) p[3] << 8 ) | ( ( DWORD ) p[4] << 16 ) | ( ( DWORD ) p[5] << 24 ) );
            /* JMP [RSI+d32]  FF A6 d32 */
            if ( modrm == 0xA6 ) { info->Register = GADGET_REG_RSI; info->Offset = d32; return TRUE; }
            /* JMP [RDI+d32]  FF A7 d32 */
            if ( modrm == 0xA7 ) { info->Register = GADGET_REG_RDI; info->Offset = d32; return TRUE; }
        }
    }

    /* ---- REX.B (0x41) forms (R12, R13, R14, R15) ---- */
    if ( remaining >= 3 && p[0] == 0x41 && p[1] == 0xFF ) {
        BYTE modrm = p[2];

        /* JMP [R12]   41 FF 24 24  (rm=4 needs SIB 0x24) */
        if ( remaining >= 4 && modrm == 0x24 && p[3] == 0x24 ) {
            info->Register = GADGET_REG_R12; info->Offset = 0; return TRUE;
        }
        /* JMP [R14]   41 FF 26 */
        if ( modrm == 0x26 ) { info->Register = GADGET_REG_R14; info->Offset = 0; return TRUE; }
        /* JMP [R15]   41 FF 27 */
        if ( modrm == 0x27 ) { info->Register = GADGET_REG_R15; info->Offset = 0; return TRUE; }

        if ( remaining >= 4 ) {
            /* JMP [R12+d8]  41 FF 64 24 d8 */
            if ( remaining >= 5 && modrm == 0x64 && p[3] == 0x24 ) {
                info->Register = GADGET_REG_R12; info->Offset = ( INT8 ) p[4]; return TRUE;
            }
            /* JMP [R13+d8]  41 FF 65 d8  (d8=0 encodes [R13] with no disp) */
            if ( modrm == 0x65 ) { info->Register = GADGET_REG_R13; info->Offset = ( INT8 ) p[3]; return TRUE; }
            /* JMP [R14+d8]  41 FF 66 d8 */
            if ( modrm == 0x66 ) { info->Register = GADGET_REG_R14; info->Offset = ( INT8 ) p[3]; return TRUE; }
            /* JMP [R15+d8]  41 FF 67 d8 */
            if ( modrm == 0x67 ) { info->Register = GADGET_REG_R15; info->Offset = ( INT8 ) p[3]; return TRUE; }
        }

        if ( remaining >= 7 ) {
            INT32 d32 = ( INT32 ) ( p[3] | ( ( DWORD ) p[4] << 8 ) | ( ( DWORD ) p[5] << 16 ) | ( ( DWORD ) p[6] << 24 ) );
            /* JMP [R12+d32]  41 FF A4 24 d32  (SIB at p[3], d32 at p[4..7]) */
            if ( remaining >= 8 && modrm == 0xA4 && p[3] == 0x24 ) {
                INT32 dr12 = ( INT32 ) ( p[4] | ( ( DWORD ) p[5] << 8 ) | ( ( DWORD ) p[6] << 16 ) | ( ( DWORD ) p[7] << 24 ) );
                info->Register = GADGET_REG_R12; info->Offset = dr12; return TRUE;
            }
            /* JMP [R13+d32]  41 FF A5 d32 */
            if ( modrm == 0xA5 ) { info->Register = GADGET_REG_R13; info->Offset = d32; return TRUE; }
            /* JMP [R14+d32]  41 FF A6 d32 */
            if ( modrm == 0xA6 ) { info->Register = GADGET_REG_R14; info->Offset = d32; return TRUE; }
            /* JMP [R15+d32]  41 FF A7 d32 */
            if ( modrm == 0xA7 ) { info->Register = GADGET_REG_R15; info->Offset = d32; return TRUE; }
        }
    }

    return FALSE;
}

BOOL find_gadget_info ( PVOID module, GADGET_INFO * out )
{
    DWORD text_section_size = 0;
    DWORD text_section_va   = 0;
    DWORD counter           = 0;
    ULONG seed              = 0;
    ULONG random            = 0;
    PBYTE text              = NULL;

    GADGET_INFO gadget_list [ 15 ] = { 0 };

    if ( ! get_text_section_size ( module, &text_section_va, &text_section_size ) ) {
        return FALSE;
    }

    text = ( PBYTE ) ( ( UINT_PTR ) module + text_section_va );

    for ( DWORD i = 0; i < text_section_size && counter < 15; i++ )
    {
        GADGET_INFO candidate  = { 0 };
        DWORD       remaining  = text_section_size - i;

        if ( match_gadget_pattern ( text + i, remaining, &candidate ) &&
             is_preceded_by_call ( text, i ) )
        {
            candidate.Address        = ( PVOID ) ( text + i );
            gadget_list [ counter++ ] = candidate;
        }
    }

    if ( counter == 0 ) {
        return FALSE;
    }

    seed   = 0x1337;
    random = NTDLL$RtlRandomEx ( &seed );
    random %= counter;

    *out = gadget_list [ random ];
    return TRUE;
}

ULONG_PTR draugr_wrapper ( PVOID function, PVOID arg1, PVOID arg2, PVOID arg3, PVOID arg4, PVOID arg5, PVOID arg6, PVOID arg7, PVOID arg8, PVOID arg9, PVOID arg10, PVOID arg11, PVOID arg12 )
{
    int attempts         = 0;
    PVOID return_address = NULL;

    DRAUGR_PARAMETERS draugr_params = { 0 };

    SYNTHETIC_STACK_FRAME frame;
    init_frame_info ( &frame );

    return_address                                 = ( PVOID ) ( ( UINT_PTR ) frame.Frame1.FunctionAddress + frame.Frame1.Offset );
    draugr_params.BaseThreadInitThunkStackSize     = calculate_function_stack_size_wrapper ( return_address );
    draugr_params.BaseThreadInitThunkReturnAddress = return_address;

    if ( ! draugr_params.BaseThreadInitThunkStackSize || ! draugr_params.BaseThreadInitThunkReturnAddress ) {
        return ( ULONG_PTR ) ( NULL );
    }

    return_address                                = ( PVOID ) ( ( UINT_PTR ) frame.Frame2.FunctionAddress + frame.Frame2.Offset );
    draugr_params.RtlUserThreadStartStackSize     = calculate_function_stack_size_wrapper ( return_address );
    draugr_params.RtlUserThreadStartReturnAddress = return_address;

    if ( ! draugr_params.RtlUserThreadStartStackSize || ! draugr_params.RtlUserThreadStartReturnAddress ) {
        return ( ULONG_PTR ) ( NULL );
    }

    GADGET_INFO gadget_info = { 0 };

    do
    {
        if ( ! find_gadget_info ( frame.Gadget, &gadget_info ) ) {
            return ( ULONG_PTR ) ( NULL );
        }

        draugr_params.Trampoline          = gadget_info.Address;
        draugr_params.GadgetReg           = ( DWORD ) gadget_info.Register;
        draugr_params.GadgetOffset        = gadget_info.Offset;
        draugr_params.TrampolineStackSize = calculate_function_stack_size_wrapper ( draugr_params.Trampoline );

        attempts++;

        if ( attempts > 15 ) {
            return ( ULONG_PTR ) ( NULL );
        }

    } while ( draugr_params.TrampolineStackSize == NULL || ( ( __int64 ) draugr_params.TrampolineStackSize < 0x80 ) );

    if ( ! draugr_params.Trampoline || ! draugr_params.TrampolineStackSize ) {
        return ( ULONG_PTR ) ( NULL );
    }

    return ( ULONG_PTR ) draugr_stub ( arg1, arg2, arg3, arg4, &draugr_params, function, 8, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12 );
}

ULONG_PTR spoof_call ( FUNCTION_CALL * call )
{
    /* very inelegant */
    if ( call->argc == 0 ) {
        return draugr_wrapper ( call->ptr, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL );
    } else if ( call->argc == 1 ) {
        return draugr_wrapper ( call->ptr, ( PVOID ) draugr_arg ( 0 ), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL );
    } else if ( call->argc == 2 ) {
        return draugr_wrapper ( call->ptr, ( PVOID ) draugr_arg ( 0 ), ( PVOID ) draugr_arg ( 1 ), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL );
    } else if ( call->argc == 3 ) {
        return draugr_wrapper ( call->ptr, ( PVOID ) draugr_arg ( 0 ), ( PVOID ) draugr_arg ( 1 ), ( PVOID ) draugr_arg ( 2 ), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL );
    } else if ( call->argc == 4 ) {
        return draugr_wrapper ( call->ptr, ( PVOID ) draugr_arg ( 0 ), ( PVOID ) draugr_arg ( 1 ), ( PVOID ) draugr_arg ( 2 ), ( PVOID ) draugr_arg ( 3 ), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL );
    } else if ( call->argc == 5 ) {
        return draugr_wrapper ( call->ptr, ( PVOID ) draugr_arg ( 0 ), ( PVOID ) draugr_arg ( 1 ), ( PVOID ) draugr_arg ( 2 ), ( PVOID ) draugr_arg ( 3 ), ( PVOID ) draugr_arg ( 4 ), NULL, NULL, NULL, NULL, NULL, NULL, NULL );
    } else if ( call->argc == 6 ) {
        return draugr_wrapper ( call->ptr, ( PVOID ) draugr_arg ( 0 ), ( PVOID ) draugr_arg ( 1 ), ( PVOID ) draugr_arg ( 2 ), ( PVOID ) draugr_arg ( 3 ), ( PVOID ) draugr_arg ( 4 ), ( PVOID ) draugr_arg ( 5 ), NULL, NULL, NULL, NULL, NULL, NULL );
    } else if ( call->argc == 7 ) {
        return draugr_wrapper ( call->ptr, ( PVOID ) draugr_arg ( 0 ), ( PVOID ) draugr_arg ( 1 ), ( PVOID ) draugr_arg ( 2 ), ( PVOID ) draugr_arg ( 3 ), ( PVOID ) draugr_arg ( 4 ), ( PVOID ) draugr_arg ( 5 ), ( PVOID ) draugr_arg ( 6 ), NULL, NULL, NULL, NULL, NULL );
    } else if ( call->argc == 8 ) {
        return draugr_wrapper ( call->ptr, ( PVOID ) draugr_arg ( 0 ), ( PVOID ) draugr_arg ( 1 ), ( PVOID ) draugr_arg ( 2 ), ( PVOID ) draugr_arg ( 3 ), ( PVOID ) draugr_arg ( 4 ), ( PVOID ) draugr_arg ( 5 ), ( PVOID ) draugr_arg ( 6 ), ( PVOID ) draugr_arg ( 7 ), NULL, NULL, NULL, NULL );
    } else if ( call->argc == 9 ) {
        return draugr_wrapper ( call->ptr, ( PVOID ) draugr_arg ( 0 ), ( PVOID ) draugr_arg ( 1 ), ( PVOID ) draugr_arg ( 2 ), ( PVOID ) draugr_arg ( 3 ), ( PVOID ) draugr_arg ( 4 ), ( PVOID ) draugr_arg ( 5 ), ( PVOID ) draugr_arg ( 6 ), ( PVOID ) draugr_arg ( 7 ), ( PVOID ) draugr_arg ( 8 ), NULL, NULL, NULL );
    } else if ( call->argc == 10 ) {
        return draugr_wrapper ( call->ptr, ( PVOID ) draugr_arg ( 0 ), ( PVOID ) draugr_arg ( 1 ), ( PVOID ) draugr_arg ( 2 ), ( PVOID ) draugr_arg ( 3 ), ( PVOID ) draugr_arg ( 4 ), ( PVOID ) draugr_arg ( 5 ), ( PVOID ) draugr_arg ( 6 ), ( PVOID ) draugr_arg ( 7 ), ( PVOID ) draugr_arg ( 8 ), ( PVOID ) draugr_arg ( 9 ), NULL, NULL );
    } else if ( call->argc == 11 ) {
        return draugr_wrapper ( call->ptr, ( PVOID ) draugr_arg ( 0 ), ( PVOID ) draugr_arg ( 1 ), ( PVOID ) draugr_arg ( 2 ), ( PVOID ) draugr_arg ( 3 ), ( PVOID ) draugr_arg ( 4 ), ( PVOID ) draugr_arg ( 5 ), ( PVOID ) draugr_arg ( 6 ), ( PVOID ) draugr_arg ( 7 ), ( PVOID ) draugr_arg ( 8 ), ( PVOID ) draugr_arg ( 9 ), ( PVOID ) draugr_arg ( 10 ), NULL );
    } else if ( call->argc == 12 ) {
        return draugr_wrapper ( call->ptr, ( PVOID ) draugr_arg ( 0 ), ( PVOID ) draugr_arg ( 1 ), ( PVOID ) draugr_arg ( 2 ), ( PVOID ) draugr_arg ( 3 ), ( PVOID ) draugr_arg ( 4 ), ( PVOID ) draugr_arg ( 5 ), ( PVOID ) draugr_arg ( 6 ), ( PVOID ) draugr_arg ( 7 ), ( PVOID ) draugr_arg ( 8 ), ( PVOID ) draugr_arg ( 9 ), ( PVOID ) draugr_arg ( 10 ), ( PVOID ) draugr_arg ( 11 ) );
    } else {
        return ( ULONG_PTR ) ( NULL );
    }
}
