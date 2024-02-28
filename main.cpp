#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <Shlwapi.h>
#include <psapi.h>

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "psapi.lib")

#define _CRT_SECURE_NO_WARNINGS

#define CREAZY_ARCADE_VERSION	146

void HookFunction();

#ifndef PEB_LDR_DATA_H
#define PEB_LDR_DATA_H

// UNICODE 字符串结构
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

// PEB_LDR_DATA 结构
typedef struct _PEB_LDR_DATA {
    ULONG Length; // +0x00
    BOOLEAN Initialized; // +0x04
    PVOID SsHandle; // +0x08
    LIST_ENTRY InLoadOrderModuleList; // +0x0c
    LIST_ENTRY InMemoryOrderModuleList; // +0x14
    LIST_ENTRY InInitializationOrderModuleList; // +0x1c
} PEB_LDR_DATA, *PPEB_LDR_DATA;

// LDR_DATA_TABLE_ENTRY 结构
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    WORD LoadCount;
    WORD TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

#endif /* PEB_LDR_DATA_H */

// 函数声明
void HookCRCPoints();
void HijackDLL(LPCWSTR dllname, LPWSTR OrigDllPath);
void* GetCurrentPEB();
PEB_LDR_DATA* GetPEB_LDR(void* peb);
void* FindModuleBaseAddress(LPCWSTR moduleName);
DWORD __stdcall CRC2FirstHandler(DWORD edx);
void SecondCRCHandler();
void ThirdCRCHandler();
void CRCMain();

// 全局变量
static void* _crc_file_start = NULL;
static void* _crc_file_end = NULL;
static void* _crc_image_start = NULL;
static void* _crc_image_end = NULL;

static DWORD _crc_hook_second = 0x011CF09E;
static DWORD _crc_back_second = 0x011CF0A6;

static DWORD _crc_hook_third = 0x01470E4D;
static DWORD _crc_back_third = 0x01470E53;

// 入口点
BOOL APIENTRY DllMain(HMODULE hDllHandle, DWORD dwReason, LPVOID lpreserved) {
    switch (dwReason) {
        case DLL_PROCESS_ATTACH:
            HijackDLL(L"nmcogame.dll", L"path_to_your_dll.dll");
            CRCMain();
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}

// 主函数，执行 CRC 旁路和 DLL 劫持
void CRCMain() {
    MODULEINFO mi = { 0 };
    GetModuleInformation(GetCurrentProcess(), GetModuleHandle(NULL), &mi, sizeof(mi));
    if (!mi.SizeOfImage) {
        MessageBoxA(NULL, "无法获取模块信息。", NULL, MB_OK);
        return;
    }

    // 动态映射 DLL，防止多个实例问题
    CHAR mapName[32] = { 0 };
    sprintf_s(mapName, "KartRider_CRC_Mapping %08X", GetCurrentProcessId());
    HANDLE hFileMap = CreateFileMappingA(GetCurrentProcess(), NULL, PAGE_READWRITE, 0, mi.SizeOfImage, mapName);
    if (!hFileMap) {
        MessageBoxA(NULL, "无法创建映射。", NULL, MB_OK);
        return;
    }

    LPVOID lpMappingBase = MapViewOfFile(hFileMap, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
    if (!lpMappingBase) {
        MessageBoxA(NULL, "无法查看文件。", NULL, MB_OK);
        CloseHandle(hFileMap);
        return;
    }

    // 复制模块镜像
    DWORD dwHasWritten = 0;
    WriteProcessMemory(GetCurrentProcess(), lpMappingBase, mi.lpBaseOfDll, mi.SizeOfImage, &dwHasWritten);

    // 初始化全局变量
    _crc_file_start = mi.lpBaseOfDll;
    _crc_file_end = (void*)((DWORD)_crc_file_start + mi.SizeOfImage);
    _crc_image_start = lpMappingBase;
    _crc_image_end = (void*)((DWORD)_crc_image_start + mi.SizeOfImage);

    // 钩住 CRC 检测点
    HookCRCPoints();
}

// 函数用于钩住 CRC 检测点
void HookCRCPoints() {
    inlineHook((PVOID)_crc_hook_second, SecondCRCHandler);
    inlineHook((PVOID)_crc_hook_third, ThirdCRCHandler);
}

// 函数处理第二个 CRC 检测点
void SecondCRCHandler() {
    __asm {
        pushad
        push edi
        call CRC2FirstHandler
        cmp eax, 0x0
        je __handle_crc
        popad
        jmp fina
    __handle_crc :
        popad
        sub edi, _crc_file_start
        add edi, _crc_image_start
    fina :
        __emit 0x8b
        __emit 0x3F
        __emit 0x81
        __emit 0xEE
        __emit 0x40
        __emit 0x00
        __emit 0x00
        __emit 0x00
        jmp _crc_back_second
    }
}

// 函数处理第三个 CRC 检测点
__declspec(naked) void ThirdCRCHandler() {
    __asm {
        CMP ebx, _crc_file_start
        Jb fina
        CMP ebx, _crc_file_end
        Ja fina
        SUB ebx, _crc_file_start
        ADD ebx, _crc_image_start
    fina :
        add al, [ebx]
        pop ebx
        push ebx
        mov bh, 0x3E
        jmp _crc_back_third
    }
}

// 函数处理第一个 CRC 检测点
DWORD __stdcall CRC2FirstHandler(DWORD edx) {
    static DWORD dwThird1 = _crc_hook_third - 0x10, dwThird2 = _crc_hook_third + 0x10;
    if (edx > (DWORD)_crc_file_start && edx < 0x00F00000) {
        return 1;
    } else if (edx > dwThird1 && edx < dwThird2) {
        return 1;
    }
    return 0;
}

// 函数用于劫持 DLL，将其替换为另一个 DLL
void HijackDLL(LPCWSTR dllname, LPWSTR OrigDllPath) {
    WCHAR wszDllName[100] = { 0 };
    void* peb = GetCurrentPEB();
    PEB_LDR_DATA* ldr = GetPEB_LDR(peb);

    for (LIST_ENTRY* entry = ldr->InLoadOrderModuleList.Blink;
        entry != (LIST_ENTRY*)(&ldr->InLoadOrderModuleList);
        entry = entry->Blink) {
        PLDR_DATA_TABLE_ENTRY data = (PLDR_DATA_TABLE_ENTRY)entry;

        memset(wszDllName, 0, 100 * 2);
        memcpy(wszDllName, data->BaseDllName.Buffer, data->BaseDllName.Length);

        if (!_wcsicmp(wszDllName, dllname)) {
            HMODULE hMod = LoadLibrary((LPCSTR)OrigDllPath);
            data->DllBase = hMod;
            break;
        }
    }
}

// 函数获取当前 PEB
void* GetCurrentPEB() {
#ifdef _WIN64
    return (void*)__readgsqword(0x30);
#else
    __asm {
        mov eax, fs:[0x30];
    }
#endif
}

// 函数获取 PEB_LDR 数据
PEB_LDR_DATA* GetPEB_LDR(void* peb) {
#ifdef _WIN64
    return (PEB_LDR_DATA*)(*(ULONGLONG*)((BYTE*)peb + 0x18));
#else
    __asm {
        mov eax, peb;
        mov eax, [eax + 0xc];
    }
#endif
}


void HookFunction() {
    // 在这里执行我们的代码
    printf("Hooked function called!\n");

    // 调用原始的函数（如果需要）
    // 这里需要根据实际情况来调用原始函数，可能需要保存和恢复寄存器状态
}

// Inline Hook 函数
void inlineHook(void* lpCurBase, void* lpToBase) {
    // 跳转指令的字节码
    unsigned char hookCode[5] = { 0xE9 }; // JMP 指令

    // 计算跳转地址
    int offset = (int)lpToBase - (int)lpCurBase - 5;

    // 将偏移量写入跳转指令
    hookCode[1] = (offset >> 24) & 0xFF;
    hookCode[2] = (offset >> 16) & 0xFF;
    hookCode[3] = (offset >> 8) & 0xFF;
    hookCode[4] = offset & 0xFF;

    // 写入跳转指令到目标地址
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(GetCurrentProcess(), lpCurBase, hookCode, sizeof(hookCode), &bytesWritten)) {
        printf("Failed to write hook code. Error: %d\n", GetLastError());
        return;
    }

    if (bytesWritten != sizeof(hookCode)) {
        printf("Hook code was not fully written.\n");
        return;
    }

    printf("Hook successful.\n");
}
