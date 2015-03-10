/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015
*
*  TITLE:       SUP.C
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
#include <Shlwapi.h>
//include for PathFileExists API
#pragma comment(lib, "shlwapi.lib")

/*
* supCopyMemory
*
* Purpose:
*
* Copies bytes between buffers.
*
* dest - Destination buffer 
* cbdest - Destination buffer size in bytes
* src - Source buffer
* cbsrc - Source buffer size in bytes
*
*/
void supCopyMemory(
	_Inout_ void *dest,
	_In_ size_t cbdest,
	_In_ const void *src,
	_In_ size_t cbsrc
	)
{
	char *d = (char*)dest;
	char *s = (char*)src;

	if ((dest == 0) || (src == 0) || (cbdest == 0))
		return;
	if (cbdest<cbsrc)
		cbsrc = cbdest;

	while (cbsrc>0) {
		*d++ = *s++;
		cbsrc--;
	}
}

/*
* supGetSystemInfo
*
* Purpose:
*
* Returns buffer with system information by given InfoClass.
*
* Returned buffer must be freed with HeapFree after usage.
* Function will return error after 100 attempts.
*
*/
PVOID supGetSystemInfo(
	_In_ SYSTEM_INFORMATION_CLASS InfoClass
	)
{
	INT			c = 0;
	PVOID		Buffer = NULL;
	ULONG		Size	= 0x1000;
	NTSTATUS	status;
	ULONG       memIO;

	do {
		Buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Size);
		if (Buffer != NULL) {
			status = NtQuerySystemInformation(InfoClass, Buffer, Size, &memIO);
		}
		else {
			return NULL;
		}
		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			HeapFree(GetProcessHeap(), 0, Buffer);
			Size *= 2;
		}
		c++;
		if (c > 100) {
			status = STATUS_SECRET_TOO_LONG;
			break;
		}
	} while (status == STATUS_INFO_LENGTH_MISMATCH);

	if (NT_SUCCESS(status)) {
		return Buffer;
	}

	if (Buffer) {
		HeapFree(GetProcessHeap(), 0, Buffer);
	}
	return NULL;
}

/*
* supBackupVBoxDrv
*
* Purpose:
*
* Backup virtualbox driver file if it already installed.
*
*/
BOOL supBackupVBoxDrv(
	_In_ BOOL bRestore
	)
{
	BOOL bResult = FALSE;
	WCHAR szOldDriverName[MAX_PATH * 2];
	WCHAR szNewDriverName[MAX_PATH * 2];
	WCHAR szDriverDirName[MAX_PATH * 2];

	if (!GetSystemDirectory(szDriverDirName, MAX_PATH)) {
		return FALSE;
	}

	_strcat(szDriverDirName, TEXT("\\drivers\\"));

	if (bRestore) {
		_strcpy(szOldDriverName, szDriverDirName);
		_strcat(szOldDriverName, TEXT("VBoxDrv.backup"));
		if (PathFileExists(szOldDriverName)) {
			_strcpy(szNewDriverName, szDriverDirName);
			_strcat(szNewDriverName, TEXT("VBoxDrv.sys"));
			bResult = MoveFileEx(szOldDriverName, szNewDriverName,
				MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
		}
	}
	else {
		_strcpy(szOldDriverName, szDriverDirName);
		_strcat(szOldDriverName, TEXT("VBoxDrv.sys"));

		bResult = PathFileExists(szOldDriverName);

		_strcpy(szNewDriverName, szDriverDirName);
		_strcat(szNewDriverName, TEXT("VBoxDrv.backup"));
		MoveFileEx(szOldDriverName, szNewDriverName, 
			MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
	}
	return bResult;
}

/*
* supGetCommandLineParamW
*
* Purpose:
*
* Query token from command line.
*
* Return value: TRUE on success, FALSE otherwise
*
* Remark: UNICODE variant
*
*/
BOOL supGetCommandLineParamA(
	IN	LPCSTR	CmdLine,
	IN	ULONG	ParamIndex,
	OUT	LPSTR	Buffer,
	IN	ULONG	BufferSize,
	OUT	PULONG	ParamLen
	)
{
	ULONG	c, plen = 0;
	TCHAR	divider;

	if (CmdLine == NULL)
		return FALSE;

	if (ParamLen != NULL)
		*ParamLen = 0;

	for (c = 0; c <= ParamIndex; c++) {
		plen = 0;

		while (*CmdLine == ' ')
			CmdLine++;

		switch (*CmdLine) {
		case 0:
			goto zero_term_exit;

		case '"':
			CmdLine++;
			divider = '"';
			break;

		default:
			divider = ' ';
		}

		while ((*CmdLine != '"') && (*CmdLine != divider) && (*CmdLine != 0)) {
			plen++;
			if (c == ParamIndex)
				if ((plen < BufferSize) && (Buffer != NULL)) {
					*Buffer = *CmdLine;
					Buffer++;
				}
			CmdLine++;
		}

		if (*CmdLine != 0)
			CmdLine++;
	}

zero_term_exit:

	if ((Buffer != NULL) && (BufferSize > 0))
		*Buffer = 0;

	if (ParamLen != NULL)
		*ParamLen = plen;

	if (plen < BufferSize)
		return TRUE;
	else
		return FALSE;
}


/*
* supGetCommandLineParamW
*
* Purpose:
*
* Query token from command line.
*
* Return value: TRUE on success, FALSE otherwise
*
* Remark: UNICODE variant
*
*/
BOOL supGetCommandLineParamW(
	IN	LPCWSTR	CmdLine,
	IN	ULONG	ParamIndex,
	OUT	LPWSTR	Buffer,
	IN	ULONG	BufferSize,
	OUT	PULONG	ParamLen
	)
{
	ULONG	c, plen = 0;
	TCHAR	divider;

	if (ParamLen != NULL)
		*ParamLen = 0;

	if (CmdLine == NULL) {
		if ((Buffer != NULL) && (BufferSize > 0))
			*Buffer = 0;
		return FALSE;
	}

	for (c = 0; c <= ParamIndex; c++) {
		plen = 0;

		while (*CmdLine == ' ')
			CmdLine++;

		switch (*CmdLine) {
		case 0:
			goto zero_term_exit;

		case '"':
			CmdLine++;
			divider = '"';
			break;

		default:
			divider = ' ';
		}

		while ((*CmdLine != '"') && (*CmdLine != divider) && (*CmdLine != 0)) {
			plen++;
			if (c == ParamIndex)
				if ((plen < BufferSize) && (Buffer != NULL)) {
					*Buffer = *CmdLine;
					Buffer++;
				}
			CmdLine++;
		}

		if (*CmdLine != 0)
			CmdLine++;
	}

zero_term_exit:

	if ((Buffer != NULL) && (BufferSize > 0))
		*Buffer = 0;

	if (ParamLen != NULL)
		*ParamLen = plen;

	if (plen < BufferSize)
		return TRUE;
	else
		return FALSE;
}