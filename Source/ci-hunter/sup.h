/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2015
*
*  TITLE:       SUP.H
*
*  VERSION:     1.10
*
*  DATE:        10 Mar 2015
*
*  Common header file for the program support routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

void supCopyMemory(
	_Inout_ void *dest,
	_In_ size_t ccdest,
	_In_ const void *src,
	_In_ size_t ccsrc
	);

PVOID supGetSystemInfo(
	_In_ SYSTEM_INFORMATION_CLASS InfoClass
	);

BOOL supBackupVBoxDrv(
	_In_ BOOL bRestore
	);

BOOL supGetCommandLineParamA(
	IN	LPCSTR	CmdLine,
	IN	ULONG	ParamIndex,
	OUT	LPSTR	Buffer,
	IN	ULONG	BufferSize,
	OUT	PULONG	ParamLen
	);

BOOL supGetCommandLineParamW(
	IN	LPCWSTR	CmdLine,
	IN	ULONG	ParamIndex,
	OUT	LPWSTR	Buffer,
	IN	ULONG	BufferSize,
	OUT	PULONG	ParamLen
	);

#ifdef _UNICODE
#define GetCommandLineParam supGetCommandLineParamW
#else
#define GetCommandLineParam supGetCommandLineParamA
#endif