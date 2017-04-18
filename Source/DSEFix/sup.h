/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2017
*
*  TITLE:       SUP.H
*
*  VERSION:     1.20
*
*  DATE:        18 Apr 2017
*
*  Common header file for the program support routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef NTSTATUS(NTAPI *PENUMOBJECTSCALLBACK)(POBJECT_DIRECTORY_INFORMATION Entry, PVOID CallbackParam);

typedef struct _OBJSCANPARAM {
    PWSTR Buffer;
    ULONG BufferSize;
} OBJSCANPARAM, *POBJSCANPARAM;

void supCopyMemory(
    _Inout_ void *dest,
    _In_ size_t ccdest,
    _In_ const void *src,
    _In_ size_t ccsrc);

PVOID supGetSystemInfo(
    _In_ SYSTEM_INFORMATION_CLASS InfoClass);

BOOL supBackupVBoxDrv(
    _In_ BOOL bRestore);

DWORD supWriteBufferToFile(
    _In_ LPWSTR lpFileName,
    _In_ PVOID Buffer,
    _In_ DWORD BufferSize);

BOOL supIsObjectExists(
    _In_ LPWSTR RootDirectory,
    _In_ LPWSTR ObjectName);

ULONG_PTR supGetModuleBaseByName(
    _In_ LPSTR ModuleName);

PVOID supMapFile(
    _In_ LPWSTR lpFileName,
    _Out_ PSIZE_T VirtualSize);

#define PathFileExists(lpszPath) (GetFileAttributes(lpszPath) != (DWORD)-1)
