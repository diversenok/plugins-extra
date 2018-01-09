/*
* Process Hacker Injector plugin -
*   dll injection code
*
* Copyright (C) 2017 dmex
*
* This file is part of Process Hacker.
*
* Process Hacker is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* Process Hacker is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with Process Hacker.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <phdk.h>
#include "mapimg.h"
#include "injectdll.h"

/**
* Causes a process to load a DLL.
*
* \param ProcessHandle A handle to a process. The handle must have
* PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_CREATE_THREAD, PROCESS_VM_OPERATION, PROCESS_VM_READ
* and PROCESS_VM_WRITE access.
* \param FileName The file name of the DLL to inject.
* \param Timeout The timeout, in milliseconds, for the process to load the DLL.
*
* \remarks If the process does not load the DLL before the timeout expires it may crash. Choose the
* timeout value carefully.
*/
NTSTATUS PhInjectDllProcess2(
    _In_ HANDLE ProcessHandle,
    _In_ PWSTR FileName,
    _In_opt_ PLARGE_INTEGER Timeout
)
{
#ifdef _WIN64
    static PVOID loadLibraryW32 = NULL;
#endif

    NTSTATUS status;
#ifdef _WIN64
    BOOLEAN isWow64 = FALSE;
    BOOLEAN isModule32 = FALSE;
    PH_MAPPED_IMAGE mappedImage;
#endif
    PVOID threadStart;
    PH_STRINGREF fileName;
    PVOID baseAddress = NULL;
    SIZE_T allocSize;
    HANDLE threadHandle;

#ifdef _WIN64
    PhGetProcessIsWow64(ProcessHandle, &isWow64);

    if (isWow64)
    {
        if (!NT_SUCCESS(status = PhLoadMappedImage(FileName, NULL, TRUE, &mappedImage)))
            return status;

        isModule32 = mappedImage.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC;
        NtUnmapViewOfSection(
            NtCurrentProcess(),
            mappedImage.ViewBase
        );
    }

    if (!isModule32)
    {
#endif
        threadStart = PhGetModuleProcAddress(L"kernel32.dll", "LoadLibraryW");
#ifdef _WIN64
    }
    else
    {
        threadStart = loadLibraryW32;

        if (!threadStart)
        {
            PPH_STRING kernel32FileName;

            kernel32FileName = PhConcatStrings2(USER_SHARED_DATA->NtSystemRoot, L"\\SysWow64\\kernel32.dll");
            status = PhGetProcedureAddressRemote(
                ProcessHandle,
                kernel32FileName->Buffer,
                "LoadLibraryW",
                0,
                &loadLibraryW32,
                NULL
            );
            PhDereferenceObject(kernel32FileName);

            if (!NT_SUCCESS(status))
                return status;

            threadStart = loadLibraryW32;
        }
    }
#endif

    PhInitializeStringRefLongHint(&fileName, FileName);
    allocSize = fileName.Length + sizeof(WCHAR);

    if (!NT_SUCCESS(status = NtAllocateVirtualMemory(
        ProcessHandle,
        &baseAddress,
        0,
        &allocSize,
        MEM_COMMIT,
        PAGE_READWRITE
    )))
        return status;

    if (!NT_SUCCESS(status = NtWriteVirtualMemory(
        ProcessHandle,
        baseAddress,
        fileName.Buffer,
        fileName.Length + sizeof(WCHAR),
        NULL
    )))
        goto FreeExit;

    if (!NT_SUCCESS(status = RtlCreateUserThread(
        ProcessHandle,
        NULL,
        FALSE,
        0,
        0,
        0,
        threadStart,
        baseAddress,
        &threadHandle,
        NULL
    )))
        goto FreeExit;

    // Wait for the thread to finish.
    status = NtWaitForSingleObject(threadHandle, FALSE, Timeout);
    NtClose(threadHandle);

FreeExit:
    // Size needs to be zero if we're freeing.
    allocSize = 0;
    NtFreeVirtualMemory(
        ProcessHandle,
        &baseAddress,
        &allocSize,
        MEM_RELEASE
    );

    return status;
}

BOOLEAN PhUiInjectDllProcess2(
    _In_ HWND hWnd,
    _In_ PPH_PROCESS_ITEM Process
)
{
    static PH_FILETYPE_FILTER filters[] =
    {
        { L"DLL files (*.dll)", L"*.dll" },
        { L"All files (*.*)", L"*.*" }
    };

    NTSTATUS status;
    PVOID fileDialog;
    PPH_STRING fileName;
    HANDLE processHandle;

    fileDialog = PhCreateOpenFileDialog();
    PhSetFileDialogFilter(fileDialog, filters, sizeof(filters) / sizeof(PH_FILETYPE_FILTER));

    if (!PhShowFileDialog(hWnd, fileDialog))
    {
        PhFreeFileDialog(fileDialog);
        return FALSE;
    }

    fileName = PH_AUTO(PhGetFileDialogFileName(fileDialog));
    PhFreeFileDialog(fileDialog);

    if (NT_SUCCESS(status = PhOpenProcess(
        &processHandle,
        ProcessQueryAccess | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
        PROCESS_VM_READ | PROCESS_VM_WRITE,
        Process->ProcessId
    )))
    {
        LARGE_INTEGER timeout;

        timeout.QuadPart = -5 * PH_TIMEOUT_SEC;
        status = PhInjectDllProcess2(
            processHandle,
            fileName->Buffer,
            &timeout
        );

        NtClose(processHandle);
    }

    if (!NT_SUCCESS(status))
    {
        PhShowContinueStatus(hWnd,
            PhaFormatString(
                L"Unable to %s %s (PID %u)", L"inject the DLL into",
                Process->ProcessName->Buffer,
                HandleToUlong(Process->ProcessId)
            )->Buffer,
            status,
            0
        );
        return FALSE;
    }

    return TRUE;
}