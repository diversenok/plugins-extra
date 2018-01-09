#include <phdk.h>

NTSTATUS PhInjectDllProcess2(
    _In_ HANDLE ProcessHandle,
    _In_ PWSTR FileName,
    _In_opt_ PLARGE_INTEGER Timeout
);

BOOLEAN PhUiInjectDllProcess2(
    _In_ HWND hWnd,
    _In_ PPH_PROCESS_ITEM Process
);