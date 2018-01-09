/*
 * Process Hacker Injector plugin -
 *   main program
 *
 * Copyright (C) 2018 diversenok
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
#include "injectdll.h"

#define INJECTOR_MENU_ID 1

PPH_PLUGIN PluginInstance;
static PH_CALLBACK_REGISTRATION ProcessMenuInitializingCallbackRegistration;
static PH_CALLBACK_REGISTRATION PluginMenuItemCallbackRegistration;

VOID AddMenuItemsAndHook(
    _In_ PPH_PLUGIN_MENU_INFORMATION MenuInfo,
    _In_ PPH_PROCESS_ITEM ProcessItem,
    _In_ BOOLEAN UseSelectionForHook
)
{
    PPH_EMENU_ITEM MiscMenuItem;

    if (MiscMenuItem = PhFindEMenuItem(MenuInfo->Menu, 0, L"Miscellaneous", 0))
    {
        PhInsertEMenuItem(MiscMenuItem, PhPluginCreateEMenuItem(PluginInstance, 0, INJECTOR_MENU_ID, L"&Inject DLL...", NULL), 2);
    }

    PhPluginAddMenuHook(MenuInfo, PluginInstance, UseSelectionForHook ? NULL : ProcessItem->ProcessId);
}

VOID ProcessMenuInitializingCallback(
	_In_opt_ PVOID Parameter,
	_In_opt_ PVOID Context
)
{
	PPH_PLUGIN_MENU_INFORMATION menuInfo = Parameter;
	PPH_PROCESS_ITEM processItem;

	if (menuInfo->u.Process.NumberOfProcesses != 1)
		return;

	processItem = menuInfo->u.Process.Processes[0];

	if (!PH_IS_FAKE_PROCESS_ID(processItem->ProcessId) && processItem->ProcessId != SYSTEM_IDLE_PROCESS_ID && processItem->ProcessId != SYSTEM_PROCESS_ID)
		AddMenuItemsAndHook(menuInfo, processItem, TRUE);

	return;
}

VOID NTAPI MenuItemCallback(
	_In_opt_ PVOID Parameter,
	_In_opt_ PVOID Context
)
{
	PPH_PLUGIN_MENU_ITEM menuItem = Parameter;
	PPH_PROCESS_ITEM processItem = PhGetSelectedProcessItem();

	if (!processItem)
		return;

    if (menuItem->Id == INJECTOR_MENU_ID)
    {
        PhReferenceObject(processItem);
        PhUiInjectDllProcess2(PhMainWndHandle, processItem);
        PhDereferenceObject(processItem);
    }
}

LOGICAL DllMain(
	_In_ HINSTANCE Instance,
	_In_ ULONG Reason,
	_Reserved_ PVOID Reserved
)
{
	switch (Reason)
	{
	case DLL_PROCESS_ATTACH:
	{
		PPH_PLUGIN_INFORMATION info;

		PluginInstance = PhRegisterPlugin(L"ProcessHacker.Injector", Instance, &info);

		if (!PluginInstance)
			return FALSE;

		info->DisplayName = L"DLL Injection Plugin";
		info->Author = L"diversenok";
		info->Description = L"Provides a menu for processes to inject dlls.";
		info->Url = L"https://github.com/processhacker2/plugins-extra";
		info->HasOptions = FALSE;

		PhRegisterCallback(
			PhGetGeneralCallback(GeneralCallbackProcessMenuInitializing),
			ProcessMenuInitializingCallback,
			NULL,
			&ProcessMenuInitializingCallbackRegistration
		);
		PhRegisterCallback(
			PhGetPluginCallback(PluginInstance, PluginCallbackMenuItem),
			MenuItemCallback,
			NULL,
			&PluginMenuItemCallbackRegistration
		);

	}
	break;
	}

	return TRUE;
}