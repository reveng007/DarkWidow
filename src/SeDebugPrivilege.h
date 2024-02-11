#pragma once

#include "Init.h"

int UpdatePriv(LPCTSTR lpszPrivilege)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(MyCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
    {
        printf("OpenProcessToken() failed! (%u)\n", GetLastError());
        return -1;
    }

    if (!LookupPrivilegeValue(
        NULL,            // lookup privilege on local system
        lpszPrivilege,   // privilege to lookup 
        &luid))        // receives LUID of privilege
    {
        printf("\n[!] LookupPrivilegeValue error: (%u)\n", GetLastError());
        return -1;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;

    // Granting SedebugPrivilege Attribute
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
    {
        printf("\n[!] AdjustTokenPrivileges error: (%u)\n", GetLastError());
        return -1;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        printf("\n[!] Alas! token does not have specified privilege.\n");
        return -1;
    }
    return 0;
}
