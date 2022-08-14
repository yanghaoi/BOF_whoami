/*
 * PROJECT:     ReactOS Whoami
 * LICENSE:     GPL - See COPYING in the top level directory
 * FILE:        base/applications/cmdutils/whoami/whoami.c
 * PURPOSE:     Displays information about the current local user, groups and privileges.
 * PROGRAMMERS: Ismael Ferreras Morezuelas (swyterzone+ros@gmail.com)
 */

#include <windows.h>
#define SECURITY_WIN32
#include <security.h>
#include <sddl.h>
#include "bofdefs.h"
#include "base.c"

#define UNLEN       256  
WINADVAPI BOOL WINAPI ADVAPI32$LookupPrivilegeNameW(LPCWSTR lpSystemName, PLUID   lpLuid, LPWSTR  lpName, LPDWORD cchName);
WINBASEAPI UINT WINAPI Kernel32$GetACP(void);
WINADVAPI BOOL WINAPI  ADVAPI32$LookupPrivilegeDisplayNameW(LPCWSTR lpSystemName,LPCWSTR lpName,LPWSTR  lpDisplayName,LPDWORD cchDisplayName, LPDWORD lpLanguageId);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenThreadToken( HANDLE ThreadHandle, DWORD DesiredAccess,BOOL OpenAsSelf,PHANDLE TokenHandle);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentThread(VOID);
DECLSPEC_IMPORT  BOOL WINAPI ADVAPI32$ImpersonateSelf(SECURITY_IMPERSONATION_LEVEL);
DECLSPEC_IMPORT DWORD ADVAPI32$GetLengthSid( PSID pSid);

typedef struct
{
    UINT Rows;
    UINT Cols;
    LPWSTR Content[1];
} WhoamiTable;

// new
BOOL Wchar2Char(char** cszTemp, const wchar_t* wszTemp, UINT Nacp) {
    BOOL blRes = FALSE;
    int iReturn = 0;
    int nbytes = 0;
    *cszTemp = NULL;
    DWORD dwCstr = MSVCRT$wcslen(wszTemp);
    nbytes = Kernel32$WideCharToMultiByte(Nacp, 0, wszTemp, -1, NULL, 0, NULL, NULL);
    if (nbytes == 0) {
        // wprintf(L"[-] WideCharToMultiByte() failed (Err: %d)\n", KERNEL32$GetLastError());
        goto CleanUp;
    }

    if (NULL == (*cszTemp = (char*)KERNEL32$LocalAlloc((0x0000 | 0x0040), nbytes * sizeof(char)))) {
        //  wprintf(L"[-] LocalAlloc() failed (Err: %d)\n", KERNEL32$GetLastError());
        goto CleanUp;
    }

    iReturn = Kernel32$WideCharToMultiByte(Nacp, 0, wszTemp, dwCstr, *cszTemp, nbytes, NULL, NULL);
    if (iReturn == 0) {
        // wprintf(L"[-] WideCharToMultiByte() failed (Err: %d)\n", KERNEL32$GetLastError());
        goto CleanUp;
    }

    blRes = TRUE;

CleanUp:
    if (!blRes) {
        if (*cszTemp != NULL) {
            KERNEL32$LocalFree(*cszTemp);
            *cszTemp = NULL;
        }
    }
    return blRes;
}

char* WhoamiGetUser(EXTENDED_NAME_FORMAT NameFormat)
{
    char* UsrBuf = intAlloc(MAX_PATH);
    ULONG UsrSiz = MAX_PATH;

    if (UsrBuf == NULL)
        return NULL;

    if (SECUR32$GetUserNameExA(NameFormat, UsrBuf, &UsrSiz))
    {
        return UsrBuf;
    }

    intFree(UsrBuf);
    return NULL;
}

VOID* WhoamiGetTokenInfo(TOKEN_INFORMATION_CLASS TokenType)
{
    HANDLE hToken = 0;
    DWORD dwLength = 0;
    VOID* pTokenInfo = 0;


    if (!ADVAPI32$OpenThreadToken(KERNEL32$GetCurrentThread(), TOKEN_READ, FALSE, &hToken) != FALSE) {
        if (KERNEL32$GetLastError() == ERROR_NO_TOKEN) {  // 1008
            if (!ADVAPI32$ImpersonateSelf(SecurityImpersonation)) {
                BeaconPrintf(CALLBACK_OUTPUT, "[-] ADVAPI32$ImpersonateSelf failed (Err: %d) = %d  ", KERNEL32$GetLastError(), __LINE__);
                return NULL;
            }
            if (!ADVAPI32$OpenThreadToken(KERNEL32$GetCurrentThread(), TOKEN_READ, FALSE, &hToken)) {
                BeaconPrintf(CALLBACK_OUTPUT, "[-] OpenThreadToken() failed (Err: %d) = %d  ", KERNEL32$GetLastError(), __LINE__);
               
                if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_READ, &hToken))
                {
                    BeaconPrintf(CALLBACK_OUTPUT, "[-] OpenProcessToken() failed (Err: %d) = %d  ", KERNEL32$GetLastError(), __LINE__);
                    return NULL;
                }
            }
        }
    }

    if (hToken != 0)
    {
        ADVAPI32$GetTokenInformation(hToken,
            TokenType,
            NULL,
            dwLength,
            &dwLength);

        if (KERNEL32$GetLastError() == ERROR_INSUFFICIENT_BUFFER)
        {
            pTokenInfo = intAlloc(dwLength);
            if (pTokenInfo == NULL)
            {
                //printf("ERROR: not enough memory to allocate the token structure.\r\n");
                KERNEL32$CloseHandle(hToken);
                return NULL;
            }
        }

        if (!ADVAPI32$GetTokenInformation(hToken, TokenType,
            (LPVOID)pTokenInfo,
            dwLength,
            &dwLength))
        {
            //printf("ERROR 0x%x: could not get token information.\r\n", GetLastError());
            KERNEL32$CloseHandle(hToken);
            intFree(pTokenInfo);
            return NULL;
        }

        KERNEL32$CloseHandle(hToken);
    }
    return pTokenInfo;
}



int WhoamiUser(void)
{
    PTOKEN_USER pUserInfo = (PTOKEN_USER)WhoamiGetTokenInfo(TokenUser);
    char* pUserStr = NULL;
    char* pSidStr = NULL;
    WhoamiTable* UserTable = NULL;
    int retval = 0;

    if (pUserInfo == NULL)
    {
        retval = 1;
        goto end;
    }

    pUserStr = WhoamiGetUser(NameSamCompatible);
    if (pUserStr == NULL)
    {
        retval = 1;
        goto end;
    }

    // Find Current Thread user in sid
    DWORD dwLen = UNLEN + 1;
    DWORD dwSize = 0;
    char* pwszDomain = NULL;           // domain
    char* pwszCurrentUsername = NULL;  // user name
    LPDWORD pdwLen = &dwLen;
    SID_NAME_USE Snu;
    
    if (!ADVAPI32$LookupAccountSidA(NULL, pUserInfo->User.Sid, pwszCurrentUsername, pdwLen, pwszDomain, &dwSize, &Snu)) {
        // BeaconPrintf(CALLBACK_OUTPUT, "[-] LookupAccountSidA() failed (Err: %d),pdwLen: %d,dwSize:%d ", KERNEL32$GetLastError(), *pdwLen, dwSize);
        if (NULL == (pwszCurrentUsername = (char*)KERNEL32$LocalAlloc(LPTR, *pdwLen))) {
            BeaconPrintf(CALLBACK_ERROR, "LocalAlloc() failed: % d in % d  ", KERNEL32$GetLastError(), __LINE__);
            goto end;
        }
        if (NULL == (pwszDomain = (char*)KERNEL32$LocalAlloc(LPTR, dwSize))) {
            BeaconPrintf(CALLBACK_OUTPUT, "[-] LocalAlloc() pwszDomain failed (Err: %d) ", KERNEL32$GetLastError());
            goto end;
        }
        // ADVAPI32$LookupAccountSidW
        if (!ADVAPI32$LookupAccountSidA(NULL, pUserInfo->User.Sid, pwszCurrentUsername, pdwLen, pwszDomain, &dwSize, &Snu)) {
          //  BeaconPrintf(CALLBACK_OUTPUT, "[-] LookupAccountSidA() failed (Err: %d),pdwLen: %d,dwSize:%d ", KERNEL32$GetLastError(), *pdwLen, dwSize);
            goto end;
        }
    }
    //---------------------------------------------------------------------------------------------------//

   // internal_printf("\nUserName\t\tSID\n");
   // internal_printf("=========================\t====================================\n");

    // get user sid
    ADVAPI32$ConvertSidToStringSidA(pUserInfo->User.Sid, &pSidStr);

    
    // calc how long '=' need use...
    char* ret  = NULL;
    char* ret2 = NULL;
    char* ret3 = NULL;
    int equal_sign0 = *pdwLen + dwSize + 2;
    if (NULL == (ret = (char*)KERNEL32$LocalAlloc(LPTR, equal_sign0))) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] LocalAlloc() failed (Err: %d) ", KERNEL32$GetLastError());
        goto end;
    }

    if (NULL == (ret3 = (char*)KERNEL32$LocalAlloc(LPTR, equal_sign0  ))) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] LocalAlloc() failed (Err: %d) ", KERNEL32$GetLastError());
        goto end;
    }

    for (size_t i = 0; i < equal_sign0; i++)
    {
        ret[i] = '=';
        ret3[i] = ' ';
    }
    ret[equal_sign0] = '\0';
    ret3[equal_sign0 - 6] = '\0';

    int equal_sign = KERNEL32$lstrlenA(pSidStr) + 1;
    if (NULL == (ret2 = (char*)KERNEL32$LocalAlloc(LPTR, equal_sign + 1))) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] LocalAlloc() failed (Err: %d) ", KERNEL32$GetLastError());
        goto end;
    }
    for (size_t i = 0; i < equal_sign; i++)
    {
        ret2[i] = '=';
    }

    // output
    internal_printf("\nUserName%sSID\n", ret3);
    internal_printf("%s  %s\n", ret, ret2);
    internal_printf("%s\\%s   %s\n\n", pwszDomain, pwszCurrentUsername, pSidStr);

    /* cleanup our allocations */
end:
    if (pwszCurrentUsername) { KERNEL32$LocalFree(pwszCurrentUsername); }
    if (pwszDomain) { KERNEL32$LocalFree(pwszDomain); }
    if (ret) { KERNEL32$LocalFree(ret); }
    if (ret2) { KERNEL32$LocalFree(ret2); }

    if (pSidStr) { KERNEL32$LocalFree(pSidStr); }
    if (pUserInfo) { intFree(pUserInfo); }
    if (pUserStr) { intFree(pUserStr); };

    return retval;
}

int WhoamiGroups(void)
{
    DWORD dwIndex = 0;
    char* pSidStr = NULL;

    char szGroupName[255] = { 0 };
    char szDomainName[255] = { 0 };

    DWORD cchGroupName = _countof(szGroupName);
    DWORD cchDomainName = _countof(szDomainName);

    SID_NAME_USE Use = 0;

    PTOKEN_GROUPS pGroupInfo = (PTOKEN_GROUPS)WhoamiGetTokenInfo(TokenGroups);
    WhoamiTable* GroupTable = NULL;

    if (pGroupInfo == NULL)
    {
        return 1;
    }

    /* the header is the first (0) row, so we start in the second one (1) */


    internal_printf("\n%-50s%-25s%-45s%-25s\n", "GROUP INFORMATION", "Type", "SID", "Attributes");
    internal_printf("================================================= ===================== ============================================= ==================================================\n");

    for (dwIndex = 0; dwIndex < pGroupInfo->GroupCount; dwIndex++)
    {
        if (ADVAPI32$LookupAccountSidA(NULL,
            pGroupInfo->Groups[dwIndex].Sid,
            (LPSTR)&szGroupName,
            &cchGroupName,
            (LPSTR)&szDomainName,
            &cchDomainName,
            &Use) == 0)
        {
            //If we fail lets try to get the next entry
            continue;
        }

        /* the original tool seems to limit the list to these kind of SID items */
        if ((Use == SidTypeWellKnownGroup || Use == SidTypeAlias ||
            Use == SidTypeLabel || Use == SidTypeGroup) && !(pGroupInfo->Groups[dwIndex].Attributes & SE_GROUP_LOGON_ID))
        {
            char tmpBuffer[1024] = { 0 };

            /* looks like windows treats 0x60 as 0x7 for some reason, let's just nod and call it a day:
               0x60 is SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED
               0x07 is SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED */

            if (pGroupInfo->Groups[dwIndex].Attributes == 0x60)
                pGroupInfo->Groups[dwIndex].Attributes = 0x07;

            /* 1- format it as DOMAIN\GROUP if the domain exists, or just GROUP if not */
            MSVCRT$sprintf((char*)&tmpBuffer, "%s%s%s", szDomainName, cchDomainName ? "\\" : "", szGroupName);
            internal_printf("%-50s", tmpBuffer);

            /* 2- let's find out the group type by using a simple lookup table for lack of a better method */
            if (Use == SidTypeWellKnownGroup) {
                internal_printf("%-25s", "Well-known group ");
            }
            else if (Use == SidTypeAlias) {
                internal_printf("%-25s", "Alias ");
            }
            else if (Use == SidTypeLabel) {
                internal_printf("%-25s", "Label ");
            }
            else if (Use == SidTypeGroup) {
                internal_printf("%-25s", "Group ");
            }
            /* 3- turn that SID into text-form */
            if (ADVAPI32$ConvertSidToStringSidA(pGroupInfo->Groups[dwIndex].Sid, &pSidStr)) {

                //WhoamiSetTable(GroupTable, pSidStr, PrintingRow, 2);
                internal_printf("%-45s ", pSidStr);

                KERNEL32$LocalFree(pSidStr);
                pSidStr = NULL;

            }

            /* 4- reuse that buffer for appending the attributes in text-form at the very end */
            ZeroMemory(tmpBuffer, sizeof(tmpBuffer));

            if (pGroupInfo->Groups[dwIndex].Attributes & SE_GROUP_MANDATORY)
                internal_printf("Mandatory group, ");
            if (pGroupInfo->Groups[dwIndex].Attributes & SE_GROUP_ENABLED_BY_DEFAULT)
                internal_printf("Enabled by default, ");
            if (pGroupInfo->Groups[dwIndex].Attributes & SE_GROUP_ENABLED)
                internal_printf("Enabled group, ");
            if (pGroupInfo->Groups[dwIndex].Attributes & SE_GROUP_OWNER)
                internal_printf("Group owner, ");
            internal_printf("\n");
        }
        /* reset the buffers so that we can reuse them */
        ZeroMemory(szGroupName, sizeof(szGroupName));
        ZeroMemory(szDomainName, sizeof(szDomainName));

        cchGroupName = 255;
        cchDomainName = 255;
    }


    /* cleanup our allocations */
    intFree(pGroupInfo);

    return 0;
}

int WhoamiPriv(void)
{
    PTOKEN_PRIVILEGES pPrivInfo = (PTOKEN_PRIVILEGES)WhoamiGetTokenInfo(TokenPrivileges);
    DWORD dwResult = 0, dwIndex = 0;
    WhoamiTable* PrivTable = NULL;

    if (pPrivInfo == NULL)
    {
        return 1;
    }

    internal_printf("\n\n%-45s%-50s%-30s\n", "Privilege Name", "Description", "State");
    internal_printf("=========================================== ================================================= ===========================\n");

    for (dwIndex = 0; dwIndex < pPrivInfo->PrivilegeCount; dwIndex++)
    {
        char* PrivName = NULL;
        WCHAR* wPrivName = NULL;
        char* DispName = NULL;
        WCHAR* wDispName = NULL;

        DWORD PrivNameSize = 0, DispNameSize = 0;
        BOOL ret = FALSE;

        ADVAPI32$LookupPrivilegeNameW(NULL,
            &pPrivInfo->Privileges[dwIndex].Luid,
            NULL,
            &PrivNameSize); // getting size

        wPrivName = intAlloc(++PrivNameSize * sizeof(wchar_t));

        if (wPrivName == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "intAlloc error! ");
        }

        if (ADVAPI32$LookupPrivilegeNameW(NULL,
            &pPrivInfo->Privileges[dwIndex].Luid,
            wPrivName,
            &PrivNameSize) == 0)
        {
            if (wPrivName) { intFree(wPrivName); wPrivName = NULL; }
            continue; // try to get next
        }

        Wchar2Char(&PrivName, wPrivName, Kernel32$GetACP());
        //WhoamiSetTableDyn(PrivTable, PrivName, dwIndex + 1, 0);
        internal_printf("%-45s", PrivName);


        /* try to grab the size of the string, also, beware, as this call is
           unimplemented in ReactOS/Wine at the moment */

       // ADVAPI32$LookupPrivilegeDisplayNameA(NULL, PrivName, NULL, &DispNameSize, &dwResult);

        ADVAPI32$LookupPrivilegeDisplayNameW(NULL, wPrivName,NULL, &DispNameSize, &dwResult);

        //DispName = intAlloc(++DispNameSize);

        wDispName = intAlloc(++DispNameSize * sizeof(wchar_t));

        ret = ADVAPI32$LookupPrivilegeDisplayNameW(NULL, wPrivName, wDispName, &DispNameSize, &dwResult);
       
        Wchar2Char(&DispName, wDispName, Kernel32$GetACP());

        if (ret && DispName)
        {
            internal_printf("%-50s", DispName);
        }
        else
        {
            internal_printf("%-50s", "???");
        }

        if (wPrivName != NULL)
            intFree(wPrivName);

        if (DispName != NULL)
            intFree(DispName);

        if (wDispName != NULL)
            intFree(wDispName);

        if (pPrivInfo->Privileges[dwIndex].Attributes & SE_PRIVILEGE_ENABLED)
            internal_printf("%-30s\n", "Enabled");
        else
            internal_printf("%-30s\n", "Disabled");
    }


    /* cleanup our allocations */
    if (pPrivInfo) { intFree(pPrivInfo); }

    return 0;
}

#ifdef BOF
VOID go(
    IN PCHAR Buffer,
    IN ULONG Length
)
{
    if (!bofstart())
    {
        return;
    }
    (void)WhoamiUser();
    (void)WhoamiGroups();
    (void)WhoamiPriv();
    printoutput(TRUE);
};
#else
int main()
{
    (void)WhoamiUser();
    (void)WhoamiGroups();
    (void)WhoamiPriv();
    return 1;
}

#endif
