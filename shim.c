/* Copyright (C) 2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include <windows.h>
#include <wintrust.h>

/*
 * HKLM\SOFTWARE\Microsoft\Cryptography\Providers\Trust\FinalPolicy\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\$DLL
 */

typedef DWORD(DRIVER_FINAL_POLICY_FN)(CRYPT_PROVIDER_DATA *);
typedef DRIVER_FINAL_POLICY_FN *PDRIVER_FINAL_POLICY_FN;

DRIVER_FINAL_POLICY_FN DriverFinalPolicy;

DWORD
DriverFinalPolicy(CRYPT_PROVIDER_DATA *ProvData)
{
    DWORD OriginalLastError = GetLastError();
    HMODULE WintrustModule = GetModuleHandleA("WINTRUST.DLL");
    if (!WintrustModule)
        return ERROR_INVALID_LIBRARY;
    PDRIVER_FINAL_POLICY_FN RealDriverFinalPolicy =
        (PDRIVER_FINAL_POLICY_FN)GetProcAddress(WintrustModule, "DriverFinalPolicy");
    if (!RealDriverFinalPolicy)
        return ERROR_INVALID_FUNCTION;
    DWORD Ret = RealDriverFinalPolicy(ProvData);
    if (Ret == ERROR_APP_WRONG_OS)
    {
        Ret = ERROR_SUCCESS;
        SetLastError(OriginalLastError);
    }
    return Ret;
}

