/* ============================================================================
 *  signature.c  --  weryfikacja podpisu cyfrowego przez WinVerifyTrust
 * ----------------------------------------------------------------------------
 *  Używa API WinTrust (Authenticode) - tego samego mechanizmu, którym Windows
 *  weryfikuje podpisy plików wykonywalnych. To kryterium forensyczne:
 *  "czy ten plik jest tym, za co się podaje, i kto za niego ręczy?".
 * ==========================================================================*/
#include "signature.h"
#include <stdio.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>

void dw_extract_exe_path(const TCHAR* raw, TCHAR* out, size_t out_len) {
    out[0] = _T('\0');
    if (!raw) return;

    const TCHAR* p = raw;
    while (*p == _T(' ') || *p == _T('\t')) ++p;   /* skip leading space */

    if (*p == _T('"')) {
        /* ścieżka w cudzysłowie: bierz do zamykającego " */
        ++p;
        size_t i = 0;
        while (*p && *p != _T('"') && i < out_len - 1) out[i++] = *p++;
        out[i] = _T('\0');
        return;
    }

    /* bez cudzysłowu: bierz do pierwszego " .exe" + ewentualny argument.
     * Heurystyka: kopiuj aż trafisz na " -" lub " /" (początek argumentu),
     * albo do końca. Następnie utnij po ".exe" jeśli jest. */
    size_t i = 0;
    while (*p && i < out_len - 1) {
        if (*p == _T(' ') && (*(p+1) == _T('-') || *(p+1) == _T('/'))) break;
        out[i++] = *p++;
    }
    out[i] = _T('\0');

    /* utnij po ".exe" gdy w środku są jeszcze spacje+argumenty bez myślnika */
    TCHAR* ext = _tcsstr(out, _T(".exe"));
    if (ext) {
        ext += 4;
        /* jeśli zaraz po .exe jest spacja a potem coś, utnij */
        if (*ext == _T(' ')) *ext = _T('\0');
    }
}

DwSigStatus dw_check_signature(const TCHAR* path_with_args) {
    TCHAR exePath[MAX_PATH];
    dw_extract_exe_path(path_with_args, exePath, MAX_PATH);
    if (exePath[0] == _T('\0')) return DW_SIG_ERROR;

    /* rozwiń zmienne typu %windir% */
    TCHAR expanded[MAX_PATH];
    if (ExpandEnvironmentStrings(exePath, expanded, MAX_PATH) > 0)
        _tcsncpy(exePath, expanded, MAX_PATH - 1);

    if (GetFileAttributes(exePath) == INVALID_FILE_ATTRIBUTES)
        return DW_SIG_ERROR;   /* pliku nie ma / brak dostępu */

    WINTRUST_FILE_INFO fileInfo;
    memset(&fileInfo, 0, sizeof(fileInfo));
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = exePath;
    fileInfo.hFile = NULL;
    fileInfo.pgKnownSubject = NULL;

    GUID actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA winTrustData;
    memset(&winTrustData, 0, sizeof(winTrustData));
    winTrustData.cbStruct            = sizeof(winTrustData);
    winTrustData.dwUIChoice          = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice       = WTD_CHOICE_FILE;
    winTrustData.dwStateAction       = WTD_STATEACTION_VERIFY;
    winTrustData.dwProvFlags         = WTD_SAFER_FLAG;
    winTrustData.pFile               = &fileInfo;

    LONG status = WinVerifyTrust(NULL, &actionGuid, &winTrustData);

    /* sprzątanie stanu */
    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &actionGuid, &winTrustData);

    switch (status) {
    case ERROR_SUCCESS:
        return DW_SIG_TRUSTED;
    case TRUST_E_NOSIGNATURE:
        return DW_SIG_UNSIGNED;
    case TRUST_E_EXPLICIT_DISTRUST:
    case CERT_E_UNTRUSTEDROOT:
    case CERT_E_EXPIRED:
    case TRUST_E_SUBJECT_NOT_TRUSTED:
        return DW_SIG_UNTRUSTED;
    default:
        /* TRUST_E_BAD_DIGEST itp. -> traktuj jako niezaufane */
        return DW_SIG_UNTRUSTED;
    }
}

BOOL dw_get_signer_name(const TCHAR* exe_path, TCHAR* out, DWORD out_len) {
    out[0] = _T('\0');

    DWORD encoding = 0, contentType = 0, formatType = 0;
    HCERTSTORE hStore = NULL;
    HCRYPTMSG  hMsg   = NULL;

    BOOL ok = CryptQueryObject(
        CERT_QUERY_OBJECT_FILE, exe_path,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY, 0,
        &encoding, &contentType, &formatType,
        &hStore, &hMsg, NULL);
    if (!ok || !hMsg || !hStore) {
        if (hMsg) CryptMsgClose(hMsg);
        if (hStore) CertCloseStore(hStore, 0);
        return FALSE;
    }

    /* pobierz info o podpisującym */
    DWORD signerInfoSize = 0;
    CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &signerInfoSize);
    if (signerInfoSize == 0) {
        CryptMsgClose(hMsg); CertCloseStore(hStore, 0); return FALSE;
    }

    PCMSG_SIGNER_INFO pSignerInfo = (PCMSG_SIGNER_INFO)malloc(signerInfoSize);
    if (!pSignerInfo) {
        CryptMsgClose(hMsg); CertCloseStore(hStore, 0); return FALSE;
    }

    BOOL got = FALSE;
    if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0,
                         pSignerInfo, &signerInfoSize)) {
        CERT_INFO certInfo;
        certInfo.Issuer       = pSignerInfo->Issuer;
        certInfo.SerialNumber = pSignerInfo->SerialNumber;

        PCCERT_CONTEXT pCert = CertFindCertificateInStore(
            hStore, encoding, 0, CERT_FIND_SUBJECT_CERT,
            &certInfo, NULL);
        if (pCert) {
            DWORD n = CertGetNameString(
                pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);
            if (n > 1 && n <= out_len) {
                CertGetNameString(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                  0, NULL, out, n);
                got = TRUE;
            }
            CertFreeCertificateContext(pCert);
        }
    }

    free(pSignerInfo);
    CryptMsgClose(hMsg);
    CertCloseStore(hStore, 0);
    return got;
}

const TCHAR* dw_sig_label(DwSigStatus s) {
    switch (s) {
    case DW_SIG_TRUSTED:   return _T("SIGNED/trusted");
    case DW_SIG_UNSIGNED:  return _T("UNSIGNED");
    case DW_SIG_UNTRUSTED: return _T("UNTRUSTED-SIG");
    default:               return _T("sig-error");
    }
}
