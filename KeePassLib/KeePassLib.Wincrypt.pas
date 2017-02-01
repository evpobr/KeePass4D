{   This file is part of KeePass4D.

    KeePass4D is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    KeePass4D is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with KeePass4D.  If not, see <http://www.gnu.org/licenses/>. }

unit KeePassLib.Wincrypt;

{$ALIGN ON}
{$MINENUMSIZE 4}
{$WEAKPACKAGEUNIT}

interface

uses
  Winapi.Windows;

const
  MS_DEF_PROV: PChar = 'Microsoft Base Cryptographic Provider v1.0';
  MS_ENHANCED_PROV: PChar = 'Microsoft Enhanced Cryptographic Provider v1.0';
  MS_STRONG_PROV: PChar = 'Microsoft Strong Cryptographic Provider';
  MS_DEF_RSA_SIG_PROV: PChar = 'Microsoft RSA Signature Cryptographic Provider';
  MS_DEF_RSA_SCHANNEL_PROV: PChar = 'Microsoft RSA SChannel Cryptographic Provider';
  MS_DEF_DSS_PROV: PChar = 'Microsoft Base DSS Cryptographic Provider';
  MS_DEF_DSS_DH_PROV: PChar = 'Microsoft Base DSS and Diffie-Hellman Cryptographic Provider';
  MS_ENH_DSS_DH_PROV: PChar = 'Microsoft Enhanced DSS and Diffie-Hellman Cryptographic Provider';
  MS_DEF_DH_SCHANNEL_PROV: PChar = 'Microsoft DH SChannel Cryptographic Provider';
  MS_SCARD_PROV: PChar = 'Microsoft Base Smart Card Crypto Provider';
  MS_ENH_RSA_AES_PROV: PChar = 'Microsoft Enhanced RSA and AES Cryptographic Provider';

  PROV_RSA_FULL       = 1;
  PROV_RSA_SIG        = 2;
  PROV_DSS            = 3;
  PROV_FORTEZZA       = 4;
  PROV_MS_EXCHANGE    = 5;
  PROV_MS_MAIL        = 5;
  PROV_SSL            = 6;
  PROV_STT_MER        = 7;
  PROV_STT_ACQ        = 8;
  PROV_STT_BRND       = 9;
  PROV_STT_ROOT       = 10;
  PROV_STT_ISS        = 11;
  PROV_RSA_SCHANNEL   = 12;
  PROV_DSS_DH         = 13;
  PROV_EC_ECDSA_SIG   = 14;
  PROV_EC_ECNRA_SIG   = 15;
  PROV_EC_ECDSA_FULL  = 16;
  PROV_EC_ECNRA_FULL  = 17;
  PROV_DH_SCHANNEL    = 18;
  PROV_SPYRUS_LYNKS   = 20;
  PROV_RNG            = 21;
  PROV_INTEL_SEC      = 22;
  PROV_RSA_AES        = 24;

  CRYPT_VERIFYCONTEXT = $F0000000;

  HP_HASHVAL       = $0002;
  HP_HASHSIZE      = $0004;

  KEYSTATEBLOB          = $C;
  OPAQUEKEYBLOB         = $9;
  PLAINTEXTKEYBLOB      = $8;
  PRIVATEKEYBLOB        = $7;
  PUBLICKEYBLOB         = $6;
  PUBLICKEYBLOBEX       = $A;
  SIMPLEBLOB            = $1;
  SYMMETRICWRAPKEYBLOB  = $B;

  CUR_BLOB_VERSION  = 2;

  KP_IV               = $00000001;
  KP_SALT             = $00000002;
  KP_PADDING          = $00000003;
  KP_MODE             = $00000004;
  KP_MODE_BITS        = $00000005;
  KP_PERMISSIONS      = $00000006;
  KP_ALGID            = $00000007;
  KP_BLOCKLEN         = $00000008;
  KP_KEYLEN           = $00000009;
  KP_SALT_EX          = $0000000a;
  KP_P                = $0000000b;
  KP_G                = $0000000c;
  KP_Q                = $0000000d;
  KP_X                = $0000000e;
  KP_Y                = $0000000f;
  KP_RA               = $00000010;
  KP_RB               = $00000011;
  KP_INFO             = $00000012;
  KP_EFFECTIVE_KEYLEN = $00000013;
  KP_SCHANNEL_ALG     = $00000014;
  KP_PUB_PARAMS       = $00000027;

  CRYPT_MODE_CBC      = 1;
  CRYPT_MODE_ECB      = 2;
  CRYPT_MODE_OFB      = 3;
  CRYPT_MODE_CFB      = 4;
  CRYPT_MODE_CTS      = 5;
  CRYPT_MODE_CBCI     = 6;
  CRYPT_MODE_CFBP     = 7;
  CRYPT_MODE_OFBP     = 8;
  CRYPT_MODE_CBCOFM   = 9;
  CRYPT_MODE_CBCOFMI  = 10;

type
  HCRYPTPROV  = THandle;
  HCRYPTKEY   = THandle;
  HCRYPTHASH  = THandle;
  HCERTSTORE  = THandle;

  PCryptUIWizDigitalSighBlobInfo = ^TCryptUIWizDigitalSighBlobInfo;
  CRYPTUI_WIZ_DIGITAL_SIGN_BLOB_INFO = record
    dwSize          : DWORD;
    pGuidSubject    : PGUID;
    cbBlob          : DWORD;
    pbBlob          : Pointer;
    pwszDisplayName : LPCWSTR;
  end;
  TCryptUIWizDigitalSighBlobInfo = CRYPTUI_WIZ_DIGITAL_SIGN_BLOB_INFO;

  _CRYPTOAPI_BLOB = record
    cbData  : DWORD;
    pbData  : Pointer;
  end;
  TCryptoApiBlob = _CRYPTOAPI_BLOB;
  PCryptoApiBlob = ^TCryptoApiBlob;
  TCryptIntegerBlob = TCryptoApiBlob;
  PCryptIntegerBlob = ^TCryptIntegerBlob;
  TCryptUIntBlob = TCryptoApiBlob;
  PCryptUIntBlob = ^TCryptUIntBlob;
  TCryptObjIDBlob = TCryptoApiBlob;
  PCryptObjIDBlob = ^TCryptObjIDBlob;
  TCertNameBlob = TCryptoApiBlob;
  PCertNameBlob = ^TCertNameBlob;
  TCertRdnValueBlob = TCryptoApiBlob;
  PCertRdnValueBlob = ^TCertRdnValueBlob;
  TCertBlob = TCryptoApiBlob;
  PCertBlob = ^TCertBlob;
  TCrlBlob = TCryptoApiBlob;
  TDataBlob = TCryptoApiBlob;
  PDataBlob = ^TDataBlob;
  TCryptDataBlob = TCryptoApiBlob;
  PCryptDataBlob = ^TCryptDataBlob;
  TCryptHashBlob = TCryptoApiBlob;
  PCryptHashBlob = ^TCryptHashBlob;
  TCryptDigestBlob = TCryptoApiBlob;
  PCryptDigestBlob = ^TCryptDigestBlob;
  TCryptDerBlob = TCryptoApiBlob;
  PCryptDerBlob = ^TCryptDerBlob;
  TCryptAttrBlob = TCryptoApiBlob;
  PCryptAttrBlob = ^TCryptAttrBlob;

  PCryptBitBlob = ^TCryptBitBlob;
  CRYPT_BIT_BLOB = record
    cbData      : DWORD;
    pbData      : Pointer;
    cUnusedBits : DWORD;
  end;
  TCryptBitBlob = CRYPT_BIT_BLOB;

  PCertExtension = ^TCertExtension;
  CERT_EXTENSION = record
    pszObjId  : LPSTR;
    fCritical : BOOL;
    Value     : TCryptObjIDBlob;
  end;
  TCertExtension = CERT_EXTENSION;

  PCryptAlgoithmIdentifier = ^TCryptAlgoithmIdentifier;
  CRYPT_ALGORITHM_IDENTIFIER = record
    pszObjId    : LPSTR;
    Parameters  : TCryptObjIDBlob;
  end;
  TCryptAlgoithmIdentifier = CRYPT_ALGORITHM_IDENTIFIER;

  PCertPublicKeyInfo = ^TCertPublicKeyInfo;
  CERT_PUBLIC_KEY_INFO = record
    Algorithm: TCryptAlgoithmIdentifier;
    PublicKey: TCryptBitBlob;
  end;
  TCertPublicKeyInfo = CERT_PUBLIC_KEY_INFO;

  PCertInfo = ^TCertInfo;
  CERT_INFO = record
    dwVersion             : DWORD;
    SerialNumber          : TCryptIntegerBlob;
    SignatureAlgorithm    : TCryptAlgoithmIdentifier;
    Issuer                : TCertNameBlob;
    NotBefore             : TFileTime;
    NotAfter              : TFileTime;
    Subject               : TCertNameBlob;
    SubjectPublicKeyInfo  : TCertPublicKeyInfo;
    IssuerUniqueId        : TCryptBitBlob;
    SubjectUniqueId       : TCryptBitBlob;
    cExtension            : DWORD;
    rgExtension           : PCertExtension;
  end;
  TCertInfo = ^CERT_INFO;

  CERT_CONTEXT = record
    dwCertEncodingType: DWORD;
    pbCertEncoded     : Pointer;
    cbCertEncoded     : DWORD;
    pCertInfo         : PCertInfo;
    hCertStore        : HCERTSTORE;
  end;

  ALG_ID =
  (
    CALG_3DES	                = $00006603,
    CALG_3DES_112	            = $00006609,
    CALG_AES	                = $00006611,
    CALG_AES_128	            = $0000660e,
    CALG_AES_192	            = $0000660f,
    CALG_AES_256	            = $00006610,
    CALG_AGREEDKEY_ANY        =	$0000aa03,
    CALG_CYLINK_MEK	          = $0000660c,
    CALG_DES	                = $00006601,
    CALG_DESX	                = $00006604,
    CALG_DH_EPHEM	            = $0000aa02,
    CALG_DH_SF	              = $0000aa01,
    CALG_DSS_SIGN	            = $00002200,
    CALG_ECDH	                = $0000aa05,
    CALG_ECDH_EPHEM	          = $0000ae06,
    CALG_ECDSA	              = $00002203,
    CALG_ECMQV	              = $0000a001,
    CALG_HASH_REPLACE_OWF	    = $0000800b,
    CALG_HUGHES_MD5	          = $0000a003,
    CALG_HMAC	                = $00008009,
    CALG_KEA_KEYX	            = $0000aa04,
    CALG_MAC	                = $00008005,
    CALG_MD2	                = $00008001,
    CALG_MD4	                = $00008002,
    CALG_MD5	                = $00008003,
    CALG_NO_SIGN	            = $00002000,
    CALG_OID_INFO_CNG_ONLY	  = $ffffffff,
    CALG_OID_INFO_PARAMETERS  =	$fffffffe,
    CALG_PCT1_MASTER	        = $00004c04,
    CALG_RC2                  = $00006602,
    CALG_RC4	                = $00006801,
    CALG_RC5	                = $0000660d,
    CALG_RSA_KEYX             = $0000a400,
    CALG_RSA_SIGN	            = $00002400,
    CALG_SCHANNEL_ENC_KEY	    = $00004c07,
    CALG_SCHANNEL_MAC_KEY	    = $00004c03,
    CALG_SCHANNEL_MASTER_HASH = $00004c02,
    CALG_SEAL                 = $00006802,
    CALG_SHA	                = $00008004,
    CALG_SHA1                 = $00008004,
    CALG_SHA_256              = $0000800c,
    CALG_SHA_384              = $0000800d,
    CALG_SHA_512              = $0000800e,
    CALG_SKIPJACK             = $0000660a,
    CALG_SSL2_MASTER          = $00004c05,
    CALG_SSL3_MASTER          = $00004c01,
    CALG_SSL3_SHAMD5          = $00008008,
    CALG_TEK                  = $0000660b,
    CALG_TLS1_MASTER          = $00004c06
  );
  TAlgID = ALG_ID;

  PPublicKeyStruc = ^TPublicKeyStruc;
  PBlobHeader = ^TBlobHeader;
  PUBLICKEYSTRUC = record
    bType     : Byte;
    bVersion  : Byte;
    reserved  : Word;
    aiKeyAlg  : TAlgID;
  end;
  TPublicKeyStruc = PUBLICKEYSTRUC;
  TBlobHeader     = PUBLICKEYSTRUC;

function CryptAcquireContext(out phProv: HCRYPTPROV; const pszContainer: PWideChar;
  const pszProvider: PWideChar; dwProvType: DWORD; dwFlags: DWORD): BOOL stdcall;
function CryptContextAddRef(hProv: HCRYPTPROV; pdwReserved: PDWORD; dwFlags: DWORD): BOOL; stdcall;
function CryptAcquireContextW(out phProv: HCRYPTPROV; const pszContainer: PWideChar;
  const pszProvider: PWideChar; dwProvType: DWORD; dwFlags: DWORD): BOOL stdcall;
function CryptReleaseContext(phProv: HCRYPTPROV; dwFlags: DWORD): BOOL stdcall;

function CryptCreateHash(phProv: HCRYPTPROV; Algid: ALG_ID; hKey: HCRYPTKEY;
  dwFlags: DWORD; out phHash: HCRYPTHASH): BOOL stdcall;
function CryptDestroyHash(hHash: HCRYPTHASH): BOOL; stdcall;
function CryptDuplicateHash(hHash: HCRYPTHASH; pdwReserved: PDWORD;
  dwFlags: DWORD; out phHash: HCRYPTHASH): BOOL; stdcall;
function CryptGetHashParam(hHash: HCRYPTHASH; dwParam: DWORD;
  out pbData; var pdwDataLen: DWORD; dwFlags: DWORD): BOOL; stdcall;
function CryptHashData(hHash: HCRYPTHASH; const pbData; dwDataLen: DWORD;
  dwFlags: DWORD): BOOL; stdcall;
function CryptHashSessionKey(hHash: HCRYPTHASH; hKey: HCRYPTKEY;
  dwFlags: DWORD): BOOL; stdcall;
function CryptSetHashParam(hHash: HCRYPTHASH; dwParam: DWORD;
  const pbData: Pointer; dwFlags:  DWORD): BOOL; stdcall;
function CryptSignHashW(hHash: HCRYPTHASH; dwKeySpec: DWORD;
  const sDescription: LPCWSTR; dwFlags: DWORD; out pbSignature: Pointer;
  var pdwSigLen: DWORD): BOOL; stdcall;
function CryptVerifySignature(hHash: HCRYPTHASH; pbSignature: Pointer;
  dwSigLen: DWORD; hPubKey: HCRYPTKEY; const sDescription: LPCWSTR;
  dwFlags: DWORD): BOOL; stdcall;
function CryptVerifySignatureW(hHash: HCRYPTHASH; pbSignature: Pointer;
  dwSigLen: DWORD; hPubKey: HCRYPTKEY; const sDescription: LPCWSTR;
  dwFlags: DWORD): BOOL; stdcall;

function CryptImportKey(hProv: HCRYPTPROV; const pbData; dwDataLen: DWORD;
  hPubKey: HCRYPTKEY; dwFlags: DWORD; out phKey: HCRYPTKEY): BOOL; stdcall;
function CryptEncrypt(hKey: HCRYPTKEY; hHash: HCRYPTHASH; &Final: BOOL;
  dwFlags: DWORD; var bData; var dwDataLen: DWORD; dwBufLen: DWORD): BOOL; stdcall;
function CryptDecrypt(hKey: HCRYPTKEY; hHash: HCRYPTHASH; &Final: BOOL; dwFlags: DWORD; var bData; var dwDataLen): BOOL; stdcall;
function CryptGetKeyParam(hKey: HCRYPTKEY; dwParam: DWORD; pdwDataLen: PDWORD; dwFlags: DWORD): BOOL; stdcall;
function CryptSetKeyParam(hKey: HCRYPTKEY; dwParam: DWORD; const [ref] bData;
  dwFlags: DWORD): BOOL; stdcall;
function CryptDuplicateKey(hKey: HCRYPTKEY; pdwReserved: PDWORD; dwFlags: DWORD;
  out phKey: HCRYPTKEY): BOOL; stdcall;
function CryptDestroyKey(hKey: HCRYPTKEY): BOOL; stdcall;

function CryptGenRandom(hProv: HCRYPTPROV; dwLen: DWORD; pbBuffer: Pointer): BOOL; stdcall;

{ dpapi.h }

const

//
// Registry value for controlling Data Protection API (DPAPI) UI settings.
//

  szFORCE_KEY_PROTECTION: PAnsiChar = 'ForceKeyProtection';

  dwFORCE_KEY_PROTECTION_DISABLED     = $0;
  dwFORCE_KEY_PROTECTION_USER_SELECT  = $1;
  dwFORCE_KEY_PROTECTION_HIGH         = $2;

//
// Data protection APIs enable applications to easily secure data.
//
// The base provider provides protection based on the users' logon
// credentials. The data secured with these APIs follow the same
// roaming characteristics as HKCU -- if HKCU roams, the data
// protected by the base provider may roam as well. This makes
// the API ideal for the munging of data stored in the registry.
//

//
// Prompt struct -- what to tell users about the access
//
type
  CRYPTPROTECT_PROMPTSTRUCT = record
    cbSize        : DWORD;
    dwPromptFlags : DWORD;
    hwndApp       : HWND;
    szPrompt      : LPCWSTR;
  end;
  TCryptProtectPromptStruct = CRYPTPROTECT_PROMPTSTRUCT;
  PCryptProtectPromptStruct = ^TCryptProtectPromptStruct;


//
// base provider action
//
//   CRYPTPROTECT_DEFAULT_PROVIDER   { 0xdf9d8cd0, 0x1501, 0x11d1, {0x8c, 0x7a, 0x00, 0xc0, 0x4f, 0xc2, 0x97, 0xeb} }

//
// CryptProtect PromptStruct dwPromtFlags
//
//
// prompt on unprotect
const
  CRYPTPROTECT_PROMPT_ON_UNPROTECT    = $1;  // 1<<0
//
// prompt on protect
  CRYPTPROTECT_PROMPT_ON_PROTECT      = $2;  // 1<<1
  CRYPTPROTECT_PROMPT_RESERVED        = $04; // reserved, do not use.

//
// default to strong variant UI protection (user supplied password currently).
  CRYPTPROTECT_PROMPT_STRONG          = $08; // 1<<3

//
// require strong variant UI protection (user supplied password currently).
  CRYPTPROTECT_PROMPT_REQUIRE_STRONG  = $10; // 1<<4

//
// CryptProtectData and CryptUnprotectData dwFlags
//
// for remote-access situations where ui is not an option
// if UI was specified on protect or unprotect operation, the call
// will fail and GetLastError() will indicate ERROR_PASSWORD_RESTRICTION
  CRYPTPROTECT_UI_FORBIDDEN = $1;

//
// per machine protected data -- any user on machine where CryptProtectData
// took place may CryptUnprotectData
  CRYPTPROTECT_LOCAL_MACHINE  = $4;

//
// force credential synchronize during CryptProtectData()
// Synchronize is only operation that occurs during this operation
  CRYPTPROTECT_CRED_SYNC  = $8;

//
// Generate an Audit on protect and unprotect operations
//
  CRYPTPROTECT_AUDIT  = $10;

//
// Protect data with a non-recoverable key
//
  CRYPTPROTECT_NO_RECOVERY  = $20;


//
// Verify the protection of a protected blob
//
  CRYPTPROTECT_VERIFY_PROTECTION  = $40;

//
// Regenerate the local machine protection
//
  CRYPTPROTECT_CRED_REGENERATE  = $80;

// flags reserved for system use
  CRYPTPROTECT_FIRST_RESERVED_FLAGVAL = $0FFFFFFF;
  CRYPTPROTECT_LAST_RESERVED_FLAGVAL  = $FFFFFFFF;

//
// flags specific to base provider
//


function CryptProtectData(pDataIn: PDataBlob; const szDataDescr: LPCWSTR;
  pOptionalEntropy: PDataBlob; pvReserved: PVOID;
  pPromptStruct: PCryptProtectPromptStruct; dwFlags: DWORD;
  pDataOut: PDataBlob): BOOL; stdcall;

function CryptUnprotectData(pDataIn: PDataBlob; const szDataDescr: LPCWSTR;
  pOptionalEntropy: PDataBlob; pvReserved: PVOID;
  pPromptStruct: PCryptProtectPromptStruct; dwFlags: DWORD;
  pDataOut: PDataBlob): BOOL; stdcall;

implementation

const
  advapi32  = 'Advapi32.dll';
  crypt32   = 'Crypt32.dll';

function CryptAcquireContext; external advapi32 name 'CryptAcquireContextW';
function CryptAcquireContextW; external advapi32;
function CryptContextAddRef; external advapi32;
function CryptReleaseContext; external advapi32;

function CryptCreateHash; external advapi32;
function CryptDestroyHash; external advapi32;
function CryptDuplicateHash; external advapi32;
function CryptGetHashParam; external advapi32;
function CryptHashData; external advapi32;
function CryptHashSessionKey; external advapi32;
function CryptSetHashParam; external advapi32;
function CryptSignHashW; external advapi32;
function CryptVerifySignature; external advapi32 name 'CryptVerifySignatureW';
function CryptVerifySignatureW; external advapi32;

function CryptImportKey; external advapi32;
function CryptEncrypt; external advapi32;
function CryptDecrypt; external advapi32;
function CryptGetKeyParam; external advapi32;
function CryptSetKeyParam; external advapi32;
function CryptDuplicateKey; external advapi32;
function CryptDestroyKey; external advapi32;
function CryptGenRandom; external advapi32;

function CryptProtectData; external crypt32;
function CryptUnprotectData; external crypt32;

end.
