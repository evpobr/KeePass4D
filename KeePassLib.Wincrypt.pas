unit KeePassLib.Wincrypt;

{$ALIGN ON}
{$MINENUMSIZE 4}
{$WEAKPACKAGEUNIT}

interface

uses
  Winapi.Windows;

const
  PROV_RSA_AES = 24;

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

implementation

const
  advapi32 = 'Advapi32.dll';

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

end.
