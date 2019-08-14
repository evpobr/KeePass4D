{ This file is part of KeePass4D.

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

//
// Algorithm IDs and Flags
//

// ALG_ID crackers
function GetAlgClass(x: DWORD): DWORD; inline;
function GetAlgType(x: DWORD): DWORD; inline;
function GetAlgSid(x: DWORD): DWORD; inline;

const
  // Algorithm classes
  // certenrolld_begin -- ALG_CLASS_*
  ALG_CLASS_ANY = 0;
  ALG_CLASS_SIGNATURE = 1 shl 13;
  ALG_CLASS_MSG_ENCRYPT = 2 shl 13;
  ALG_CLASS_DATA_ENCRYPT = 3 shl 13;
  ALG_CLASS_HASH = 4 shl 13;
  ALG_CLASS_KEY_EXCHANGE = 5 shl 13;
  ALG_CLASS_ALL = 7 shl 13;
  // certenrolld_end

  // Algorithm types
  ALG_TYPE_ANY = 0;
  ALG_TYPE_DSS = 1 shl 9;
  ALG_TYPE_RSA = 2 shl 9;
  ALG_TYPE_BLOCK = 3 shl 9;
  ALG_TYPE_STREAM = 4 shl 9;
  ALG_TYPE_DH = 5 shl 9;
  ALG_TYPE_SECURECHANNEL = 6 shl 9;

  // Generic sub-ids
  ALG_SID_ANY = 0;

  // Some RSA sub-ids
  ALG_SID_RSA_ANY = 0;
  ALG_SID_RSA_PKCS = 1;
  ALG_SID_RSA_MSATWORK = 2;
  ALG_SID_RSA_ENTRUST = 3;
  ALG_SID_RSA_PGP = 4;

  // Some DSS sub-ids
  //
  ALG_SID_DSS_ANY = 0;
  ALG_SID_DSS_PKCS = 1;
  ALG_SID_DSS_DMS = 2;
  // #if (NTDDI_VERSION >= NTDDI_VISTA)
  ALG_SID_ECDSA = 3;
  // #endif //(NTDDI_VERSION >= NTDDI_VISTA)

  // Block cipher sub ids
  // DES sub_ids
  ALG_SID_DES = 1;
  ALG_SID_3DES = 3;
  ALG_SID_DESX = 4;
  ALG_SID_IDEA = 5;
  ALG_SID_CAST = 6;
  ALG_SID_SAFERSK64 = 7;
  ALG_SID_SAFERSK128 = 8;
  ALG_SID_3DES_112 = 9;
  ALG_SID_CYLINK_MEK = 12;
  ALG_SID_RC5 = 13;
  // #if (NTDDI_VERSION >= NTDDI_WINXP)
  ALG_SID_AES_128 = 14;
  ALG_SID_AES_192 = 15;
  ALG_SID_AES_256 = 16;
  ALG_SID_AES = 17;
  // (NTDDI_VERSION >= NTDDI_WINXP)

  // Fortezza sub-ids
  ALG_SID_SKIPJACK = 10;
  ALG_SID_TEK = 11;

  // KP_MODE
  CRYPT_MODE_CBCI = 6; // ANSI CBC Interleaved
  CRYPT_MODE_CFBP = 7; // ANSI CFB Pipelined
  CRYPT_MODE_OFBP = 8; // ANSI OFB Pipelined
  CRYPT_MODE_CBCOFM = 9; // ANSI CBC + OF Masking
  CRYPT_MODE_CBCOFMI = 10; // ANSI CBC + OFM Interleaved

  // RC2 sub-ids
  ALG_SID_RC2 = 2;

  // Stream cipher sub-ids
  ALG_SID_RC4 = 1;
  ALG_SID_SEAL = 2;

  // Diffie-Hellman sub-ids
  ALG_SID_DH_SANDF = 1;
  ALG_SID_DH_EPHEM = 2;
  ALG_SID_AGREED_KEY_ANY = 3;
  ALG_SID_KEA = 4;
  // #if (NTDDI_VERSION >= NTDDI_VISTA)
  ALG_SID_ECDH = 5;
  // (NTDDI_VERSION >= NTDDI_VISTA)

  // Hash sub ids
  ALG_SID_MD2 = 1;
  ALG_SID_MD4 = 2;
  ALG_SID_MD5 = 3;
  ALG_SID_SHA = 4;
  ALG_SID_SHA1 = 4;
  ALG_SID_MAC = 5;
  ALG_SID_RIPEMD = 6;
  ALG_SID_RIPEMD160 = 7;
  ALG_SID_SSL3SHAMD5 = 8;
  ALG_SID_HMAC = 9;
  ALG_SID_TLS1PRF = 10;
  // #if (NTDDI_VERSION >= NTDDI_WINXP)
  ALG_SID_HASH_REPLACE_OWF = 11;
  // #endif //(NTDDI_VERSION >= NTDDI_WINXP)
  // #if (NTDDI_VERSION > NTDDI_WINXPSP2)
  ALG_SID_SHA_256 = 12;
  ALG_SID_SHA_384 = 13;
  ALG_SID_SHA_512 = 14;
  // #endif //(NTDDI_VERSION > NTDDI_WINXPSP2)

  // secure channel sub ids
  ALG_SID_SSL3_MASTER = 1;
  ALG_SID_SCHANNEL_MASTER_HASH = 2;
  ALG_SID_SCHANNEL_MAC_KEY = 3;
  ALG_SID_PCT1_MASTER = 4;
  ALG_SID_SSL2_MASTER = 5;
  ALG_SID_TLS1_MASTER = 6;
  ALG_SID_SCHANNEL_ENC_KEY = 7;

  // #if (NTDDI_VERSION >= NTDDI_VISTA)
  // misc ECC sub ids
  ALG_SID_ECMQV = 1;
  // #endif //(NTDDI_VERSION >= NTDDI_VISTA)

  // Our silly example sub-id
  ALG_SID_EXAMPLE = 80;

type
  // certenrolls_begin -- PROV_ENUMALGS_EX
  ALG_ID = UINT;
  TAlgID = ALG_ID;
  // certenrolls_end

const
  // algorithm identifier definitions
  CALG_MD2 = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_MD2;
  CALG_MD4 = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_MD4;
  CALG_MD5 = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_MD5;
  CALG_SHA = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_SHA;
  CALG_SHA1 = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_SHA1;
  CALG_MAC = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_MAC;
  // Deprecated. Don't use.
  CALG_RSA_SIGN = ALG_CLASS_SIGNATURE or ALG_TYPE_RSA or ALG_SID_RSA_ANY;
  CALG_DSS_SIGN = ALG_CLASS_SIGNATURE or ALG_TYPE_DSS or ALG_SID_DSS_ANY;
  // #if (NTDDI_VERSION >= NTDDI_WINXP)
  CALG_NO_SIGN = ALG_CLASS_SIGNATURE or ALG_TYPE_ANY or ALG_SID_ANY;
  // #endif //(NTDDI_VERSION >= NTDDI_WINXP)
  CALG_RSA_KEYX = ALG_CLASS_KEY_EXCHANGE or ALG_TYPE_RSA or ALG_SID_RSA_ANY;
  CALG_DES = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_DES;
  CALG_3DES_112 = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_3DES_112;
  CALG_3DES = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_3DES;
  CALG_DESX = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_DESX;
  CALG_RC2 = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_RC2;
  CALG_RC4 = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_STREAM or ALG_SID_RC4;
  CALG_SEAL = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_STREAM or ALG_SID_SEAL;
  CALG_DH_SF = ALG_CLASS_KEY_EXCHANGE or ALG_TYPE_DH or ALG_SID_DH_SANDF;
  CALG_DH_EPHEM = ALG_CLASS_KEY_EXCHANGE or ALG_TYPE_DH or ALG_SID_DH_EPHEM;
  CALG_AGREEDKEY_ANY = ALG_CLASS_KEY_EXCHANGE or ALG_TYPE_DH or
    ALG_SID_AGREED_KEY_ANY;
  CALG_KEA_KEYX = ALG_CLASS_KEY_EXCHANGE or ALG_TYPE_DH or ALG_SID_KEA;
  CALG_HUGHES_MD5 = ALG_CLASS_KEY_EXCHANGE or ALG_TYPE_ANY or ALG_SID_MD5;
  CALG_SKIPJACK = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_SKIPJACK;
  CALG_TEK = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_TEK;
  CALG_CYLINK_MEK = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or
    ALG_SID_CYLINK_MEK; // Deprecated. Do not use
  CALG_SSL3_SHAMD5 = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_SSL3SHAMD5;
  CALG_SSL3_MASTER = ALG_CLASS_MSG_ENCRYPT or ALG_TYPE_SECURECHANNEL or
    ALG_SID_SSL3_MASTER;
  CALG_SCHANNEL_MASTER_HASH = ALG_CLASS_MSG_ENCRYPT or ALG_TYPE_SECURECHANNEL or
    ALG_SID_SCHANNEL_MASTER_HASH;
  CALG_SCHANNEL_MAC_KEY = ALG_CLASS_MSG_ENCRYPT or ALG_TYPE_SECURECHANNEL or
    ALG_SID_SCHANNEL_MAC_KEY;
  CALG_SCHANNEL_ENC_KEY = ALG_CLASS_MSG_ENCRYPT or ALG_TYPE_SECURECHANNEL or
    ALG_SID_SCHANNEL_ENC_KEY;
  CALG_PCT1_MASTER = ALG_CLASS_MSG_ENCRYPT or ALG_TYPE_SECURECHANNEL or
    ALG_SID_PCT1_MASTER;
  CALG_SSL2_MASTER = ALG_CLASS_MSG_ENCRYPT or ALG_TYPE_SECURECHANNEL or
    ALG_SID_SSL2_MASTER;
  CALG_TLS1_MASTER = ALG_CLASS_MSG_ENCRYPT or ALG_TYPE_SECURECHANNEL or
    ALG_SID_TLS1_MASTER;
  CALG_RC5 = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_RC5;
  CALG_HMAC = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_HMAC;
  CALG_TLS1PRF = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_TLS1PRF;
  // #if (NTDDI_VERSION >= NTDDI_WINXP)
  CALG_HASH_REPLACE_OWF = ALG_CLASS_HASH or ALG_TYPE_ANY or
    ALG_SID_HASH_REPLACE_OWF;
  CALG_AES_128 = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_AES_128;
  CALG_AES_192 = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_AES_192;
  CALG_AES_256 = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_AES_256;
  CALG_AES = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_AES;
  // #endif //(NTDDI_VERSION >= NTDDI_WINXP)
  // #if (NTDDI_VERSION > NTDDI_WINXPSP2)
  CALG_SHA_256 = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_SHA_256;
  CALG_SHA_384 = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_SHA_384;
  CALG_SHA_512 = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_SHA_512;
  // #endif //(NTDDI_VERSION > NTDDI_WINXPSP2)
  // #if (NTDDI_VERSION >= NTDDI_VISTA)
  CALG_ECDH = ALG_CLASS_KEY_EXCHANGE or ALG_TYPE_DH or ALG_SID_ECDH;
  CALG_ECMQV = ALG_CLASS_KEY_EXCHANGE or ALG_TYPE_ANY or ALG_SID_ECMQV;
  CALG_ECDSA = ALG_CLASS_SIGNATURE or ALG_TYPE_DSS or ALG_SID_ECDSA;
  // #endif //(NTDDI_VERSION >= NTDDI_VISTA)

  // #if (NTDDI_VERSION < NTDDI_WINXP)
  // resource number for signatures in the CSP
  SIGNATURE_RESOURCE_NUMBER = $29A;

type
  VTableProvStruc = record
    Version: DWORD;
    FuncVerifyImage: FARPROC;
    FuncReturnhWnd: FARPROC;
    dwProvType: DWORD;
    pbContextInfo: PBYTE;
    cbContextInfo: DWORD;
    pszProvName: LPSTR;
  end;

  PVTableProvStruc = ^VTableProvStruc;
  TVTableProvStruc = VTableProvStruc;
  // #endif //(NTDDI_VERSION < NTDDI_WINXP)

  // Used for certenroll.idl:
  // certenrolls_begin -- HCRYPT*
  // #ifndef HCRYPTPROV_DEFINED
  // #define HCRYPTPROV_DEFINED
  HCRYPTPROV = ULONG_PTR;
  HCRYPTKEY = ULONG_PTR;
  HCRYPTHASH = ULONG_PTR;
  // #endif
  // certenrolls_end

const
  // dwFlags definitions for CryptAcquireContext
  CRYPT_VERIFYCONTEXT = $F0000000;
  CRYPT_NEWKEYSET = $00000008;
  CRYPT_DELETEKEYSET = $00000010;
  CRYPT_MACHINE_KEYSET = $00000020;
  CRYPT_SILENT = $00000040;
  // #if (NTDDI_VERSION >= NTDDI_VISTA)
  CRYPT_DEFAULT_CONTAINER_OPTIONAL = $00000080;
  // #endif //(NTDDI_VERSION >= NTDDI_VISTA)

  // dwFlag definitions for CryptGenKey
  CRYPT_EXPORTABLE = $00000001;
  CRYPT_USER_PROTECTED = $00000002;
  CRYPT_CREATE_SALT = $00000004;
  CRYPT_UPDATE_KEY = $00000008;
  CRYPT_NO_SALT = $00000010;
  CRYPT_PREGEN = $00000040;
  CRYPT_RECIPIENT = $00000010;
  CRYPT_INITIATOR = $00000040;
  CRYPT_ONLINE = $00000080;
  CRYPT_SF = $00000100;
  CRYPT_CREATE_IV = $00000200;
  CRYPT_KEK = $00000400;
  CRYPT_DATA_KEY = $00000800;
  CRYPT_VOLATILE = $00001000;
  CRYPT_SGCKEY = $00002000;
  // PKCS12_ALLOW_OVERWRITE_KEY 0x00004000
  // PKCS12_NO_PERSIST_KEY 0x00008000
  // should use other than these two
  CRYPT_USER_PROTECTED_STRONG = $00100000;
  // #if (NTDDI_VERSION >= NTDDI_WINXP)
  CRYPT_ARCHIVABLE = $00004000;
  // #endif //(NTDDI_VERSION >= NTDDI_WINXP)
  // #if (NTDDI_VERSION >= NTDDI_VISTA)
  CRYPT_FORCE_KEY_PROTECTION_HIGH = $00008000;
  // #endif //(NTDDI_VERSION >= NTDDI_VISTA)

  RSA1024BIT_KEY = $04000000;

  // dwFlags definitions for CryptDeriveKey
  CRYPT_SERVER = $00000400;

  KEY_LENGTH_MASK = $FFFF0000;

  // dwFlag definitions for CryptExportKey
  CRYPT_Y_ONLY = $00000001;
  CRYPT_SSL2_FALLBACK = $00000002;
  CRYPT_DESTROYKEY = $00000004;
  CRYPT_OAEP = $00000040; // used with RSA encryptions/decryptions
  // CryptExportKey, CryptImportKey,
  // CryptEncrypt and CryptDecrypt

  CRYPT_BLOB_VER3 = $00000080; // export version 3 of a blob type
  // #if (NTDDI_VERSION >= NTDDI_WINXP)
  CRYPT_IPSEC_HMAC_KEY = $00000100; // CryptImportKey only
  // #endif //(NTDDI_VERSION >= NTDDI_WINXP)

  // #if (NTDDI_VERSION >= NTDDI_WS03)
  // dwFlags definitions for CryptDecrypt
  // See also CRYPT_OAEP, above.
  // Note, the following flag is not supported for CryptEncrypt
  CRYPT_DECRYPT_RSA_NO_PADDING_CHECK = $00000020;
  // #endif //(NTDDI_VERSION >= NTDDI_WS03)

  // dwFlags definitions for CryptCreateHash
  CRYPT_SECRETDIGEST = $00000001;

  // #if (NTDDI_VERSION >= NTDDI_WINXP)
  // dwFlags definitions for CryptHashData
  CRYPT_OWF_REPL_LM_HASH = $00000001;
  // this is only for the OWF replacement CSP
  // #endif //(NTDDI_VERSION >= NTDDI_WINXP)

  // dwFlags definitions for CryptHashSessionKey
  CRYPT_LITTLE_ENDIAN = $00000001;

  // dwFlags definitions for CryptSignHash and CryptVerifySignature
  CRYPT_NOHASHOID = $00000001;
  CRYPT_TYPE2_FORMAT = $00000002; // Not supported
  CRYPT_X931_FORMAT = $00000004; // Not supported

  // dwFlag definitions for CryptSetProviderEx and CryptGetDefaultProvider
  CRYPT_MACHINE_DEFAULT = $00000001;
  CRYPT_USER_DEFAULT = $00000002;
  CRYPT_DELETE_DEFAULT = $00000004;

  // exported key blob definitions
  // certenrolld_begin -- *BLOB
  SIMPLEBLOB = $1;
  PUBLICKEYBLOB = $6;
  PRIVATEKEYBLOB = $7;
  PLAINTEXTKEYBLOB = $8;
  OPAQUEKEYBLOB = $9;
  PUBLICKEYBLOBEX = $A;
  SYMMETRICWRAPKEYBLOB = $B;
  // #if (NTDDI_VERSION >= NTDDI_WS03)
  KEYSTATEBLOB = $C;
  // #endif //(NTDDI_VERSION >= NTDDI_WS03)
  // certenrolld_end

  // certenrolld_begin -- AT_*
  AT_KEYEXCHANGE = 1;
  AT_SIGNATURE = 2;
  // certenrolld_end

  CRYPT_USERDATA = 1;

  // dwParam
  KP_IV = 1; // Initialization vector
  KP_SALT = 2; // Salt value
  KP_PADDING = 3; // Padding values
  KP_MODE = 4; // Mode of the cipher
  KP_MODE_BITS = 5; // Number of bits to feedback
  KP_PERMISSIONS = 6; // Key permissions DWORD
  KP_ALGID = 7; // Key algorithm
  KP_BLOCKLEN = 8; // Block size of the cipher
  KP_KEYLEN = 9; // Length of key in bits
  KP_SALT_EX = 10; // Length of salt in bytes
  KP_P = 11; // DSS/Diffie-Hellman P value
  KP_G = 12; // DSS/Diffie-Hellman G value
  KP_Q = 13; // DSS Q value
  KP_X = 14; // Diffie-Hellman X value
  KP_Y = 15; // Y value
  KP_RA = 16; // Fortezza RA value
  KP_RB = 17; // Fortezza RB value
  KP_INFO = 18; // for putting information into an RSA envelope
  KP_EFFECTIVE_KEYLEN = 19; // setting and getting RC2 effective key length
  KP_SCHANNEL_ALG = 20; // for setting the Secure Channel algorithms
  KP_CLIENT_RANDOM = 21; // for setting the Secure Channel client random data
  KP_SERVER_RANDOM = 22; // for setting the Secure Channel server random data
  KP_RP = 23;
  KP_PRECOMP_MD5 = 24;
  KP_PRECOMP_SHA = 25;
  KP_CERTIFICATE = 26; // for setting Secure Channel certificate data (PCT1)
  KP_CLEAR_KEY = 27; // for setting Secure Channel clear key data (PCT1)
  KP_PUB_EX_LEN = 28;
  KP_PUB_EX_VAL = 29;
  KP_KEYVAL = 30;
  KP_ADMIN_PIN = 31;
  KP_KEYEXCHANGE_PIN = 32;
  KP_SIGNATURE_PIN = 33;
  KP_PREHASH = 34;
  // #if (NTDDI_VERSION >= NTDDI_WS03)
  KP_ROUNDS = 35;
  // #endif //(NTDDI_VERSION >= NTDDI_WS03)
  KP_OAEP_PARAMS = 36; // for setting OAEP params on RSA keys
  KP_CMS_KEY_INFO = 37;
  KP_CMS_DH_KEY_INFO = 38;
  KP_PUB_PARAMS = 39; // for setting public parameters
  KP_VERIFY_PARAMS = 40; // for verifying DSA and DH parameters
  KP_HIGHEST_VERSION = 41; // for TLS protocol version setting
  // #if (NTDDI_VERSION >= NTDDI_WS03)
  KP_GET_USE_COUNT = 42; // for use with PP_CRYPT_COUNT_KEY_USE contexts
  // #endif //(NTDDI_VERSION >= NTDDI_WS03)
  KP_PIN_ID = 43;
  KP_PIN_INFO = 44;

  // KP_PADDING
  PKCS5_PADDING = 1; // PKCS 5 (sec 6.2) padding method
  RANDOM_PADDING = 2;
  ZERO_PADDING = 3;

  // KP_MODE
  CRYPT_MODE_CBC = 1; // Cipher block chaining
  CRYPT_MODE_ECB = 2; // Electronic code book
  CRYPT_MODE_OFB = 3; // Output feedback mode
  CRYPT_MODE_CFB = 4; // Cipher feedback mode
  CRYPT_MODE_CTS = 5; // Ciphertext stealing mode

  // KP_PERMISSIONS
  CRYPT_ENCRYPT = $0001; // Allow encryption
  CRYPT_DECRYPT = $0002; // Allow decryption
  CRYPT_EXPORT = $0004; // Allow key to be exported
  CRYPT_READ = $0008; // Allow parameters to be read
  CRYPT_WRITE = $0010; // Allow parameters to be set
  CRYPT_MAC = $0020; // Allow MACs to be used with key
  CRYPT_EXPORT_KEY = $0040; // Allow key to be used for exporting keys
  CRYPT_IMPORT_KEY = $0080; // Allow key to be used for importing keys
  // #if (NTDDI_VERSION >= NTDDI_WINXP)
  CRYPT_ARCHIVE = $0100; // Allow key to be exported at creation only
  // #endif //(NTDDI_VERSION >= NTDDI_WINXP)

  HP_ALGID = $0001; // Hash algorithm
  HP_HASHVAL = $0002; // Hash value
  HP_HASHSIZE = $0004; // Hash value size
  HP_HMAC_INFO = $0005; // information for creating an HMAC
  HP_TLS1PRF_LABEL = $0006; // label for TLS1 PRF
  HP_TLS1PRF_SEED = $0007; // seed for TLS1 PRF

  CRYPT_FAILED = BOOL(FALSE);
  CRYPT_SUCCEED = BOOL(TRUE);

function RCrypt_Succeeded(rt: BOOL): Boolean; inline;
function RCrypt_Failed(rt: BOOL): Boolean; inline;

const
  //
  // CryptGetProvParam
  //
  PP_ENUMALGS = 1;
  PP_ENUMCONTAINERS = 2;
  PP_IMPTYPE = 3;
  PP_NAME = 4;
  PP_VERSION = 5;
  PP_CONTAINER = 6;
  PP_CHANGE_PASSWORD = 7;
  PP_KEYSET_SEC_DESCR = 8; // get/set security descriptor of keyset
  PP_CERTCHAIN = 9; // for retrieving certificates from tokens
  PP_KEY_TYPE_SUBTYPE = 10;
  PP_PROVTYPE = 16;
  PP_KEYSTORAGE = 17;
  PP_APPLI_CERT = 18;
  PP_SYM_KEYSIZE = 19;
  PP_SESSION_KEYSIZE = 20;
  PP_UI_PROMPT = 21;
  PP_ENUMALGS_EX = 22;
  PP_ENUMMANDROOTS = 25;
  PP_ENUMELECTROOTS = 26;
  PP_KEYSET_TYPE = 27;
  PP_ADMIN_PIN = 31;
  PP_KEYEXCHANGE_PIN = 32;
  PP_SIGNATURE_PIN = 33;
  PP_SIG_KEYSIZE_INC = 34;
  PP_KEYX_KEYSIZE_INC = 35;
  PP_UNIQUE_CONTAINER = 36;
  PP_SGC_INFO = 37;
  PP_USE_HARDWARE_RNG = 38;
  PP_KEYSPEC = 39;
  PP_ENUMEX_SIGNING_PROT = 40;
  // #if (NTDDI_VERSION >= NTDDI_WS03)
  PP_CRYPT_COUNT_KEY_USE = 41;
  // #endif //(NTDDI_VERSION >= NTDDI_WS03)
  // #if (NTDDI_VERSION >= NTDDI_VISTA)
  PP_USER_CERTSTORE = 42;
  PP_SMARTCARD_READER = 43;
  PP_SMARTCARD_GUID = 45;
  PP_ROOT_CERTSTORE = 46;
  // #endif //(NTDDI_VERSION >= NTDDI_VISTA)
  // #if (NTDDI_VERSION >= NTDDI_WIN8)
  PP_SMARTCARD_READER_ICON = 47;
  // #endif // (NTDDI_VERSION >= NTDDI_WIN8)

  CRYPT_FIRST = 1;
  CRYPT_NEXT = 2;
  CRYPT_SGC_ENUM = 4;

  CRYPT_IMPL_HARDWARE = 1;
  CRYPT_IMPL_SOFTWARE = 2;
  CRYPT_IMPL_MIXED = 3;
  CRYPT_IMPL_UNKNOWN = 4;
  CRYPT_IMPL_REMOVABLE = 8;

  // key storage flags
  CRYPT_SEC_DESCR = $00000001;
  CRYPT_PSTORE = $00000002;
  CRYPT_UI_PROMPT = $00000004;

  // protocol flags
  CRYPT_FLAG_PCT1 = $0001;
  CRYPT_FLAG_SSL2 = $0002;
  CRYPT_FLAG_SSL3 = $0004;
  CRYPT_FLAG_TLS1 = $0008;
  CRYPT_FLAG_IPSEC = $0010;
  CRYPT_FLAG_SIGNING = $0020;

  // SGC flags
  CRYPT_SGC = $0001;
  CRYPT_FASTSGC = $0002;

  //
  // CryptSetProvParam
  //
  PP_CLIENT_HWND = 1;
  PP_CONTEXT_INFO = 11;
  PP_KEYEXCHANGE_KEYSIZE = 12;
  PP_SIGNATURE_KEYSIZE = 13;
  PP_KEYEXCHANGE_ALG = 14;
  PP_SIGNATURE_ALG = 15;
  PP_DELETEKEY = 24;
  // #if (NTDDI_VERSION >= NTDDI_VISTA)
  PP_PIN_PROMPT_STRING = 44;
  PP_SECURE_KEYEXCHANGE_PIN = 47;
  PP_SECURE_SIGNATURE_PIN = 48;
  // #endif //(NTDDI_VERSION >= NTDDI_VISTA)

  // certenrolld_begin -- PROV_RSA_*
  PROV_RSA_FULL = 1;
  PROV_RSA_SIG = 2;
  PROV_DSS = 3;
  PROV_FORTEZZA = 4;
  PROV_MS_EXCHANGE = 5;
  PROV_SSL = 6;
  PROV_RSA_SCHANNEL = 12;
  PROV_DSS_DH = 13;
  PROV_EC_ECDSA_SIG = 14;
  PROV_EC_ECNRA_SIG = 15;
  PROV_EC_ECDSA_FULL = 16;
  PROV_EC_ECNRA_FULL = 17;
  PROV_DH_SCHANNEL = 18;
  PROV_SPYRUS_LYNKS = 20;
  PROV_RNG = 21;
  PROV_INTEL_SEC = 22;
  // #if (NTDDI_VERSION >= NTDDI_WINXP)
  PROV_REPLACE_OWF = 23;
  PROV_RSA_AES = 24;
  // #endif //(NTDDI_VERSION >= NTDDI_WINXP)
  // certenrolld_end

  // #if (NTDDI_VERSION <= NTDDI_WINXP)
  //
  // STT defined Providers
  //
  PROV_STT_MER = 7;
  PROV_STT_ACQ = 8;
  PROV_STT_BRND = 9;
  PROV_STT_ROOT = 10;
  PROV_STT_ISS = 11;
  // #endif //(NTDDI_VERSION <= NTDDI_WINXP)

  //
  // Provider friendly names
  //
  MS_DEF_PROV: PChar = 'Microsoft Base Cryptographic Provider v1.0';
  MS_ENHANCED_PROV: PChar = 'Microsoft Enhanced Cryptographic Provider v1.0';
  MS_STRONG_PROV: PChar = 'Microsoft Strong Cryptographic Provider';
  MS_DEF_RSA_SIG_PROV: PChar = 'Microsoft RSA Signature Cryptographic Provider';
  MS_DEF_RSA_SCHANNEL_PROV
    : PChar = 'Microsoft RSA SChannel Cryptographic Provider';
  MS_DEF_DSS_PROV: PChar = 'Microsoft Base DSS Cryptographic Provider';
  MS_DEF_DSS_DH_PROV
    : PChar = 'Microsoft Base DSS and Diffie-Hellman Cryptographic Provider';
  MS_ENH_DSS_DH_PROV
    : PChar = 'Microsoft Enhanced DSS and Diffie-Hellman Cryptographic Provider';
  MS_DEF_DH_SCHANNEL_PROV
    : PChar = 'Microsoft DH SChannel Cryptographic Provider';
  MS_SCARD_PROV: PChar = 'Microsoft Base Smart Card Crypto Provider';

  // #if (NTDDI_VERSION >= NTDDI_WINXP)
  MS_ENH_RSA_AES_PROV
    : PChar = 'Microsoft Enhanced RSA and AES Cryptographic Provider';
  MS_ENH_RSA_AES_PROV_XP_A
    : PChar = 'Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype)';
  // #endif //(NTDDI_VERSION >= NTDDI_WINXP)

  MAXUIDLEN = 64;

  // Exponentiation Offload Reg Location
  EXPO_OFFLOAD_REG_VALUE = 'ExpoOffload';
  EXPO_OFFLOAD_FUNC_NAME = 'OffloadModExpo';

  //
  // Registry key in which the following private key-related
  // values are created.
  //
  szKEY_CRYPTOAPI_PRIVATE_KEY_OPTIONS
    : PChar = 'Software\\Policies\\Microsoft\\Cryptography';

  //
  // Registry values for enabling and controlling the caching (and timeout)
  // of private keys.  This feature is intended for UI-protected private
  // keys.
  //
  // Note that in Windows 2000 and later, private keys, once read from storage,
  // are cached in the associated HCRYPTPROV structure for subsequent use.
  //
  // In Server 2003 and XP SP1, new key caching behavior is available.  Keys
  // that have been read from storage and cached may now be considered "stale"
  // if a period of time has elapsed since the key was last used.  This forces
  // the key to be re-read from storage (which will make the DPAPI UI appear
  // again).
  //
  // Optional Key Timeouts:
  //
  // In Windows Server 2003, XP SP1, and later, new key caching behavior is
  // available.  Keys that have been read from storage and cached per-context
  // may now be considered "stale" if a period of time has elapsed since the
  // key was last used.  This forces the key to be re-read from storage (which
  // will make the Data Protection API dialog appear again if the key is
  // UI-protected).
  //
  // To enable the new behavior, create the registry DWORD value
  // szKEY_CACHE_ENABLED and set it to 1.  The registry DWORD value
  // szKEY_CACHE_SECONDS must also be created and set to the number of seconds
  // that a cached private key may still be considered usable.
  //
  szKEY_CACHE_ENABLED: PChar = 'CachePrivateKeys';
  szKEY_CACHE_SECONDS: PChar = 'PrivateKeyLifetimeSeconds';

  // #if (NTDDI_VERSION >= NTDDI_WINXP)
  //
  // In platforms later than (and not including) Windows Server 2003, private
  // keys are always cached for a period of time per-process, even when
  // not being used in any context.
  //
  // The differences between the process-wide caching settings described below
  // and the Optional Key Timeouts described above are subtle.
  //
  // - The Optional Key Timeout policy is applied only when an attempt is made
  // to use a specific private key with an open context handle (HCRYPTPROV).
  // If szKEY_CACHE_SECONDS have elapsed since the key was last used, the
  // private key will be re-read from storage.
  //
  // - The Cache Purge Interval policy, below, is applied whenever any
  // non-ephemeral private key is used or read from storage.  If
  // szPRIV_KEY_CACHE_PURGE_INTERVAL_SECONDS have elapsed since the last
  // purge occurred, all cached keys that have not been referenced since the
  // last purge will be removed from the cache.
  //
  // If a private key that is purged from the cache is currently
  // referenced in an open context, then the key will be re-read from storage
  // the next time an attempt is made to use it (via any context).
  //
  // The following two registry DWORD values control this behavior.
  //

  //
  // Registry value for controlling the maximum number of persisted
  // (non-ephemeral) private keys that can be cached per-process.  If the cache
  // fills up, keys will be replaced on a least-recently-used basis.  If the
  // maximum number of cached keys is set to zero, no keys will be globally
  // cached.
  //
  szPRIV_KEY_CACHE_MAX_ITEMS: PChar = 'PrivKeyCacheMaxItems';
  cPRIV_KEY_CACHE_MAX_ITEMS_DEFAULT = 20;

  //
  // Registry value for controlling the interval at which the private key
  // cache is proactively purged of outdated keys.
  //
  szPRIV_KEY_CACHE_PURGE_INTERVAL_SECONDS
    : PChar = 'PrivKeyCachePurgeIntervalSeconds';
  cPRIV_KEY_CACHE_PURGE_INTERVAL_SECONDS_DEFAULT = 86400; // 1 day
  // #endif //(NTDDI_VERSION >= NTDDI_WINXP)

  CUR_BLOB_VERSION = 2;

type
  // structure for use with CryptSetKeyParam for CMS keys
  // DO NOT USE THIS STRUCTURE!!!!!
  _CMS_KEY_INFO = record
    dwVersion: DWORD; // sizeof(CMS_KEY_INFO)
    Algid: ALG_ID; // algorithmm id for the key to be converted
    pbOID: PBYTE; // pointer to OID to hash in with Z
    cbOID: DWORD; // length of OID to hash in with Z
  end;

  CMS_KEY_INFO = _CMS_KEY_INFO;
  PCMS_KEY_INFO = ^CMS_KEY_INFO;
  TCmsKeyInfo = CMS_KEY_INFO;
  PCmsKeyInfo = ^TCmsKeyInfo;

  // structure for use with CryptSetHashParam with CALG_HMAC
  _HMAC_Info = record
    HashAlgid: ALG_ID;
    pbInnerString: PBYTE;
    cbInnerString: DWORD;
    pbOuterString: BYTE;
    cbOuterString: DWORD;
  end;

  HMAC_INFO = _HMAC_Info;
  PHMAC_INFO = ^HMAC_INFO;
  THMACInfo = HMAC_INFO;
  PHMACInfo = ^THMACInfo;

  // structure for use with CryptSetKeyParam with KP_SCHANNEL_ALG
  _SCHANNEL_ALG = record
    dwUse: DWORD;
    Algid: ALG_ID;
    cBits: DWORD;
    dwFlags: DWORD;
    dwReserved: DWORD;
  end;

  SCHANNEL_ALG = _SCHANNEL_ALG;
  PSCHANNEL_ALG = ^SCHANNEL_ALG;
  TSchannelAlg = SCHANNEL_ALG;
  PSchannelAlg = ^TSchannelAlg;

const
  // uses of algortihms for SCHANNEL_ALG structure
  SCHANNEL_MAC_KEY = $00000000;
  SCHANNEL_ENC_KEY = $00000001;

  // uses of dwFlags SCHANNEL_ALG structure
  INTERNATIONAL_USAGE = $00000001;

type
  _PROV_ENUMALGS = record
    aiAlgid: ALG_ID;
    dwBitLen: DWORD;
    dwNameLen: DWORD;
    szName: array [0 .. 19] of CHAR;
  end;

  PROV_ENUMALGS = _PROV_ENUMALGS;
  TProvEnumAlgs = PROV_ENUMALGS;
  PProvEnumAlgs = ^TProvEnumAlgs;

  // certenrolls_begin -- PROV_ENUMALGS_EX
  _PROV_ENUMALGS_EX = record
    aiAlgid: ALG_ID;
    dwDefaultLen: DWORD;
    dwMinLen: DWORD;
    dwMaxLen: DWORD;
    dwProtocols: DWORD;
    dwNameLen: DWORD;
    szName: array [0 .. 19] of CHAR;
    dwLongNameLen: DWORD;
    szLongName: array [0 .. 39] of CHAR;
  end;

  PROV_ENUMALGS_EX = _PROV_ENUMALGS_EX;
  TProvEnumAlgsEx = PROV_ENUMALGS_EX;
  PProvEnumAlgsEx = ^TProvEnumAlgsEx;
  // certenrolls_end

  _PUBLICKEYSTRUC = record
    bType: BYTE;
    bVersion: BYTE;
    reserved: WORD;
    aiKeyAlg: ALG_ID;
  end;

  BLOBHEADER = _PUBLICKEYSTRUC;
  PUBLICKEYSTRUC = _PUBLICKEYSTRUC;
  TPublicKeyStruc = _PUBLICKEYSTRUC;
  PPublicKeyStruc = TPublicKeyStruc;

  _RSAPUBKEY = record
    magic: DWORD; // Has to be RSA1
    bitlen: DWORD; // # of bits in modulus
    pubexp: DWORD; // public exponent
    // Modulus data follows
  end;

  RSAPUBKEY = _RSAPUBKEY;
  TRSAPubKey = _RSAPUBKEY;
  PRSAPubKey = TRSAPubKey;

  _PUBKEY = record
    magic: DWORD;
    bitlen: DWORD; // # of bits in modulus
  end;

  DHPUBKEY = _PUBKEY;
  TDHPubKey = _PUBKEY;
  DSSPUBKEY = _PUBKEY;
  TDSSPubKey = _PUBKEY;
  KEAPUBKEY = _PUBKEY;
  TKEAPubKey = _PUBKEY;
  TEKPUBKEY = _PUBKEY;

  _DSSSEED = record
    counter: DWORD;
    seed: array [0 .. 19] of BYTE;
  end;

  DSSSEED = _DSSSEED;
  TDSSSeed = DSSSEED;

  _PUBKEYVER3 = record
    magic: DWORD;
    bitlenP: DWORD; // # of bits in prime modulus
    bitlenQ: DWORD; // # of bits in prime q, 0 if not available
    bitlenJ: DWORD; // # of bits in (p-1)/q, 0 if not available
    DSSSEED: TDSSSeed;
  end;

  DHPUBKEY_VER3 = _PUBKEYVER3;
  TDHPubKeyVer3 = DHPUBKEY_VER3;
  DSSPUBKEY_VER3 = _PUBKEYVER3;
  TDSSPubKeyVer3 = DSSPUBKEY_VER3;

  _PRIVKEYVER3 = record
    magic: DWORD;
    bitlenP: DWORD; // # of bits in prime modulus
    bitlenQ: DWORD; // # of bits in prime q, 0 if not available
    bitlenJ: DWORD; // # of bits in (p-1)/q, 0 if not available
    bitlenX: DWORD; // # of bits in X
    DSSSEED: TDSSSeed;
  end;

  DHPRIVKEY_VER3 = _PRIVKEYVER3;
  TDHPrivKeyVer3 = DHPRIVKEY_VER3;
  DSSPRIVKEY_VER3 = _PRIVKEYVER3;
  TDSSPrivKeyVer3 = DSSPRIVKEY_VER3;

  _KEY_TYPE_SUBTYPE = record
    dwKeySpec: DWORD;
    &Type: TGUID;
    Subtype: TGUID;
  end;

  KEY_TYPE_SUBTYPE = _KEY_TYPE_SUBTYPE;
  PKEY_TYPE_SUBTYPE = ^_KEY_TYPE_SUBTYPE;
  TKeyTypeSubtype = KEY_TYPE_SUBTYPE;
  PKeyTypeSubtype = ^TKeyTypeSubtype;

  _CERT_FORTEZZA_DATA_PROP = record
    SerialNumber: array [0 .. 7] of BYTE;
    CertIndex: Integer;
    CertLabel: array [0 .. 35] of BYTE;
  end;

  CERT_FORTEZZA_DATA_PROP = _CERT_FORTEZZA_DATA_PROP;
  TCertFortezzaDataProp = CERT_FORTEZZA_DATA_PROP;

  // #if (NTDDI_VERSION >= NTDDI_WS03)
  _CRYPT_RC4_KEY_STATE = record
    Key: array [0 .. 15] of BYTE;
    SBox: array [0 .. 255] of BYTE;
    i: BYTE;
    j: BYTE;
  end;

  CRYPT_RC4_KEY_STATE = _CRYPT_RC4_KEY_STATE;
  PCRYPT_RC4_KEY_STATE = ^CRYPT_RC4_KEY_STATE;
  TCryptRC4KeyState = CRYPT_RC4_KEY_STATE;
  PCryptRC4KeyState = ^TCryptRC4KeyState;

  _CRYPT_DES_KEY_STATE = record
    Key: array [0 .. 7] of BYTE;
    IV: array [0 .. 7] of BYTE;
    Feedback: array [0 .. 7] of BYTE;
  end;

  CRYPT_DES_KEY_STATE = _CRYPT_DES_KEY_STATE;
  PCRYPT_DES_KEY_STATE = ^CRYPT_DES_KEY_STATE;
  TCryptDESKeyState = CRYPT_DES_KEY_STATE;
  PCryptDESKeyState = ^TCryptDESKeyState;

  _CRYPT_3DES_KEY_STATE = record
    Key: array [0 .. 23] of BYTE;
    IV: array [0 .. 7] of BYTE;
    Feedback: array [0 .. 7] of BYTE;
  end;

  CRYPT_3DES_KEY_STATE = _CRYPT_3DES_KEY_STATE;
  PCRYPT_3DES_KEY_STATE = ^CRYPT_3DES_KEY_STATE;
  TCrypt3DESKeyState = CRYPT_3DES_KEY_STATE;
  PCrypt3DESKeyState = ^TCrypt3DESKeyState;
  // #endif //(NTDDI_VERSION >= NTDDI_WS03)

  // #if (NTDDI_VERSION >= NTDDI_VISTA)
  _CRYPT_AES_128_KEY_STATE = record
    Key: array [0 .. 15] of BYTE;
    IV: array [0 .. 15] of BYTE;
    EncryptionState: array [0 .. 10, 0 .. 15] of BYTE; // 10 rounds + 1
    DecryptionState: array [0 .. 10, 0 .. 15] of BYTE;
    Feedback: array [0 .. 15] of BYTE;
  end;

  CRYPT_AES_128_KEY_STATE = _CRYPT_AES_128_KEY_STATE;
  PCRYPT_AES_128_KEY_STATE = ^CRYPT_AES_128_KEY_STATE;
  TCryptAES128KeyState = CRYPT_AES_128_KEY_STATE;
  PCryptAES128KeyState = ^TCryptAES128KeyState;

  _CRYPT_AES_256_KEY_STATE = record
    Key: array [0 .. 31] of BYTE;
    IV: array [0 .. 15] of BYTE;
    EncryptionState: array [0 .. 14, 0 .. 15] of BYTE; // 14 rounds + 1
    DecryptionState: array [0 .. 14, 0 .. 15] of BYTE;
    Feedback: array [0 .. 15] of BYTE;
  end;

  CRYPT_AES_256_KEY_STATE = _CRYPT_AES_256_KEY_STATE;
  PCRYPT_AES_256_KEY_STATE = ^CRYPT_AES_256_KEY_STATE;
  TCryptAES256KeyState = ^CRYPT_AES_256_KEY_STATE;
  PCryptAES256KeyState = ^TCryptAES256KeyState;
  // #endif //(NTDDI_VERSION >= NTDDI_VISTA)

  // #endif /* WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP) */
  // #pragma endregion


  // #pragma region Application Family
  // #if WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_APP)

  // +-------------------------------------------------------------------------
  // CRYPTOAPI BLOB definitions
  // --------------------------------------------------------------------------
  // certenrolls_begin -- *_BLOB
  _CRYPTOAPI_BLOB = record
    cbData: DWORD;
    pbData: PBYTE;
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
  // certenrolls_end

  // #endif /* WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_APP) */
  // #pragma endregion

  // #pragma region Desktop Family
  // #if WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)

  // structure for use with CryptSetKeyParam for CMS keys
  _CMS_DH_KEY_INFO = record
    dwVersion: DWORD; // sizeof(CMS_DH_KEY_INFO)
    Algid: ALG_ID; // algorithmm id for the key to be converted
    pszContentEncObjId: LPSTR; // pointer to OID to hash in with Z
    PubInfo: TCryptDataBlob; // OPTIONAL - public information
    pReserved: Pointer; // reserved - should be NULL
  end;

  CMS_DH_KEY_INFO = _CMS_DH_KEY_INFO;
  PCMS_DH_KEY_INFO = ^CMS_DH_KEY_INFO;
  TCmsDHKeyInfo = CMS_DH_KEY_INFO;
  PCmsDHKeyInfo = ^TCmsDHKeyInfo;

  // #if (NTDDI_VERSION >= NTDDI_VISTA)
function CryptAcquireContextA(out phProv: HCRYPTPROV;
  const pszContainer: LPCSTR; const pszProvider: LPCSTR; dwProvType: DWORD;
  dwFlags: DWORD): BOOL stdcall;
function CryptAcquireContextW(out phProv: HCRYPTPROV;
  const pszContainer: LPCWSTR; const pszProvider: LPCWSTR; dwProvType: DWORD;
  dwFlags: DWORD): BOOL stdcall;
function CryptAcquireContext(out phProv: HCRYPTPROV;
  const pszContainer: LPCTSTR; const pszProvider: LPCTSTR; dwProvType: DWORD;
  dwFlags: DWORD): BOOL stdcall;
// #endif //(NTDDI_VERSION >= NTDDI_VISTA)

// #if (NTDDI_VERSION >= NTDDI_WINXP)
function CryptReleaseContext(hProv: HCRYPTPROV; dwFlags: DWORD): BOOL stdcall;
// #endif //(NTDDI_VERSION >= NTDDI_WINXP)

function CryptGenKey(hProv: HCRYPTPROV; Algid: TAlgID; dwFlags: DWORD;
  out phKey: HCRYPTKEY): BOOL; stdcall;

function CryptDeriveKey(hProv: HCRYPTPROV; Algid: TAlgID; hBaseData: HCRYPTHASH;
  dwFlags: DWORD; out phKey: HCRYPTKEY): BOOL; stdcall;

function CryptDestroyKey(hKey: HCRYPTKEY): BOOL; stdcall;

// #if (NTDDI_VERSION >= NTDDI_WINXP)
function CryptSetKeyParam(hKey: HCRYPTKEY; dwParam: DWORD; pbData: PBYTE;
  dwFlags: DWORD): BOOL; stdcall;
// #endif //(NTDDI_VERSION >= NTDDI_WINXP)

function CryptGetKeyParam(hKey: HCRYPTKEY; dwParam: DWORD; pbData: PBYTE;
  pdwDataLen: PDWORD; dwFlags: DWORD): BOOL; stdcall;

// #if (NTDDI_VERSION >= NTDDI_WINXP)
function CryptSetHashParam(hHash: HCRYPTHASH; dwParam: DWORD;
  const pbData: PBYTE; dwFlags: DWORD): BOOL; stdcall;
// #endif //(NTDDI_VERSION >= NTDDI_WINXP)

function CryptGetHashParam(hHash: HCRYPTHASH; dwParam: DWORD;
  { out } pbData: PBYTE; var pdwDataLen: DWORD; dwFlags: DWORD): BOOL; stdcall;

// #if (NTDDI_VERSION >= NTDDI_WINXP)
function CryptSetProvParam(hProv: HCRYPTPROV; dwParam: DWORD;
  const pbData: PBYTE; dwFlags: DWORD): BOOL; stdcall;
// #endif //(NTDDI_VERSION >= NTDDI_WINXP)

function CryptGetProvParam(hProv: HCRYPTPROV; dwParam: DWORD; out pbData: PBYTE;
  pdwDataLen: PDWORD; dwFlags: DWORD): BOOL; stdcall;

function CryptGenRandom(hProv: HCRYPTPROV; dwLen: DWORD; pbBuffer: PBYTE)
  : BOOL; stdcall;

function CryptGetUserKey(hProv: HCRYPTPROV; dwKeySpec: DWORD;
  out phUserKey: HCRYPTKEY): BOOL; stdcall;

function CryptExportKey(hKey: HCRYPTKEY; hExpKey: HCRYPTKEY; dwBlobType: DWORD;
  dwFlags: DWORD; out pbData: PBYTE; pdwDataLen: PDWORD): BOOL; stdcall;

function CryptImportKey(hProv: HCRYPTPROV; const pbData: PBYTE;
  dwDataLen: DWORD; hPubKey: HCRYPTKEY; dwFlags: DWORD; out phKey: HCRYPTKEY)
  : BOOL; stdcall;

function CryptEncrypt(hKey: HCRYPTKEY; hHash: HCRYPTHASH; &Final: BOOL;
  dwFlags: DWORD; pbData: PBYTE; pdwDataLen: PDWORD; dwBufLen: DWORD)
  : BOOL; stdcall;

function CryptDecrypt(hKey: HCRYPTKEY; hHash: HCRYPTHASH; Final: BOOL;
  dwFlags: DWORD; { var } pbData: PBYTE; var pdwDataLen: DWORD): BOOL; stdcall;

function CryptCreateHash(hProv: HCRYPTPROV; Algid: TAlgID; hKey: HCRYPTKEY;
  dwFlags: DWORD; out phHash: HCRYPTHASH): BOOL stdcall;

function CryptHashData(hHash: HCRYPTHASH; const pbData: PBYTE; dwDataLen: DWORD;
  dwFlags: DWORD): BOOL; stdcall;

function CryptHashSessionKey(hHash: HCRYPTHASH; hKey: HCRYPTKEY; dwFlags: DWORD)
  : BOOL; stdcall;

function CryptDestroyHash(hHash: HCRYPTHASH): BOOL; stdcall;

// #if (NTDDI_VERSION >= NTDDI_VISTA)
function CryptSignHashA(hHash: HCRYPTHASH; dwKeySpec: DWORD;
  const sDescription: LPCSTR; dwFlags: DWORD; out pbSignature: PBYTE;
  pdwSigLen: PDWORD): BOOL; stdcall;
function CryptSignHashW(hHash: HCRYPTHASH; dwKeySpec: DWORD;
  const sDescription: LPCWSTR; dwFlags: DWORD; out pbSignature: PBYTE;
  pdwSigLen: PDWORD): BOOL; stdcall;
function CryptSignHash(hHash: HCRYPTHASH; dwKeySpec: DWORD;
  const sDescription: LPCTSTR; dwFlags: DWORD; out pbSignature: PBYTE;
  pdwSigLen: PDWORD): BOOL; stdcall;
// #endif //(NTDDI_VERSION >= NTDDI_VISTA)

// #if (NTDDI_VERSION >= NTDDI_VISTA)
function CryptVerifySignatureA(hHash: HCRYPTHASH; const pbSignature: PBYTE;
  dwSigLen: DWORD; hPubKey: HCRYPTKEY; const sDescription: LPCSTR;
  dwFlags: DWORD): BOOL; stdcall;
function CryptVerifySignatureW(hHash: HCRYPTHASH; const pbSignature: PBYTE;
  dwSigLen: DWORD; hPubKey: HCRYPTKEY; const sDescription: LPCWSTR;
  dwFlags: DWORD): BOOL; stdcall;
function CryptVerifySignature(hHash: HCRYPTHASH; const pbSignature: PBYTE;
  dwSigLen: DWORD; hPubKey: HCRYPTKEY; const sDescription: LPCTSTR;
  dwFlags: DWORD): BOOL; stdcall;
// #endif //(NTDDI_VERSION >= NTDDI_VISTA)

// #if (NTDDI_VERSION >= NTDDI_VISTA)
function CryptSetProviderA(const pszProvName: LPCSTR; dwProvType: DWORD)
  : BOOL; stdcall;
function CryptSetProviderW(const pszProvName: LPCWSTR; dwProvType: DWORD)
  : BOOL; stdcall;
function CryptSetProvider(const pszProvName: LPCTSTR; dwProvType: DWORD)
  : BOOL; stdcall;
// #endif //(NTDDI_VERSION >= NTDDI_VISTA)

// #if (NTDDI_VERSION >= NTDDI_VISTA)

type
  PCryptUIWizDigitalSighBlobInfo = ^TCryptUIWizDigitalSighBlobInfo;

  CRYPTUI_WIZ_DIGITAL_SIGN_BLOB_INFO = record
    dwSize: DWORD;
    pGuidSubject: PGUID;
    cbBlob: DWORD;
    pbBlob: Pointer;
    pwszDisplayName: LPCWSTR;
  end;

  TCryptUIWizDigitalSighBlobInfo = CRYPTUI_WIZ_DIGITAL_SIGN_BLOB_INFO;

  PCryptBitBlob = ^TCryptBitBlob;

  CRYPT_BIT_BLOB = record
    cbData: DWORD;
    pbData: Pointer;
    cUnusedBits: DWORD;
  end;

  TCryptBitBlob = CRYPT_BIT_BLOB;

  PCertExtension = ^TCertExtension;

  CERT_EXTENSION = record
    pszObjId: LPSTR;
    fCritical: BOOL;
    Value: TCryptObjIDBlob;
  end;

  TCertExtension = CERT_EXTENSION;

  PCryptAlgoithmIdentifier = ^TCryptAlgoithmIdentifier;

  CRYPT_ALGORITHM_IDENTIFIER = record
    pszObjId: LPSTR;
    Parameters: TCryptObjIDBlob;
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
    dwVersion: DWORD;
    SerialNumber: TCryptIntegerBlob;
    SignatureAlgorithm: TCryptAlgoithmIdentifier;
    Issuer: TCertNameBlob;
    NotBefore: TFileTime;
    NotAfter: TFileTime;
    Subject: TCertNameBlob;
    SubjectPublicKeyInfo: TCertPublicKeyInfo;
    IssuerUniqueId: TCryptBitBlob;
    SubjectUniqueId: TCryptBitBlob;
    cExtension: DWORD;
    rgExtension: PCertExtension;
  end;

  TCertInfo = ^CERT_INFO;

  HCERTSTORE = DWORD;
  THCertStore = HCERTSTORE;
  PHCertStore = ^THCertStore;

  CERT_CONTEXT = record
    dwCertEncodingType: DWORD;
    pbCertEncoded: Pointer;
    cbCertEncoded: DWORD;
    PCertInfo: PCertInfo;
    HCERTSTORE: HCERTSTORE;
  end;

function CryptContextAddRef(hProv: HCRYPTPROV; pdwReserved: PDWORD;
  dwFlags: DWORD): BOOL; stdcall;

function CryptDuplicateHash(hHash: HCRYPTHASH; pdwReserved: PDWORD;
  dwFlags: DWORD; out phHash: HCRYPTHASH): BOOL; stdcall;
// function CryptVerifySignatureW(hHash: HCRYPTHASH; pbSignature: Pointer;
// dwSigLen: DWORD; hPubKey: HCRYPTKEY; const sDescription: LPCWSTR;
// dwFlags: DWORD): BOOL; stdcall;

function CryptDuplicateKey(hKey: HCRYPTKEY; pdwReserved: PDWORD; dwFlags: DWORD;
  out phKey: HCRYPTKEY): BOOL; stdcall;

{ dpapi.h }

const

  //
  // Registry value for controlling Data Protection API (DPAPI) UI settings.
  //

  szFORCE_KEY_PROTECTION: PAnsiChar = 'ForceKeyProtection';

  dwFORCE_KEY_PROTECTION_DISABLED = $0;
  dwFORCE_KEY_PROTECTION_USER_SELECT = $1;
  dwFORCE_KEY_PROTECTION_HIGH = $2;

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
    cbSize: DWORD;
    dwPromptFlags: DWORD;
    hwndApp: HWND;
    szPrompt: LPCWSTR;
  end;

  TCryptProtectPromptStruct = CRYPTPROTECT_PROMPTSTRUCT;
  PCryptProtectPromptStruct = ^TCryptProtectPromptStruct;


  //
  // base provider action
  //
  // CRYPTPROTECT_DEFAULT_PROVIDER   { 0xdf9d8cd0, 0x1501, 0x11d1, {0x8c, 0x7a, 0x00, 0xc0, 0x4f, 0xc2, 0x97, 0xeb} }

  //
  // CryptProtect PromptStruct dwPromtFlags
  //
  //
  // prompt on unprotect
const
  CRYPTPROTECT_PROMPT_ON_UNPROTECT = $1; // 1<<0
  //
  // prompt on protect
  CRYPTPROTECT_PROMPT_ON_PROTECT = $2; // 1<<1
  CRYPTPROTECT_PROMPT_RESERVED = $04; // reserved, do not use.

  //
  // default to strong variant UI protection (user supplied password currently).
  CRYPTPROTECT_PROMPT_STRONG = $08; // 1<<3

  //
  // require strong variant UI protection (user supplied password currently).
  CRYPTPROTECT_PROMPT_REQUIRE_STRONG = $10; // 1<<4

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
  CRYPTPROTECT_LOCAL_MACHINE = $4;

  //
  // force credential synchronize during CryptProtectData()
  // Synchronize is only operation that occurs during this operation
  CRYPTPROTECT_CRED_SYNC = $8;

  //
  // Generate an Audit on protect and unprotect operations
  //
  CRYPTPROTECT_AUDIT = $10;

  //
  // Protect data with a non-recoverable key
  //
  CRYPTPROTECT_NO_RECOVERY = $20;

  //
  // Verify the protection of a protected blob
  //
  CRYPTPROTECT_VERIFY_PROTECTION = $40;

  //
  // Regenerate the local machine protection
  //
  CRYPTPROTECT_CRED_REGENERATE = $80;

  // flags reserved for system use
  CRYPTPROTECT_FIRST_RESERVED_FLAGVAL = $0FFFFFFF;
  CRYPTPROTECT_LAST_RESERVED_FLAGVAL = $FFFFFFFF;

  //
  // flags specific to base provider
  //

  CRYPTPROTECTMEMORY_BLOCK_SIZE = 16;

  CRYPTPROTECTMEMORY_SAME_PROCESS = $0;
  CRYPTPROTECTMEMORY_CROSS_PROCESS = $1;
  CRYPTPROTECTMEMORY_SAME_LOGON = $2;

function CryptProtectData(pDataIn: PDataBlob; const szDataDescr: LPCWSTR;
  pOptionalEntropy: PDataBlob; pvReserved: PVOID;
  pPromptStruct: PCryptProtectPromptStruct; dwFlags: DWORD; pDataOut: PDataBlob)
  : BOOL; stdcall;

function CryptUnprotectData(pDataIn: PDataBlob; const szDataDescr: LPCWSTR;
  pOptionalEntropy: PDataBlob; pvReserved: PVOID;
  pPromptStruct: PCryptProtectPromptStruct; dwFlags: DWORD; pDataOut: PDataBlob)
  : BOOL; stdcall;

function CryptProtectMemory(pData: LPVOID; cbData: DWORD; dwFlags: DWORD)
  : BOOL; stdcall;
function CryptUnprotectMemory(pData: LPVOID; cbData: DWORD; dwFlags: DWORD)
  : BOOL; stdcall;

implementation

function GetAlgClass(x: DWORD): DWORD; inline;
begin
  Result := (x and (7 shl 13));
end;

function GetAlgType(x: DWORD): DWORD; inline;
begin
  Result := (x and (15 shl 9));
end;

function GetAlgSid(x: DWORD): DWORD; inline;
begin
  Result := x and 511;
end;

function RCrypt_Succeeded(rt: BOOL): Boolean; inline;
begin
  Result := rt = CRYPT_SUCCEED;
end;

function RCrypt_Failed(rt: BOOL): Boolean; inline;
begin
  Result := rt = CRYPT_FAILED;
end;

const
  advapi32 = 'Advapi32.dll';
  crypt32 = 'Crypt32.dll';

function CryptAcquireContextA; external advapi32;
function CryptAcquireContextW; external advapi32;
{$IFDEF UNICODE}
function CryptAcquireContext; external advapi32 name 'CryptAcquireContextW';
{$ELSE}
function CryptAcquireContext; external advapi32 name 'CryptAcquireContextA';
{$ENDIF}
function CryptReleaseContext; external advapi32;
function CryptGenKey; external advapi32;
function CryptDeriveKey; external advapi32;
function CryptDestroyKey; external advapi32;
function CryptSetKeyParam; external advapi32;
function CryptGetKeyParam; external advapi32;
function CryptSetHashParam; external advapi32;
function CryptGetHashParam; external advapi32;
function CryptSetProvParam; external advapi32;
function CryptGetProvParam; external advapi32;
function CryptGenRandom; external advapi32;
function CryptGetUserKey; external advapi32;
function CryptExportKey; external advapi32;
function CryptImportKey; external advapi32;
function CryptEncrypt; external advapi32;
function CryptDecrypt; external advapi32;
function CryptCreateHash; external advapi32;
function CryptHashData; external advapi32;
function CryptHashSessionKey; external advapi32;
function CryptDestroyHash; external advapi32;
function CryptSignHashA; external advapi32;
function CryptSignHashW; external advapi32;
{$IFDEF UNICODE}
function CryptSignHash; external advapi32 name 'CryptSignHashW';
{$ELSE}
function CryptSignHash; external advapi32 name 'CryptSignHashA';
{$ENDIF}
function CryptVerifySignatureA; external advapi32;
function CryptVerifySignatureW; external advapi32;
{$IFDEF UNICODE}
function CryptVerifySignature; external advapi32 name 'CryptVerifySignatureW';
{$ELSE}
function CryptVerifySignature; external advapi32 name 'CryptVerifySignatureA';
{$ENDIF}
function CryptSetProviderA; external advapi32;
function CryptSetProviderW; external advapi32;
{$IFDEF UNICODE}
function CryptSetProvider; external advapi32 name 'CryptSetProviderW';
{$ELSE}
function CryptSetProvider; external advapi32 name 'CryptSetProviderA';
{$ENDIF}
function CryptContextAddRef; external advapi32;
function CryptDuplicateHash; external advapi32;
function CryptDuplicateKey; external advapi32;

function CryptProtectData; external crypt32;
function CryptUnprotectData; external crypt32;

function CryptProtectMemory; external crypt32;
function CryptUnprotectMemory; external crypt32;

end.
