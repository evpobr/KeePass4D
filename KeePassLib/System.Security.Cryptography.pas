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

unit System.Security.Cryptography;

interface

{$WARN SYMBOL_PLATFORM OFF}

uses
  Winapi.Windows, System.SysUtils, System.Classes, RTLConsts, KeePassLib.Wincrypt;

resourcestring
  SCryptographyHashNotYetFinalized = 'Hash not yet finalized.';
  SCryptographyCryptoStreamFlushFinalBlockTwice = '';
  SCryptography_InvalidKeySize = 'Invalid key size.';
  sCryptography_InvalidIVSize = 'Invalid IV size.';
  sCryptography_InvalidFeedbackSize = 'Invalid feedback size.';
  sCryptography_InvalidBlockSize = 'Invalid block size.';
  sCryptography_InvalidCipherMode = 'Invalid cipher mode.';
  sCryptography_InvalidPaddingMode = 'Invalid padding mode.';
  SCryptography_DpApi_InvalidMemoryLength = 'Invalid memory block size.';
  SArg_EnumIllegalVal = 'Illegal enum value.';

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
  CALG_MAC = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_MAC; // Deprecated. Don't use.
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
  CALG_AGREEDKEY_ANY = ALG_CLASS_KEY_EXCHANGE or ALG_TYPE_DH or ALG_SID_AGREED_KEY_ANY;
  CALG_KEA_KEYX = ALG_CLASS_KEY_EXCHANGE or ALG_TYPE_DH or ALG_SID_KEA;
  CALG_HUGHES_MD5 = ALG_CLASS_KEY_EXCHANGE or ALG_TYPE_ANY or ALG_SID_MD5;
  CALG_SKIPJACK = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_SKIPJACK;
  CALG_TEK = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_TEK;
  CALG_CYLINK_MEK = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_CYLINK_MEK; // Deprecated. Do not use
  CALG_SSL3_SHAMD5 = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_SSL3SHAMD5;
  CALG_SSL3_MASTER = ALG_CLASS_MSG_ENCRYPT or ALG_TYPE_SECURECHANNEL or ALG_SID_SSL3_MASTER;
  CALG_SCHANNEL_MASTER_HASH = ALG_CLASS_MSG_ENCRYPT or ALG_TYPE_SECURECHANNEL or ALG_SID_SCHANNEL_MASTER_HASH;
  CALG_SCHANNEL_MAC_KEY = ALG_CLASS_MSG_ENCRYPT or ALG_TYPE_SECURECHANNEL or ALG_SID_SCHANNEL_MAC_KEY;
  CALG_SCHANNEL_ENC_KEY = ALG_CLASS_MSG_ENCRYPT or ALG_TYPE_SECURECHANNEL or ALG_SID_SCHANNEL_ENC_KEY;
  CALG_PCT1_MASTER = ALG_CLASS_MSG_ENCRYPT or ALG_TYPE_SECURECHANNEL or ALG_SID_PCT1_MASTER;
  CALG_SSL2_MASTER = ALG_CLASS_MSG_ENCRYPT or ALG_TYPE_SECURECHANNEL or ALG_SID_SSL2_MASTER;
  CALG_TLS1_MASTER = ALG_CLASS_MSG_ENCRYPT or ALG_TYPE_SECURECHANNEL or ALG_SID_TLS1_MASTER;
  CALG_RC5 = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_RC5;
  CALG_HMAC = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_HMAC;
  CALG_TLS1PRF = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_TLS1PRF;
  // #if (NTDDI_VERSION >= NTDDI_WINXP)
  CALG_HASH_REPLACE_OWF = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_HASH_REPLACE_OWF;
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

  PROV_RSA_AES = 24;
  crypt32   = 'Crypt32.dll';



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

  CRYPTPROTECTMEMORY_BLOCK_SIZE     = 16;

  CRYPTPROTECTMEMORY_SAME_PROCESS   = $0;
  CRYPTPROTECTMEMORY_CROSS_PROCESS  = $1;
  CRYPTPROTECTMEMORY_SAME_LOGON     = $2;


function CryptProtectData(pDataIn: PDataBlob; const szDataDescr: LPCWSTR;
  pOptionalEntropy: PDataBlob; pvReserved: PVOID;
  pPromptStruct: PCryptProtectPromptStruct; dwFlags: DWORD;
  pDataOut: PDataBlob): BOOL; stdcall;

function CryptUnprotectData(pDataIn: PDataBlob; const szDataDescr: LPCWSTR;
  pOptionalEntropy: PDataBlob; pvReserved: PVOID;
  pPromptStruct: PCryptProtectPromptStruct; dwFlags: DWORD;
  pDataOut: PDataBlob): BOOL; stdcall;

function CryptProtectMemory(pData: LPVOID; cbData: DWORD;
  dwFlags: DWORD): BOOL; stdcall;
function CryptUnprotectMemory(pData: LPVOID; cbData: DWORD;
  dwFlags: DWORD): BOOL; stdcall;



  // TM

type
  TEncryptionMode = (Encrypt, Decrypt);

  /// <summary>
  /// Defines the basic operations of cryptographic transformations.
  /// </summary>
  ICryptoTransform = interface
    ['{8ABAD867-F515-3CF6-BB62-5F0C88B3BB11}']
    function GetCanReuseTransform: Boolean;
    function GetCanTransformMultipleBlocks: Boolean;
    function GetInputBlockSize: Integer;
    function GetOutputBlockSize: Integer;

    /// <summary>
    /// Gets the input block size.
    /// </summary>
    property InputBlockSize: Integer read GetInputBlockSize;

    /// <summary>
    /// Gets the output block size.
    /// </summary>
    property OutputBlockSize: Integer read GetOutputBlockSize;

    /// <summary>
    /// Gets a value indicating whether multiple blocks can be transformed.
    /// </summary>
    property CanTransformMultipleBlocks: Boolean read GetCanTransformMultipleBlocks;

    /// <summary>
    /// Gets a value indicating whether the current transform can be reused.
    /// </summary>
    property CanReuseTransform: Boolean read GetCanReuseTransform;

    function TransformBlock(InputBuffer: TBytes; InputOffset: Integer; InputCount: Integer; out OutputBuffer: TBytes; OutputOffset: Integer): Integer;

    /// <summary>
    /// Transforms the specified region of the specified byte array.
    /// <param name="InputBuffer">
    /// The input for which to compute the transform.
    /// </param>
    /// <param name="InputOffset">
    /// The offset into the byte array from which to begin using data.
    /// </param>
    /// <param name="InputCount">
    /// The number of bytes in the byte array to use as data.
    /// </param>
    /// </summary>
    /// <returns>
    /// The computed transform.
    /// </returns>
    /// <remarks>
    /// TransformFinalBlock is a special function for transforming the last
    /// block or a partial block in the stream. It returns a new array that
    /// contains the remaining transformed bytes. A new array is returned,
    /// because the amount of information returned at the end might be larger
    /// than a single block when padding is added.
    /// </remarks>
    function TransformFinalBlock(InputBuffer: TBytes; InputOffset: Integer; InputCount: Integer): TBytes;
  end;

  ECryptographicException = class(Exception);
  ECryptographicUnexpectedOperationException = class(ECryptographicException);

  /// <summary>
  /// Represents the base class from which all implementations of
  /// cryptographic hash algorithms must derive.
  /// </summary>
  THashAlgorithm = class abstract(TInterfacedObject, ICryptoTransform)
  strict protected
    FHashValue: TBytes;
  protected
    FHashSizeValue: Integer;
    FState: Integer;
    function GetCanReuseTransform: Boolean; virtual;
    function GetCanTransformMultipleBlocks: Boolean; virtual;
    function GetInputBlockSize: Integer; virtual;
    function GetOutputBlockSize: Integer; virtual;
    function GetHash: TBytes; virtual;
    function GetHashSize: Integer; virtual;
    function HashCore(&Array: TBytes; ibStart: Integer; cbSize: Integer): Integer; virtual; abstract;
    function HashFinal: TBytes; virtual; abstract;
  public
    property CanReuseTransform: Boolean read GetCanReuseTransform;
    property CanTransformMultipleBlocks: Boolean read GetCanTransformMultipleBlocks;
    property InputBlockSize: Integer read GetInputBlockSize;
    property OutputBlockSize: Integer read GetOutputBlockSize;
    property Hash: TBytes read GetHash;
    property HashSize: Integer read GetHashSize;
    constructor Create;
    destructor Destroy; override;
    procedure Clear; virtual;
    function ComputeHash(InputStream: TStream): TBytes; overload;
    function ComputeHash(Buffer: TBytes): TBytes; overload;
    function ComputeHash(Buffer: TBytes; Offset: Integer; Count: Integer): TBytes; overload;
    /// <summary>
    /// Computes the hash value for the specified region of the input byte
    /// array and copies the specified region of the input byte array to the
    /// specified region of the output byte array.
    /// <param name="InputBuffer">
    /// The input to compute the hash code for.
    /// </param>
    /// <param name="InputOffset">
    /// The offset into the input byte array from which to begin using data.
    /// </param>
    /// <param name="InputCount">
    /// The number of bytes in the input byte array to use as data.
    /// </param>
    /// <param name="OutputBuffer">
    /// A copy of the part of the input array used to compute the hash code.
    /// </param>
    /// <param name="OutputOffset">
    /// The offset into the output byte array from which to begin writing data.
    /// </param>
    /// </summary>
    /// <returns>
    /// The number of bytes written.
    /// </returns>
    /// <exception cref="System|EArgumentException">
    /// <paramref name="inputCount"/> uses an invalid value or inputBuffer has an invalid length.
    /// </exception>
    function TransformBlock(InputBuffer: TBytes; InputOffset: Integer; InputCount: Integer; out OutputBuffer: TBytes; OutputOffset: Integer): Integer;
    function TransformFinalBlock(InputBuffer: TBytes; InputOffset: Integer; InputCount: Integer): TBytes;
    procedure Initialize; virtual; abstract;
  end;

  TCipherMode = (CBC, ECB, OFB, CFB, CTS);

  TPaddingMode = (None, PKCS7, Zeroes, ANSIX923, ISO10126);

  TKeySizes = record
  private
    FMinSize: Integer;
    FMaxSize: Integer;
    FSkipSize: Integer;
  public
    property MinSize: Integer read FMinSize;
    property MaxSize: Integer read FMaxSize;
    property SkipSize: Integer read FSkipSize;
  end;

  /// <summary>
  /// Represents the abstract base class from which all implementations of
  /// symmetric algorithms must inherit.
  /// </summary>
  TSymmetricAlgorithm = class abstract
  private
    function GetBlockSize: Integer; virtual;
    procedure SetBlockSize(const Value: Integer); virtual;
    function GetFeedbackSize: Integer; virtual;
    procedure SetFeedbackSize(const Value: Integer); virtual;
    function GetIV: TBytes; virtual;
    procedure SetIV(const Value: TBytes); virtual;
    function GetKey: TBytes; virtual;
    procedure SetKey(const Value: TBytes); virtual;
    function GetLegalBlockSizes: TArray<TKeySizes>; virtual;
    function GetLegalKeySizes: TArray<TKeySizes>; virtual;
    function GetKeySize: Integer; virtual;
    procedure SetKeySize(const Value: Integer); virtual;
    function GetMode: TCipherMode; virtual;
    procedure SetMode(const Value: TCipherMode); virtual;
    function GetPadding: TPaddingMode; virtual;
    procedure SetPadding(const Value: TPaddingMode); virtual;
  protected
    FBlockSize: Integer;
    FFeedbackSize: Integer;
    FIV: TBytes;
    FKey: TBytes;
    FLegalBlockSizes: TArray<TKeySizes>;
    FLegalKeySizes: TArray<TKeySizes>;
    FKeySize: Integer;
    FMode: TCipherMode;
    FPadding: TPaddingMode;
  public
    property BlockSize: Integer read GetBlockSize write SetBlockSize;
    property FeedbackSize: Integer read GetFeedbackSize write SetFeedbackSize;
    property IV: TBytes read GetIV write SetIV;
    property Key: TBytes read GetKey write SetKey;
    property LegalBlockSizes: TArray<TKeySizes> read GetLegalBlockSizes;
    property LegalKeySizes: TArray<TKeySizes> read GetLegalKeySizes;
    property KeySize: Integer read GetKeySize write SetKeySize;
    property Mode: TCipherMode read GetMode write SetMode;
    property Padding: TPaddingMode read GetPadding write SetPadding;
    function ValidKeySize(BitLength: Integer): Boolean;
    function CreateEncryptor: ICryptoTransform; overload; virtual;
    function CreateEncryptor(Key: TBytes; IV: TBytes): ICryptoTransform; overload; virtual; abstract;
    function CreateDecryptor: ICryptoTransform; overload; virtual;
    function CreateDecryptor(Key: TBytes; IV: TBytes): ICryptoTransform; overload; virtual; abstract;
    procedure GenerateKey; virtual; abstract;
    procedure GenerateIV; virtual; abstract;

    constructor Create;
    destructor Destroy; override;
  end;

  TCapiSymmetricAlgorithm = class(TInterfacedObject, ICryptoTransform)
  private
    FBlockSize: Integer;
    FDepadBuffer: TBytes;
    FEncryptionMode: TEncryptionMode;
    FKey: HCRYPTKEY;
    FPaddingMode: TPaddingMode;
    FProvider: HCRYPTPROV;

    class function SetupKey(Key: HCRYPTKEY; IV: TBytes; CipherMode: TCipherMode; FeedbackSize: Integer): HCRYPTKEY; static;
    function DecryptBlocks(InputBuffer: TBytes; InputOffset: Integer; InputCount: Integer; out OutputBuffer: TBytes; OutputOffset: Integer): Integer;
    function RawDecryptBlocks(Buffer: TBytes; Offset: Integer; Count: Integer): Integer;
    function DepadBlock(Block: TBytes; Offset: Integer; Count: Integer): TBytes;
  protected
    function GetCanReuseTransform: Boolean;
    function GetCanTransformMultipleBlocks: Boolean;
    function GetInputBlockSize: Integer;
    function GetOutputBlockSize: Integer;
  public
    property InputBlockSize: Integer read GetInputBlockSize;
    property OutputBlockSize: Integer read GetOutputBlockSize;
    property CanTransformMultipleBlocks: Boolean read GetCanTransformMultipleBlocks;
    property CanReuseTransform: Boolean read GetCanReuseTransform;
    function TransformBlock(InputBuffer: TBytes; InputOffset: Integer; InputCount: Integer; out OutputBuffer: TBytes; OutputOffset: Integer): Integer;
    function TransformFinalBlock(InputBuffer: TBytes; InputOffset: Integer; InputCount: Integer): TBytes;

    constructor Create(BlockSize: Integer; FeedbackSize: Integer; Provider: HCRYPTPROV; Key: HCRYPTKEY; IV: TBytes; CipherMode: TCipherMode;
        PaddingMode: TPaddingMode; EncryptionMode: TEncryptionMode);
    destructor Destroy; override;
  end;

  TCapiHash = class(THashAlgorithm, ICryptoTransform)
  private
    FAlgid: ALG_ID;
    FHashHandle: HCRYPTHASH;
    FProvHandle: HCRYPTPROV;
  protected
    function HashCore(&Array: TBytes; ibStart: Integer; cbSize: Integer): Integer; override;
    function HashFinal: TBytes; override;
    constructor Create(Algid: ALG_ID);
  public
    procedure Initialize; override;
    procedure Clear; override;
  end;

  TSHA1CryptoServiceProvider = class(TCapiHash, ICryptoTransform)
  public
    constructor Create;
  end;

  TSHA256CryptoServiceProvider = class(TCapiHash, ICryptoTransform)
  public
    constructor Create;
  end;

  TCryptoStreamMode = (csmRead, csmWrite);

  TCryptoStream = class(TStream)
  private
    FStream: TStream;
    FTransform: ICryptoTransform;
    FInputBuffer: TBytes;
    FInputBufferIndex: Integer;
    FOutputBuffer: TBytes;
    FOutputBufferIndex: Integer;
    FOutputBlockSize: Integer;
    FTransformMode: TCryptoStreamMode;
    FFinalBlockTransformed: Boolean;
  public
    property HasFlushedFinalBlock: Boolean read FFinalBlockTransformed;

    constructor Create(Stream: TStream; Transform: ICryptoTransform; Mode: TCryptoStreamMode);
    procedure FlushFinalBlock;
  end;

  TDataProtectionScope = (CurrentUser, LocalMachine);

  TMemoryProtectionScope = (SameProcess, CrossProcess, SameLogon);

  TProtectedData = class
  public
    class function Protect(UserData: TBytes; OptionalEntropy: TBytes; Scope: TDataProtectionScope): TBytes; static;
    class function Unprotect(EncryptedData: TBytes; OptionalEntropy: TBytes; Scope: TDataProtectionScope): TBytes; static;
  strict protected
    constructor Create;
  end;

  TProtectedMemory = class
  strict private
    class procedure VerifyScope(Scope: TMemoryProtectionScope); static;
  public
    class procedure Protect(UserData: TBytes; Scope: TMemoryProtectionScope); static;
    class procedure Unprotect(EncryptedData: TBytes; Scope: TMemoryProtectionScope); static;
  strict protected
    constructor Create;
  end;

  TRandomNumberGenerator = class abstract
  strict protected
    constructor Create;
  public
    procedure GetBytes(Data: TBytes); overload; virtual; abstract;
    procedure GetBytes(Data: TBytes; Offset: Integer; Count: Integer); overload; virtual;
    procedure GetNonZeroBytes(Data: TBytes); virtual;
  end;

  TRNGCryptoServiceProvider = class(TRandomNumberGenerator)
  strict private
    FProvHandle: HCRYPTPROV;
  public
    constructor Create;
    destructor Destroy; override;
    procedure GetBytes(Data: TBytes);
    procedure GetNonZeroBytes(Data: TBytes); override;
  end;

implementation

{ THashAlgorithm }

procedure THashAlgorithm.Clear;
begin
  if Length(FHashValue) <> 0 then
  begin
    FillChar(FHashValue[0], Length(FHashValue), 0);
    FHashValue := nil;
  end;
end;

function THashAlgorithm.ComputeHash(Buffer: TBytes): TBytes;
var
  Tmp: TBytes;
begin
  if not Assigned(Buffer) then
    raise EArgumentNilException.CreateFmt(SParamIsNil, ['Buffer']);

  HashCore(Buffer, 0, Length(Buffer));
  FHashValue := HashFinal;
  Tmp := Copy(FHashValue);
  Initialize;
  Result := Tmp;
end;

function THashAlgorithm.ComputeHash(Buffer: TBytes; Offset, Count: Integer): TBytes;
var
  Tmp: TBytes;
begin
  if not Assigned(Buffer) then
    raise EArgumentNilException.CreateFmt(SParamIsNil, ['Buffer']);
  if Offset < 0 then
    raise EArgumentOutOfRangeException.CreateFmt(SParamIsNegative, ['Offset']);
  if (Count < 0) or (Count > Length(Buffer)) then
    raise EArgumentException.Create(sArgumentInvalid);
  if (Length(Buffer) - Count) < Offset then
    raise EArgumentException.Create(sArgumentOutOfRange_OffLenInvalid);

  HashCore(Buffer, Offset, Count);
  FHashValue := HashFinal;
  Tmp := Copy(FHashValue);
  Initialize;
  Result := Tmp;
end;

function THashAlgorithm.ComputeHash(InputStream: TStream): TBytes;
var
  BytesRead: Longint;
  Buffer: TBytes;
  Tmp: TBytes;
begin
  BytesRead := 0;
  SetLength(Buffer, 4096);

  repeat
    BytesRead := InputStream.Read(Buffer[0], BytesRead);
    if BytesRead > 0 then
      HashCore(Buffer, 0, BytesRead);
  until BytesRead > 0;

  FHashValue := HashFinal;
  Tmp := Copy(FHashValue);
  Initialize;
  Result := Tmp;
end;

constructor THashAlgorithm.Create;
begin
  inherited;
  Initialize;
end;

destructor THashAlgorithm.Destroy;
begin
  Clear;
  inherited;
end;

function THashAlgorithm.GetCanReuseTransform: Boolean;
begin
  Result := True;
end;

function THashAlgorithm.GetCanTransformMultipleBlocks: Boolean;
begin
  Result := True;
end;

function THashAlgorithm.GetHash: TBytes;
begin
  if FState <> 0 then
    raise ECryptographicUnexpectedOperationException.Create(SCryptographyHashNotYetFinalized);

  Result := Copy(FHashValue);
end;

function THashAlgorithm.GetHashSize: Integer;
begin
  Result := FHashSizeValue;
end;

function THashAlgorithm.GetInputBlockSize: Integer;
begin
  Result := 1;
end;

function THashAlgorithm.GetOutputBlockSize: Integer;
begin
  Result := 1;
end;

function THashAlgorithm.TransformBlock(InputBuffer: TBytes; InputOffset, InputCount: Integer; out OutputBuffer: TBytes;
    OutputOffset: Integer): Integer;
begin
  if not Assigned(InputBuffer) then
    raise EArgumentNilException.CreateFmt(SParamIsNil, ['InputBuffer']);
  if InputOffset < 0 then
    raise EArgumentOutOfRangeException.CreateFmt(SParamIsNegative, ['InputOffset']);
  if (InputCount < 0) or (InputCount > Length(InputBuffer)) then
    raise EArgumentException.Create(sArgumentInvalid);
  if (Length(InputBuffer) - InputCount) < InputOffset then
    raise EArgumentException.Create(sArgumentOutOfRange_OffLenInvalid);

  FState := 1;

  HashCore(InputBuffer, InputOffset, InputCount);

  if Assigned(OutputBuffer) and (InputBuffer <> OutputBuffer) and (InputOffset <> OutputOffset) then
    Move(InputBuffer[InputOffset], OutputBuffer[OutputOffset], InputCount);

  Result := InputCount;
end;

function THashAlgorithm.TransformFinalBlock(InputBuffer: TBytes; InputOffset, InputCount: Integer): TBytes;
var
  OutputBytes: TBytes;
begin
  if InputBuffer = nil then
    raise EArgumentNilException.CreateFmt(SParamIsNil, ['InputBuffer']);
  if InputOffset < 0 then
    raise EArgumentOutOfRangeException.CreateFmt(SParamIsNegative, ['InputOffset']);
  if (InputCount < 0) or (InputCount > Length(InputBuffer)) then
    raise EArgumentException.Create(sArgumentInvalid);
  if Length(InputBuffer) - InputCount < InputOffset then
    raise EArgumentException.Create(sArgumentOutOfRange_OffLenInvalid);

  HashCore(InputBuffer, InputOffset, InputCount);
  FHashValue := HashFinal;

  if InputCount <> 0 then
  begin
    SetLength(OutputBytes, InputCount);
    Move(InputBuffer[InputOffset], OutputBytes, InputCount);
  end
  else
  begin
    SetLength(OutputBytes, 0);
  end;
  FState := 0;
  Result := Copy(OutputBytes);
end;

{ TSHA1CryptoServiceProvider }

constructor TSHA1CryptoServiceProvider.Create;
begin
  inherited Create(CALG_SHA1);
end;

{ TCapiHash }

procedure TCapiHash.Clear;
begin
  inherited;

  if FHashHandle <> 0 then
    CryptDestroyHash(FHashHandle);
  if FProvHandle <> 0 then
    CryptReleaseContext(FProvHandle, 0);
end;

constructor TCapiHash.Create(Algid: ALG_ID);
var
  dwDataLen, dwHashSize: DWORD;
begin
  FAlgid := Algid;

  inherited Create;

  dwDataLen := SizeOf(DWORD);
  Win32Check(CryptGetHashParam(FHashHandle, HP_HASHSIZE, @(dwHashSize), dwDataLen, 0));
  FHashSizeValue := dwHashSize * 8;
end;

function TCapiHash.HashCore(&Array: TBytes; ibStart, cbSize: Integer): Integer;
var
  dwDataLen: DWORD;
begin
  dwDataLen := cbSize;
  Win32Check(CryptHashData(FHashHandle, @&Array[ibStart], dwDataLen, 0));

  Result := cbSize;
end;

function TCapiHash.HashFinal: TBytes;
var
  dwDataLen, dwHashSize: DWORD;
begin
  dwDataLen := SizeOf(DWORD);
  Win32Check(CryptGetHashParam(FHashHandle, HP_HASHSIZE, @(dwHashSize), dwDataLen, 0));
  SetLength(FHashValue, dwHashSize);
  Win32Check(CryptGetHashParam(FHashHandle, HP_HASHVAL, @(FHashValue[0]), dwHashSize, 0));

  Result := Copy(FHashValue);
end;

procedure TCapiHash.Initialize;
begin
  Clear;

  Win32Check(CryptAcquireContext(FProvHandle, nil, nil, PROV_RSA_AES, CRYPT_VERIFYCONTEXT));
  Win32Check(CryptCreateHash(FProvHandle, FAlgid, 0, 0, FHashHandle));
end;

{ TSHA256CryptoServiceProvider }

constructor TSHA256CryptoServiceProvider.Create;
begin
  inherited Create(CALG_SHA_256);
end;

{ TCryptoStream }

constructor TCryptoStream.Create(Stream: TStream; Transform: ICryptoTransform; Mode: TCryptoStreamMode);
begin
  inherited Create;

  FStream := Stream;
  FTransform := Transform;
  FTransformMode := Mode;
end;

procedure TCryptoStream.FlushFinalBlock;
var
  FinalBytes: TBytes;
  InnerCryptoStream: TCryptoStream;
begin
  if FFinalBlockTransformed then
    raise ENotSupportedException.Create(SCryptographyCryptoStreamFlushFinalBlockTwice);

  FinalBytes := FTransform.TransformFinalBlock(FInputBuffer, 0, FInputBufferIndex);
  FFinalBlockTransformed := True;

  FStream.Write(FOutputBuffer, 0, FOutputBufferIndex);
  FOutputBufferIndex := 0;

  FStream.Write(FinalBytes, 0, Length(FinalBytes));

  InnerCryptoStream := FStream as TCryptoStream;
  if InnerCryptoStream <> nil then
  begin
    if not InnerCryptoStream.HasFlushedFinalBlock then
      InnerCryptoStream.FlushFinalBlock;
  end

end;

{ TSymmetricAlgorithm }

constructor TSymmetricAlgorithm.Create;
begin
  FMode := TCipherMode.CBC;
  FPadding := TPaddingMode.PKCS7;
end;

function TSymmetricAlgorithm.CreateDecryptor: ICryptoTransform;
begin

end;

function TSymmetricAlgorithm.CreateEncryptor: ICryptoTransform;
begin

end;

destructor TSymmetricAlgorithm.Destroy;
begin
  if Length(FKey) > 0 then
  begin
    FillChar(FKey, Length(FKey), 0);
    FKey := nil;
  end;
  if Length(FIV) > 0 then
  begin
    FillChar(FIV, Length(FIV), 0);
    FIV := nil;
  end;

  inherited;
end;

function TSymmetricAlgorithm.GetBlockSize: Integer;
begin
  Result := FBlockSize;
end;

function TSymmetricAlgorithm.GetFeedbackSize: Integer;
begin
  Result := FFeedbackSize;
end;

function TSymmetricAlgorithm.GetKey: TBytes;
begin
  if Length(FKey) <= 0 then
    GenerateIV;

  Result := Copy(FKey);
end;

function TSymmetricAlgorithm.GetKeySize: Integer;
begin
  Result := FKeySize;
end;

function TSymmetricAlgorithm.GetLegalBlockSizes: TArray<TKeySizes>;
begin
  Result := Copy(FLegalBlockSizes);
end;

function TSymmetricAlgorithm.GetLegalKeySizes: TArray<TKeySizes>;
begin
  Result := Copy(FLegalKeySizes);
end;

function TSymmetricAlgorithm.GetMode: TCipherMode;
begin
  Result := FMode;
end;

function TSymmetricAlgorithm.GetPadding: TPaddingMode;
begin
  Result := FPadding;
end;

function TSymmetricAlgorithm.GetIV: TBytes;
begin
  if Length(FIV) <= 0 then
    GenerateIV;

  Result := Copy(FIV);
end;

procedure TSymmetricAlgorithm.SetBlockSize(const Value: Integer);
var
  I, J: Integer;
begin
  for I := 0 to Length(FLegalBlockSizes) - 1 do
  begin
    if FLegalBlockSizes[I].SkipSize = 0 then
    begin
      if FLegalBlockSizes[I].MinSize = Value then
      begin
        FBlockSize := Value;
        FIV := nil;
        Exit;
      end;
    end
    else
    begin
      J := FLegalBlockSizes[I].MinSize;
      while J <= FLegalBlockSizes[I].MaxSize do
      begin
        if J = Value then
        begin
          if FBlockSize <> Value then
          begin
            FBlockSize := Value;
            FIV := nil;
          end;
          Exit;
        end;
        Inc(J, FLegalBlockSizes[I].SkipSize);
      end;
    end;
  end;

  raise ECryptographicException.Create(sCryptography_InvalidBlockSize);
end;

procedure TSymmetricAlgorithm.SetFeedbackSize(const Value: Integer);
begin
  if (Value <= 0) or (Value > FBlockSize) or (Value mod 8 <> 0) then
    raise ECryptographicException.Create(sCryptography_InvalidFeedbackSize);

  FFeedbackSize := Value;
end;

procedure TSymmetricAlgorithm.SetIV(const Value: TBytes);
begin
  if Value = nil then
    raise EArgumentNilException.Create('Value');

  if Length(Value) <> (FBlockSize div 8) then
    raise ECryptographicException.Create(sCryptography_InvalidIVSize);

  FIV := Copy(Value);
end;

procedure TSymmetricAlgorithm.SetKey(const Value: TBytes);
begin
  if Value = nil then
    raise EArgumentNilException.Create('Key');

  if not ValidKeySize(Length(Value) * 8) then
    raise ECryptographicException.Create(SCryptography_InvalidKeySize);

  FKey := Copy(Value);
  FKeySize := Length(Value) * 8;
end;

procedure TSymmetricAlgorithm.SetKeySize(const Value: Integer);
begin
  if not ValidKeySize(Value) then
    raise ECryptographicException.Create(SCryptography_InvalidKeySize);

  FKeySize := Value;
  FKey := nil;
end;

procedure TSymmetricAlgorithm.SetMode(const Value: TCipherMode);
begin
  if (Value < Low(TCipherMode)) or (Value > High(TCipherMode)) then
    raise ECryptographicException.Create(sCryptography_InvalidCipherMode);

  FMode := Value;
end;

procedure TSymmetricAlgorithm.SetPadding(const Value: TPaddingMode);
begin
  if (Value < Low(TPaddingMode)) or (Value > High(TPaddingMode)) then
    raise ECryptographicException.Create(sCryptography_InvalidPaddingMode);

  FPadding := Value;
end;

function TSymmetricAlgorithm.ValidKeySize(BitLength: Integer): Boolean;
var
  ValidSizes: TArray<TKeySizes>;
  I: NativeInt;
  J: Integer;
begin
  ValidSizes := FLegalKeySizes;
  if Length(ValidSizes) <= 0 then
    Exit(False);

  for I := 0 to Length(ValidSizes) - 1 do
  begin
    if ValidSizes[I].SkipSize = 0 then
    begin
      if ValidSizes[I].MinSize = BitLength then
        Exit(True);
    end
    else
    begin
      J := ValidSizes[I].MinSize;
      while J <= ValidSizes[I].MaxSize do
      begin
        if J = BitLength then
          Exit(True);
      end;
      Inc(J, ValidSizes[I].SkipSize);
    end;
  end;

  Result := False;
end;

{ TCapiSymmetricAlgorithm }

constructor TCapiSymmetricAlgorithm.Create(BlockSize, FeedbackSize: Integer; Provider: HCRYPTPROV; Key: HCRYPTKEY; IV: TBytes;
    CipherMode: TCipherMode; PaddingMode: TPaddingMode; EncryptionMode: TEncryptionMode);
begin
  inherited Create;

  Assert((0 < BlockSize) and (BlockSize mod 8 = 0));
  Assert(0 <= FeedbackSize);
  Assert(Provider <> 0);
  Assert(Key <> 0);

  FBlockSize := BlockSize;
  FEncryptionMode := EncryptionMode;
  FPaddingMode := PaddingMode;
  if CryptContextAddRef(FProvider, nil, 0) then
    FProvider := Provider
  else
    RaiseLastOSError;

  FKey := SetupKey(Key, IV, CipherMode, FeedbackSize);
end;

function TCapiSymmetricAlgorithm.DecryptBlocks(InputBuffer: TBytes; InputOffset, InputCount: Integer; out OutputBuffer: TBytes;
    OutputOffset: Integer): Integer;
var
  DecryptedBytes: Integer;
  DepadDecryptLength: Integer;
begin
  Assert(FKey <> 0);
  Assert((Length(InputBuffer) > 0) and (InputCount <= Length(InputBuffer) - InputOffset));
  Assert(InputOffset >= 0);

  DecryptedBytes := 0;

  if (FPaddingMode <> TPaddingMode.None) and (FPaddingMode <> TPaddingMode.Zeroes) then
  begin
    if Length(FDepadBuffer) > 0 then
    begin
      DepadDecryptLength := RawDecryptBlocks(FDepadBuffer, 0, Length(FDepadBuffer));
      Move(FDepadBuffer[0], OutputBuffer[OutputOffset], DepadDecryptLength);
      FillChar(FDepadBuffer[0], Length(FDepadBuffer), 0);
      Inc(OutputOffset, DepadDecryptLength);
      Inc(DecryptedBytes, DepadDecryptLength);
    end
    else
    begin
      SetLength(FDepadBuffer, InputBlockSize);
    end;

    Move(InputBuffer[InputOffset + InputCount - Length(FDepadBuffer)], FDepadBuffer[0], Length(FDepadBuffer));
    Dec(InputCount, Length(FDepadBuffer));
  end;

  if InputCount > 0 then
  begin
    Move(InputBuffer[InputOffset], OutputBuffer[OutputOffset], InputCount);
    Inc(DecryptedBytes, RawDecryptBlocks(OutputBuffer, OutputOffset, InputCount));
  end;

  Result := DecryptedBytes;
end;

function TCapiSymmetricAlgorithm.DepadBlock(Block: TBytes; Offset, Count: Integer): TBytes;
var
  PadBytes: TBytes;
begin

end;

destructor TCapiSymmetricAlgorithm.Destroy;
begin
  if FKey <> 0 then
    CryptDestroyKey(FKey);
  if FProvider <> 0 then
    CryptReleaseContext(FProvider, 0);
  if Length(FDepadBuffer) > 0 then
    FillChar(FDepadBuffer, Length(FDepadBuffer), 0);

  inherited;
end;

function TCapiSymmetricAlgorithm.GetCanReuseTransform: Boolean;
begin
  Result := True;
end;

function TCapiSymmetricAlgorithm.GetCanTransformMultipleBlocks: Boolean;
begin
  Result := True;
end;

function TCapiSymmetricAlgorithm.GetInputBlockSize: Integer;
begin
  Result := FBlockSize div 8;
end;

function TCapiSymmetricAlgorithm.GetOutputBlockSize: Integer;
begin
  Result := FBlockSize div 8;
end;

function TCapiSymmetricAlgorithm.RawDecryptBlocks(Buffer: TBytes; Offset, Count: Integer): Integer;
var
  DataLength: Cardinal;
begin
  DataLength := Count;

  Win32Check(CryptDecrypt(FKey, 0, False, 0, @(Buffer[Offset]), DataLength));

  Result := DataLength;
end;

class function TCapiSymmetricAlgorithm.SetupKey(Key: HCRYPTKEY; IV: TBytes; CipherMode: TCipherMode; FeedbackSize: Integer): HCRYPTKEY;
var
  EncryptionKey: HCRYPTKEY;
  dwData: DWORD;
begin
  Assert(Key <> 0);
  Assert((CipherMode = TCipherMode.ECB) or (Length(IV) > 0));
  Assert(0 <= FeedbackSize);

  CryptDuplicateKey(Key, nil, 0, EncryptionKey);

  dwData := DWORD(CipherMode);
  CryptSetKeyParam(EncryptionKey, KP_MODE, @(dwData), 0);

  if CipherMode <> TCipherMode.ECB then
    CryptSetKeyParam(EncryptionKey, KP_IV, @(IV[0]), 0);

  if (CipherMode = TCipherMode.CFB) or (CipherMode = TCipherMode.OFB) then
    CryptSetKeyParam(EncryptionKey, KP_MODE_BITS, @(IV[0]), 0);

  Result := EncryptionKey;
end;

function TCapiSymmetricAlgorithm.TransformBlock(InputBuffer: TBytes; InputOffset, InputCount: Integer; out OutputBuffer: TBytes;
    OutputOffset: Integer): Integer;
begin

end;

function TCapiSymmetricAlgorithm.TransformFinalBlock(InputBuffer: TBytes; InputOffset, InputCount: Integer): TBytes;
var
  OutputData: TBytes;
begin
  OutputData := nil;

  if InputBuffer = nil then
    raise EArgumentNilException.CreateFmt(SParamIsNil, ['InputBuffer']);
  if InputOffset < 0 then
    raise EArgumentOutOfRangeException.CreateFmt(SParamIsNegative, ['InputOffset']);
  if InputCount < 0 then
    raise EArgumentOutOfRangeException.CreateFmt(SParamIsNegative, ['InputCount']);
  if InputCount < Length(InputBuffer) - InputOffset then
    raise EArgumentOutOfRangeException.Create(sArgumentOutOfRange_OffLenInvalid);

end;

{ TProtectedData }

constructor TProtectedData.Create;
begin

end;

class function TProtectedData.Protect(UserData, OptionalEntropy: TBytes; Scope: TDataProtectionScope): TBytes;
var
  DataIn, DataOut, Entropy: TDataBlob;
  EntropyPtr: PDataBlob;
  dwFlags: DWORD;
begin
  Result := nil;

  if UserData = nil then
    raise EArgumentNilException.CreateFmt(SParamIsNil, ['UserData']);

  DataIn.cbData := Length(UserData);
  DataIn.pbData := @UserData[0];

  EntropyPtr := nil;
  if Length(OptionalEntropy) > 0 then
  begin
    Entropy.cbData := Length(OptionalEntropy);
    Entropy.pbData := @OptionalEntropy[0];
    EntropyPtr := @Entropy;
  end;

  dwFlags := CRYPTPROTECT_UI_FORBIDDEN;
  if Scope = TDataProtectionScope.LocalMachine then
    dwFlags := dwFlags or CRYPTPROTECT_LOCAL_MACHINE;

  FillChar(DataOut, SizeOf(TDataBlob), 0);
  try
    Win32Check(CryptProtectData(@DataIn, nil, EntropyPtr, nil, nil, dwFlags, @DataOut));
    if DataOut.pbData = nil then
      raise EOutOfMemory.Create('');
    SetLength(Result, DataOut.cbData);
    Move(PByte(DataOut.pbData)[0], Result[0], DataOut.cbData);
  finally
    if DataOut.pbData <> nil then
    begin
      ZeroMemory(DataOut.pbData, DataOut.cbData);
      LocalFree(HLOCAL(DataOut.pbData));
    end;
  end;
end;

class function TProtectedData.Unprotect(EncryptedData, OptionalEntropy: TBytes; Scope: TDataProtectionScope): TBytes;
var
  DataIn, DataOut, Entropy: TDataBlob;
  EntropyPtr: PDataBlob;
  dwFlags: DWORD;
begin
  Result := nil;

  if EncryptedData = nil then
    raise EArgumentNilException.CreateFmt(SParamIsNil, ['EncryptedData']);

  DataIn.cbData := Length(EncryptedData);
  DataIn.pbData := @EncryptedData[0];

  EntropyPtr := nil;
  if Length(OptionalEntropy) > 0 then
  begin
    Entropy.cbData := Length(OptionalEntropy);
    Entropy.pbData := @OptionalEntropy[0];
    EntropyPtr := @Entropy;
  end;

  dwFlags := CRYPTPROTECT_UI_FORBIDDEN;
  if Scope = TDataProtectionScope.LocalMachine then
    dwFlags := dwFlags or CRYPTPROTECT_LOCAL_MACHINE;

  FillChar(DataOut, SizeOf(TDataBlob), 0);
  try
    Win32Check(CryptUnprotectData(@DataIn, nil, EntropyPtr, nil, nil, dwFlags, @DataOut));
    if DataOut.pbData = nil then
      raise EOutOfMemory.Create('');
    SetLength(Result, DataOut.cbData);
    Move(PByte(DataOut.pbData)[0], Result[0], DataOut.cbData);
  finally
    if DataOut.pbData <> nil then
    begin
      ZeroMemory(DataOut.pbData, DataOut.cbData);
      LocalFree(HLOCAL(DataOut.pbData));
    end;
  end;
end;

{ TRandomNumberGenerator }

constructor TRandomNumberGenerator.Create;
begin

end;

procedure TRandomNumberGenerator.GetBytes(Data: TBytes; Offset, Count: Integer);
var
  TempData: TBytes;
begin
  if Data = nil then
    raise EArgumentNilException.CreateFmt(SParamIsNil, ['Data']);
  if Offset < 0 then
    raise EArgumentOutOfRangeException.CreateFmt(SParamIsNegative, ['Offset']);
  if Count < 0 then
    raise EArgumentOutOfRangeException.CreateFmt(SParamIsNegative, ['Count']);
  if Offset + Count > Length(Data) then
    raise EArgumentException.Create(sArgumentOutOfRange_OffLenInvalid);

  if Count > 0 then
  begin
    SetLength(TempData, Count);
    GetBytes(TempData);
    Data := Copy(TempData, Offset, Count);
  end;
end;

procedure TRandomNumberGenerator.GetNonZeroBytes(Data: TBytes);
begin
  raise ENotImplemented.Create('');
end;

{ TRNGCryptoServiceProvider }

constructor TRNGCryptoServiceProvider.Create;
begin
  inherited;

  Win32Check(CryptAcquireContext(FProvHandle, nil, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT));
end;

destructor TRNGCryptoServiceProvider.Destroy;
begin
  if FProvHandle <> 0 then
    CryptReleaseContext(FProvHandle, 0);

  inherited;
end;

procedure TRNGCryptoServiceProvider.GetBytes(Data: TBytes);
begin
  if Data = nil then
    raise EArgumentNilException.CreateFmt(SParamIsNil, ['Data']);

  Win32Check(CryptGenRandom(FProvHandle, Length(Data), @Data[0]));
end;

procedure TRNGCryptoServiceProvider.GetNonZeroBytes(Data: TBytes);
var
  IndexOfFirst0Byte: Integer;
  I: Integer;
  Tmp: TBytes;
begin
  GetBytes(Data);
  IndexOfFirst0Byte := Length(Data);
  for I := 0 to Length(Data) - 1 do
    if Data[I] = 0 then
    begin
      IndexOfFirst0Byte := I;
      Break;
    end;

  for I := IndexOfFirst0Byte to Length(Data) - 1 do
    if Data[I] <> 0 then
    begin
      Data[IndexOfFirst0Byte] := Data[I];
      Inc(IndexOfFirst0Byte);
    end;

  while IndexOfFirst0Byte < Length(Data) do
  begin
    SetLength(Tmp, 2 * (Length(Data) - IndexOfFirst0Byte));
    GetBytes(Tmp);
    for I := 0 to Length(Tmp) - 1 do
      if Tmp[I] <> 0 then
      begin
        Data[IndexOfFirst0Byte] := Tmp[I];
        Inc(IndexOfFirst0Byte);
        if IndexOfFirst0Byte >= Length(Data) then
          Break;
      end;
  end;
end;

{ TProtectedMemory }

constructor TProtectedMemory.Create;
begin

end;

class procedure TProtectedMemory.Protect(UserData: TBytes; Scope: TMemoryProtectionScope);
begin
  if UserData = nil then
    raise EArgumentNilException.CreateFmt(SParamIsNil, ['UserData']);

  TProtectedMemory.VerifyScope(Scope);

  if Length(UserData) mod CRYPTPROTECTMEMORY_BLOCK_SIZE <> 0 then
    raise ECryptographicException.Create(SCryptography_DpApi_InvalidMemoryLength);

  Win32Check(CryptProtectMemory(@UserData[0], Length(UserData), DWORD(Scope)));
end;

class procedure TProtectedMemory.Unprotect(EncryptedData: TBytes; Scope: TMemoryProtectionScope);
begin
  if EncryptedData = nil then
    raise EArgumentNilException.CreateFmt(SParamIsNil, ['EncryptedData']);

  TProtectedMemory.VerifyScope(Scope);

  if Length(EncryptedData) mod CRYPTPROTECTMEMORY_BLOCK_SIZE <> 0 then
    raise ECryptographicException.Create(SCryptography_DpApi_InvalidMemoryLength);

  Win32Check(CryptUnprotectMemory(@EncryptedData[0], Length(EncryptedData), DWORD(Scope)));
end;

class procedure TProtectedMemory.VerifyScope(Scope: TMemoryProtectionScope);
begin
  if (Scope < Low(TMemoryProtectionScope)) and (Scope > High(TMemoryProtectionScope)) then
    raise EArgumentException.Create(SArg_EnumIllegalVal);
end;


function CryptProtectData; external crypt32;
function CryptUnprotectData; external crypt32;

function CryptProtectMemory; external crypt32;
function CryptUnprotectMemory; external crypt32;


end.

