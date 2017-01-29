unit KeePassLib.BCrypt;

interface

uses
  Winapi.Windows;

const
  MS_PRIMITIVE_PROVIDER: PWideChar = 'Microsoft Primitive Provider';

  BCRYPT_SHA256_ALGORITHM: PWideChar = 'SHA256';

  BCRYPT_OBJECT_LENGTH: PWideChar = 'ObjectLength';
  BCRYPT_ALGORITHM_NAME: PWideChar = 'AlgorithmName';
  BCRYPT_PROVIDER_HANDLE: PWideChar = 'ProviderHandle';
  BCRYPT_CHAINING_MODE: PWideChar = 'ChainingMode';
  BCRYPT_BLOCK_LENGTH: PWideChar = 'BlockLength';
  BCRYPT_KEY_LENGTH: PWideChar = 'KeyLength';
  BCRYPT_KEY_OBJECT_LENGTH: PWideChar = 'KeyObjectLength';
  BCRYPT_KEY_STRENGTH: PWideChar = 'KeyStrength';
  BCRYPT_KEY_LENGTHS: PWideChar = 'KeyLengths';
  BCRYPT_BLOCK_SIZE_LIST: PWideChar = 'BlockSizeList';
  BCRYPT_EFFECTIVE_KEY_LENGTH: PWideChar = 'EffectiveKeyLength';
  BCRYPT_HASH_LENGTH: PWideChar = 'HashDigestLength';
  BCRYPT_HASH_OID_LIST: PWideChar = 'HashOIDList';
  BCRYPT_PADDING_SCHEMES: PWideChar = 'PaddingSchemes';
  BCRYPT_SIGNATURE_LENGTH: PWideChar = 'SignatureLength';
  BCRYPT_HASH_BLOCK_LENGTH: PWideChar = 'HashBlockLength';
  BCRYPT_AUTH_TAG_LENGTH: PWideChar = 'AuthTagLength';
  BCRYPT_PRIMITIVE_TYPE: PWideChar = 'PrimitiveType';
  BCRYPT_IS_KEYED_HASH: PWideChar = 'IsKeyedHash';

type
  BCRYPT_ALG_HANDLE = PVOID;
  BCRYPT_HANDLE     = PVOID;
  TBCryptAlgHandle  = BCRYPT_ALG_HANDLE;
  TBCryptHandle     = BCRYPT_HANDLE;

function BCryptOpenAlgorithmProvider(out hAlgorithm: TBCryptAlgHandle;
  const pszAlgId: PWideChar; const pszImplementation: PWideChar; dwFlags: DWORD): LONG; stdcall;
function BCryptCloseAlgorithmProvider(var hAlgorithm: TBCryptAlgHandle;
  dwFlags: ULONG): LONG; stdcall;
function BCryptGetProperty(hObject: TBCryptHandle;
  const pszProperty: PWideChar; pbOutput: PUCHAR; cbOutput: ULONG;
  out cbResult: ULONG; dwFlags: ULONG): LONG; stdcall;

implementation

const
  bcryptdll = 'Bcrypt.dll';


function BCryptOpenAlgorithmProvider; external bcryptdll;
function BCryptCloseAlgorithmProvider; external bcryptdll;
function BCryptGetProperty; external bcryptdll;

end.
