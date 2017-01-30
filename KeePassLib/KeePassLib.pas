unit KeePassLib;

{$SCOPEDENUMS ON}
{$WARN SYMBOL_PLATFORM OFF}

interface

uses
  Winapi.Windows, System.Types, System.SysUtils, System.Classes, System.Hash,
  Vcl.Dialogs, System.UITypes, System.Generics.Collections;

const
  DefaultTransformRounds = 6000;

resourcestring
  SFailedToParseKeePassXml = 'Failed to parse KeePass XML.';

type
  EKdbxError = class(Exception);
  EKdbxPasswordError = class(EKdbxError);

  TPwCompressionAlgorithm = (None, GZip);

  TCrsAlgorithm = (None, ArcFourVariant, Salsa20);

  TMemoryProtectionMode = (ProtectTitle, ProtectUserName, ProtectPassword, ProtectURL, ProtectNotes);

  TMemoryProtection = set of TMemoryProtectionMode;

  TKdbxFile = class
  private
    FStream: TStream;
    FOwnsStream: Boolean;
    FDataCipherUuid: TGUID;
    FCompressionAlgorithm: TPwCompressionAlgorithm;
    FMasterSeed: TBytes;
    FTransformSeed: TBytes;
    FTransformRounds: UInt64;
    FEncryptionIV: TBytes;
    FProtectedStreamKey: TBytes;
    FStreamStartBytes: TBytes;
    FInnerRandomStreamID: UInt32;
    FHashOfHeader: TBytes;
    FGenerator: string;
    FName: string;
    FNameChanged: TDateTime;
    FDescription: TStringList;
    FDescriptionChanged: TDateTime;
    FDefaultUserName: string;
    FDefaultUsernameChanged: TDateTime;
    FMaintenanceHistoryDays: Cardinal;
    FColor: TColor;
    FMasterKeyChanged: TDateTime;
    FMasterKeyChangeRec: Int64;
    FMasterKeyChangeForce: Int64;
    FMemoryProtection: TMemoryProtection;
    FCustomIcons: TObjectDictionary<TGUID, TStream>;
    FRecycleBinEnabled: Boolean;
    FRecycleBinUUID: TGUID;
    FRecycleBinChanged: TDateTime;
    FEntryTemplatesGroup: TGUID;
    FEntryTemplatesGroupChanged: TDateTime;
    FHistoryMaxItems: Integer;
    FHistoryMaxSize: Int64;
    FLastSelectedGroup: TGUID;
    FLastTopVisibleGroup: TGUID;
    FCustomData: TDictionary<string, string>;
    FIsOpen: Boolean;
    function GetGenerator: string;
    procedure SetGenerator(const Value: string);
    function GetName: string;
    procedure SetName(const Value: string);
    function GetNameChanged: TDateTime;
    function GetDescription: TStringList;
    function GetDescriptionChanged: TDateTime;
    procedure OnDescriptionChanged(Sender: TObject);
    function GetDefaultUserName: string;
    procedure SetDefaultUserName(const Value: string);
    function GetDefaultUsernameChanged: TDateTime;
    function GetMaintenanceHistoryDays: Cardinal;
    procedure SetMaintenanceHistoryDays(const Value: Cardinal);
    function GetColor: TColor;
    procedure SetColor(const Value: TColor);
    function GetMasterKeyChanged: TDateTime;
    function GetMasterKeyChangeRec: Int64;
    procedure SetMasterKeyChangeRec(const Value: Int64);
    function GetMasterKeyChangeForce: Int64;
    procedure SetMasterKeyChangeForce(const Value: Int64);
    function GetMemoryProtection: TMemoryProtection;
    procedure SetMemoryProtection(const Value: TMemoryProtection);
    function GetCustomIcons: TObjectDictionary<TGUID, TStream>;
    function GetRecycleBinEnabled: Boolean;
    procedure SetRecycleBinEnabled(const Value: Boolean);
    function GetRecycleBinUUID: TGUID;
    procedure SetRecycleBinUUID(const Value: TGUID);
    function GetRecycleBinChanged: TDateTime;
    function GetEntryTemplatesGroup: TGUID;
    procedure SetEntryTemplatesGroup(const Value: TGUID);
    function GetEntryTemplatesGroupChanged: TDateTime;
    function GetHistoryMaxItems: Integer;
    procedure SetHistoryMaxItems(const Value: Integer);
    function GetHistoryMaxSize: Int64;
    procedure SetHistoryMaxSize(const Value: Int64);
    function GetLastSelectedGroup: TGUID;
    procedure SetLastSelectedGroup(const Value: TGUID);
    function GetLastTopVisibleGroup: TGUID;
    procedure SetLastTopVisibleGroup(const Value: TGUID);
    function GetCustomData: TDictionary<string, string>;

    procedure ReadHeader;
    function ReadHeaderField: Boolean;
    function GetCompositeKey(const APassword: string): TBytes;
    function TransformKey(const CompositeKey: TBytes; Seed: TBytes; Rounds: UInt64): TBytes;
    function GetMasterKey(const MasterSeed: TBytes; const TransformedKey: TBytes): TBytes;
    function DecryptDataStream(const AMasterKey: TBytes): TStream;
    function GetSHA256WinCrypt(const Data: TBytes): TBytes;
    procedure Deserialize(const Stream: TStream);
    function GetIsOpen: Boolean;

  public
    property Generator: string read GetGenerator write SetGenerator;
    property Name: string read GetName write SetName;
    property NameChanged: TDateTime read GetNameChanged;
    property Description: TStringList read GetDescription;
    property DescriptionChanged: TDateTime read GetDescriptionChanged;
    property DefaultUserName: string read GetDefaultUserName write SetDefaultUserName;
    property DefaultUsernameChanged: TDateTime read GetDefaultUsernameChanged;
    property MaintenanceHistoryDays: Cardinal read GetMaintenanceHistoryDays write SetMaintenanceHistoryDays;
    property Color: TColor read GetColor write SetColor;
    property MasterKeyChanged: TDateTime read GetMasterKeyChanged;
    property MasterKeyChangeRec: Int64 read GetMasterKeyChangeRec write SetMasterKeyChangeRec;
    property MasterKeyChangeForce: Int64 read GetMasterKeyChangeForce write SetMasterKeyChangeForce;
    property TMemoryProtection: TMemoryProtection read GetMemoryProtection write SetMemoryProtection;
    property CustomIcons: TObjectDictionary<TGUID, TStream> read GetCustomIcons;
    property RecycleBinEnabled: Boolean read GetRecycleBinEnabled write SetRecycleBinEnabled;
    property RecycleBinUUID: TGUID read GetRecycleBinUUID write SetRecycleBinUUID;
    property RecycleBinChanged: TDateTime read GetRecycleBinChanged;
    property EntryTemplatesGroup: TGUID read GetEntryTemplatesGroup write SetEntryTemplatesGroup;
    property EntryTemplatesGroupChanged: TDateTime read GetEntryTemplatesGroupChanged;
    property HistoryMaxItems: Integer read GetHistoryMaxItems write SetHistoryMaxItems;
    property HistoryMaxSize: Int64 read GetHistoryMaxSize write SetHistoryMaxSize;
    property LastSelectedGroup: TGUID read GetLastSelectedGroup write SetLastSelectedGroup;
    property LastTopVisibleGroup: TGUID read GetLastTopVisibleGroup write SetLastTopVisibleGroup;
    property CustomData: TDictionary<string, string> read GetCustomData;

    property IsOpen: Boolean read GetIsOpen;

    constructor Create; overload;
    constructor Create(const APassword: string; Stream: TStream; AOwnsStream: Boolean = False); overload;
    procedure LoadFromStream(const APassword: string; Stream: TStream; AOwnsStream: Boolean = True);
    procedure LoadFromFile(const APassword: string; const FileName: string; AOwnStream: Boolean = True);
    procedure Close;
    function GetSHA256(const Data: TBytes): TBytes;
    destructor Destroy; override;
  end;

implementation

uses
  idGlobal, idHashSha, idZLib, KeePassLib.Wincrypt, System.Security.Cryptography,
  Xml.XmlDoc, Xml.XmlDom, Xml.XmlIntf, System.Variants, System.DateUtils,
  Vcl.GraphUtil, System.NetEncoding, System.StrUtils;

const
  kfEndOfHeader = 0;
	kfComment = 1;
	kfCipherID = 2;
	kfCompressionFlags = 3;
	kfMasterSeed = 4;
	kfTransformSeed = 5;
	kfTransformRounds = 6;
	kfEncryptionIV = 7;
	kfProtectedStreamKey = 8;
	kfStreamStartBytes = 9;
	kfInnerRandomStreamID = 10;

type
  TAes256KeyBlob = record
    Header  : TBlobHeader;
    KeySize : DWORD;
    KeyData : array[0..31] of Byte;
  end;

  TKdbxPayloadAreaBlockHeader = packed record
    ID      : DWORD;
    Hash    : packed array[0..31] of Byte;
    Size    : DWORD;
  end;

{ TKdbxFile }

procedure TKdbxFile.Close;
var
  NowDate: TDateTime;
begin
  FIsOpen := False;

  NowDate := Now;

  if FOwnsStream then
    FreeAndNil(FStream);
  FOwnsStream := False;

  FDataCipherUuid := TGUID.Empty;
  FCompressionAlgorithm := TPwCompressionAlgorithm.None;

  FillChar(FMasterSeed, Length(FMasterSeed), 0);
  FMasterSeed := nil;

  FillChar(FTransformSeed, Length(FTransformSeed), 0);
  FTransformSeed := nil;

  FTransformRounds := 6000;

  FillChar(FEncryptionIV, Length(FEncryptionIV), 0);
  FEncryptionIV := nil;

  FillChar(FProtectedStreamKey, Length(FProtectedStreamKey), 0);
  FProtectedStreamKey := nil;

  FillChar(FStreamStartBytes, Length(FStreamStartBytes), 0);
  FStreamStartBytes := nil;

  FInnerRandomStreamID := 0;

  FillChar(FHashOfHeader, Length(FHashOfHeader), 0);
  FHashOfHeader := nil;

  FGenerator := '';
  FName := '';
  FNameChanged := NowDate;
  FDescription.Clear;
  FDescriptionChanged := NowDate;
  FDefaultUserName := '';
  FDefaultUsernameChanged := NowDate;
  FMaintenanceHistoryDays := 365;
  FColor := 0;
  FMasterKeyChanged := NowDate;
  FMasterKeyChangeRec := -1;
  FMasterKeyChangeForce := -1;
  FMemoryProtection := [TMemoryProtectionMode.ProtectPassword];
  FCustomIcons.Clear;
  FRecycleBinEnabled := True;
  FRecycleBinUUID := TGUID.Empty;
  FRecycleBinChanged := NowDate;
  FEntryTemplatesGroup := TGUID.Empty;
  FEntryTemplatesGroupChanged := NowDate;
  FHistoryMaxItems := -1;
  FHistoryMaxSize := -1;
  FLastSelectedGroup := TGUID.Empty;
  FLastTopVisibleGroup := TGUID.Empty;
  FCustomData.Clear;
end;

constructor TKdbxFile.Create;
var
  DataStream      : TStream;
  CreationTime    : TDateTime;
begin
  inherited;

  CreationTime := Now;
  FNameChanged := CreationTime;
  FDescription := TStringList.Create;
  FDescription.OnChange := OnDescriptionChanged;
  FCustomIcons := TObjectDictionary<TGUID, TStream>.Create;
  FCustomData := TDictionary<string, string>.Create;

  DataStream := nil;
end;

constructor TKdbxFile.Create(const APassword: string; Stream: TStream; AOwnsStream: Boolean);
begin
  Create;

  LoadFromStream(APassword, Stream, AOwnsStream);
end;

procedure TKdbxFile.Deserialize(const Stream: TStream);

  /// <summary>
  ///   Checks is given string is valid web color.
  /// </summary>
  function IsWebColorString(const WebColor: string): Boolean;
  var
    I: Integer;
  begin
    Result := False;

    if (Length(WebColor) < 6) or (Length(WebColor) > 7) then
      Exit;
    for I := 1 to Length(WebColor) do
      if not CharInSet(WebColor[I], ['#', 'a'..'f', 'A'..'F', '0'..'9']) then
        Exit;

    Result := True;
  end;


var
  Xml: IXMLDocument;
  Root: IXMLNode;
  Meta: IXMLNode;
  MemoryProtectionNode: IXMLNode;
  vColor: OleVariant;
  OldNullStrictConvert: Boolean;
begin
  Xml := TXMLDocument.Create(nil);
  Xml.LoadFromStream(Stream);
  Root := Xml.DocumentElement;
  Meta := Root.ChildNodes['Meta'];
  if (Meta = nil) or (Meta.NodeName <> 'Meta') then
    raise EKdbxError.Create(SFailedToParseKeePassXml);

  OldNullStrictConvert := NullStrictConvert;
  try
    // To avoid exceptions when OleVariant value is Null.
    NullStrictConvert := False;

    Generator := Meta.ChildValues['Generator'];
    FName := Meta.ChildValues['DatabaseName'];
    FNameChanged := ISO8601ToDate(Meta.ChildValues['DatabaseNameChanged']);
    FDescription.Text := Meta.ChildValues['DatabaseDescription'];
    FDescriptionChanged := ISO8601ToDate(Meta.ChildValues['DatabaseDescriptionChanged']);
    FDefaultUserName := Meta.ChildValues['DefaultUserName'];
    FDefaultUsernameChanged := ISO8601ToDate(Meta.ChildValues['DefaultUserNameChanged']);
    FMaintenanceHistoryDays := StrToUInt64Def(Meta.ChildValues['MaintenanceHistoryDays'], 365);
    vColor := Meta.ChildValues['Color'];
    // To avoid exception when string is empty or in invalid format
    if IsWebColorString(vColor) then
      FColor := WebColorStrToColor(vColor);

    FMasterKeyChanged := ISO8601ToDate(Meta.ChildValues['MasterKeyChanged']);
    FMasterKeyChangeRec := StrToIntDef(Meta.ChildValues['MasterKeyChanged'], -1);
    FMasterKeyChangeForce := StrToInt64Def(Meta.ChildValues['MasterKeyChangeForce'], -1);

    MemoryProtectionNode := Meta.ChildNodes['MemoryProtection'];
    if MemoryProtectionNode <> nil then
    begin
      if StrToBoolDef(MemoryProtectionNode.ChildValues['ProtectTitle'], False) then
        Include(FMemoryProtection, TMemoryProtectionMode.ProtectTitle);
      if StrToBoolDef(MemoryProtectionNode.ChildValues['ProtectUserName'], False) then
        Include(FMemoryProtection, TMemoryProtectionMode.ProtectUserName);
      if StrToBoolDef(MemoryProtectionNode.ChildValues['ProtectPassword'], True) then
        Include(FMemoryProtection, TMemoryProtectionMode.ProtectPassword);
      if StrToBoolDef(MemoryProtectionNode.ChildValues['ProtectURL'], False) then
        Include(FMemoryProtection, TMemoryProtectionMode.ProtectURL);
      if StrToBoolDef(MemoryProtectionNode.ChildValues['ProtectNotes'], False) then
        Include(FMemoryProtection, TMemoryProtectionMode.ProtectNotes);
    end;
    MemoryProtectionNode := nil;

    FRecycleBinEnabled := StrToBoolDef(Meta.ChildValues['RecycleBinEnabled'], True);
    FRecycleBinUUID := TGUID.Create(TNetEncoding.Base64.DecodeStringToBytes(Meta.ChildValues['RecycleBinUUID']));
    FRecycleBinChanged := ISO8601ToDate(Meta.ChildValues['RecycleBinChanged']);
    FEntryTemplatesGroup := TGUID.Create(TNetEncoding.Base64.DecodeStringToBytes(Meta.ChildValues['EntryTemplatesGroup']));
    FEntryTemplatesGroupChanged := ISO8601ToDate(Meta.ChildValues['EntryTemplatesGroupChanged']);
    FHistoryMaxItems := StrToIntDef(Meta.ChildValues['HistoryMaxItems'], -1);
    FHistoryMaxSize := StrToIntDef(Meta.ChildValues['HistoryMaxSize'], -1);
    FLastSelectedGroup := TGUID.Create(TNetEncoding.Base64.DecodeStringToBytes(Meta.ChildValues['LastSelectedGroup']));
    FLastTopVisibleGroup := TGUID.Create(TNetEncoding.Base64.DecodeStringToBytes(Meta.ChildValues['LastTopVisibleGroup']));
  finally
    NullStrictConvert := OldNullStrictConvert;
  end;
end;

destructor TKdbxFile.Destroy;
begin
  FDescription.Free;
  FCustomIcons.Free;
  FCustomData.Free;

  if FOwnsStream then
    FStream.Free;

  inherited;
end;

function TKdbxFile.GetColor: TColor;
begin
  Result := FColor;
end;

function TKdbxFile.GetCompositeKey(const APassword: string): TBytes;
var
  PasswordUTF8Bytes: TBytes;
  PasswordHash  : TBytes;
  Sha256: TSHA256CryptoServiceProvider;
begin
  // Calculate hash of password
  PasswordUTF8Bytes := TEncoding.UTF8.GetBytes(APassword);

  Sha256 := TSHA256CryptoServiceProvider.Create;
  try
    PasswordHash := Sha256.ComputeHash(PasswordUTF8Bytes);
    Result := Sha256.ComputeHash(PasswordHash);
  finally
    Sha256.Free;
  end;
end;

function TKdbxFile.GetCustomData: TDictionary<string, string>;
begin
  Result := FCustomData;
end;

function TKdbxFile.GetCustomIcons: TObjectDictionary<TGUID, TStream>;
begin
  Result := FCustomIcons;
end;

function TKdbxFile.GetDefaultUserName: string;
begin
  Result := FDefaultUserName;
end;

function TKdbxFile.GetDefaultUsernameChanged: TDateTime;
begin
  Result := FDefaultUsernameChanged;
end;

function TKdbxFile.GetDescription: TStringList;
begin
  Result := FDescription;
end;

function TKdbxFile.GetDescriptionChanged: TDateTime;
begin
  Result := FDescriptionChanged;
end;

function TKdbxFile.GetEntryTemplatesGroup: TGUID;
begin
  Result := FEntryTemplatesGroup;
end;

function TKdbxFile.GetEntryTemplatesGroupChanged: TDateTime;
begin
  Result := FEntryTemplatesGroupChanged;
end;

function TKdbxFile.GetGenerator: string;
begin
  Result := FGenerator;
end;

function TKdbxFile.GetHistoryMaxItems: Integer;
begin
  Result := FHistoryMaxItems;
end;

function TKdbxFile.GetHistoryMaxSize: Int64;
begin
  Result := FHistoryMaxSize;
end;

function TKdbxFile.GetIsOpen: Boolean;
begin
  Result := FIsOpen;
end;

function TKdbxFile.GetLastSelectedGroup: TGUID;
begin
  Result := FLastSelectedGroup;
end;

function TKdbxFile.GetLastTopVisibleGroup: TGUID;
begin
  Result := FLastTopVisibleGroup;
end;

function TKdbxFile.GetMaintenanceHistoryDays: Cardinal;
begin
  Result := FMaintenanceHistoryDays;
end;

function TKdbxFile.GetMasterKey(const MasterSeed,
  TransformedKey: TBytes): TBytes;
var
  ConcatKey : TBytes;
  Sha256: TSHA256CryptoServiceProvider;
begin
  if not Assigned(TransformedKey) then
    raise EKdbxError.Create('');
  if not Assigned(MasterSeed) then
    raise EKdbxError.Create('');
  if Length(TransformedKey) <> 32 then
    raise EKdbxError.Create('');
  if Length(MasterSeed) <> 32 then
    raise EKdbxError.Create('');

  ConcatKey := TransformedKey + MasterSeed;


  Result := nil;

  Sha256 := TSHA256CryptoServiceProvider.Create;
  try
    Result := Sha256.ComputeHash(ConcatKey);
  finally
    Sha256.Free;
  end;
end;

function TKdbxFile.GetMasterKeyChanged: TDateTime;
begin
  Result := FMasterKeyChanged;
end;

function TKdbxFile.GetMasterKeyChangeForce: Int64;
begin
  Result := FMasterKeyChangeForce;
end;

function TKdbxFile.GetMasterKeyChangeRec: Int64;
begin
  Result := FMasterKeyChangeRec;
end;

function TKdbxFile.GetName: string;
begin
  Result := FName;
end;

function TKdbxFile.GetNameChanged: TDateTime;
begin
  Result := FNameChanged;
end;

function TKdbxFile.GetRecycleBinChanged: TDateTime;
begin
  Result := FRecycleBinChanged;
end;

function TKdbxFile.GetRecycleBinEnabled: Boolean;
begin
  Result := FRecycleBinEnabled;
end;

function TKdbxFile.GetRecycleBinUUID: TGUID;
begin
  Result := FRecycleBinUUID;
end;

function TKdbxFile.GetSHA256(const Data: TBytes): TBytes;
begin
  Result := GetSHA256WinCrypt(Data);
end;

function TKdbxFile.GetSHA256WinCrypt(const Data: TBytes): TBytes;
var
  hProv     : HCRYPTPROV;
  hHash     : HCRYPTHASH;
  dwDataLen : DWORD;
  dwHashSize: DWORD;
begin
  Result := nil;

  try
      Win32Check(CryptAcquireContext(hProv, nil, nil, PROV_RSA_AES, CRYPT_VERIFYCONTEXT));
      Win32Check(CryptCreateHash(hProv, CALG_SHA_256, 0, 0, hHash));
      dwDataLen := Length(Data);
      Win32Check(CryptHashData(hHash, Data[0], dwDataLen, 0));
    try
      dwDataLen := SizeOf(DWORD);
      Win32Check(CryptGetHashParam(hHash, HP_HASHSIZE, dwHashSize, dwDataLen, 0));
      SetLength(Result, dwHashSize);
      Win32Check(CryptGetHashParam(hHash, HP_HASHVAL, Result[0], dwHashSize, 0));
    except
      Result := nil;
    end;
  finally
    if hHash <> 0 then
      CryptDestroyHash(hHash);
    if hProv <> 0 then
      CryptReleaseContext(hProv, 0);
  end;
end;

procedure TKdbxFile.LoadFromFile(const APassword, FileName: string;
  AOwnStream: Boolean);
var
  FS: TFileStream;
begin
  Close;
  FS := TFileStream.Create(FileName, fmOpenRead);
  LoadFromStream(APassword, FS, True);
end;

procedure TKdbxFile.LoadFromStream(const APassword: string; Stream: TStream;
  AOwnsStream: Boolean);
var
  CompositeKey    : TBytes;
  TransformedKey  : TBytes;
  MasterKey       : TBytes;
  DataStream      : TStream;
begin
  try
    Close;
    DataStream := nil;

    if not Assigned(Stream) then
      raise EArgumentNilException.Create('Input stream is nil!');

    FStream := Stream;
    FOwnsStream := AOwnsStream;

    if APassword = '' then
      raise EKdbxPasswordError.Create('Password is empty!');

    CompositeKey := GetCompositeKey(APassword);

    ReadHeader;

    TransformedKey := TransformKey(CompositeKey, FTransformSeed, FTransformRounds);

    MasterKey := GetMasterKey(TransformedKey, FMasterSeed);

    try
      DataStream := DecryptDataStream(MasterKey);

      Deserialize(DataStream);
    finally
      DataStream.Free;
    end;

    FIsOpen := True;

  except
    Close;
    raise;
  end;
end;

function TKdbxFile.GetMemoryProtection: TMemoryProtection;
begin
  Result := FMemoryProtection;
end;

procedure TKdbxFile.OnDescriptionChanged(Sender: TObject);
begin
  FDescriptionChanged := Now;
end;

procedure TKdbxFile.ReadHeader;
const
  // File identifier, first 32-bit value.
  FileSignature1 = $9AA2D903;
  // File identifier, second 32-bit value.
  FileSignature2 = $B54BFB67;
  // KeePass 1.x signature
  FileSignatureOld1 = $9AA2D903;
  FileSignatureOld2 = $B54BFB65;
  // KeePass 2.x pre-release (alpha and beta) signature
  FileSignaturePreRelease1 = $9AA2D903;
  FileSignaturePreRelease2 = $B54BFB66;

  FileVersion32 = $00030001;
  FileVersionCriticalMask = $FFFF0000;
var
  Sig1, Sig2: UInt32;
  BytesRead: Longint;
  Version: UInt32;
  HeaderSize: Int64;
  Sha256: TIdHashSHA256;
  Sha256Bytes: TIdBytes;
begin
  Assert(Assigned(FStream));

  BytesRead := FStream.Read(Sig1, SizeOf(Sig1));
  if BytesRead <> SizeOf(Sig1) then
    raise EKdbxError.Create('Kdbx file header parse error: Sig1 field size <> 4 bytes.');
  BytesRead := FStream.Read(Sig2, SizeOf(Sig2));
  if BytesRead <> SizeOf(Sig2) then
    raise EKdbxError.Create('Kdbx file header parse error: Sig2 field size <> 4 bytes.');


  // Check if Kdbx file is of unsupported 1.x version
  if (Sig1 = FileSignatureOld1) and (Sig2 = FileSignatureOld2) then
    raise EKdbxError.Create('KeePass 1.x files are not supported.');

  // Check if Kdbx is supported 2.x
  if ((Sig1 = FileSignature1) and (Sig2 = FileSignature2)) or
      ((Sig1 = FileSignaturePreRelease1) and (Sig2 = FileSignaturePreRelease2)) then
  begin
  end
  else
  begin
    raise EKdbxError.Create('File is not valid KeePass 2.x file');
  end;

  // Check version
  BytesRead := FStream.Read(Version, SizeOf(Version));
  if BytesRead <> SizeOf(Version) then
    raise EKdbxError.Create('Kdbx file header parse error: Version field size <> 4 bytes.');
  if (Version and FileVersionCriticalMask) > (FileVersion32 and FileVersionCriticalMask) then
    raise EKdbxError.Create('Unsupported KeePass 2.x file.');

  while ReadHeaderField do
  begin

  end;

  // Calculate header hash

  HeaderSize := FStream.Position;
  Sha256 := nil;
  try
    Sha256 := TIdHashSHA256.Create;
    Sha256Bytes := Sha256.HashStream(FStream, 0, HeaderSize);
    // Stupid TIdBytes...
    SetLength(FHashOfHeader, Length(Sha256Bytes));
    Move(Sha256Bytes, FHashOfHeader, Length(Sha256Bytes));
    FStream.Position := HeaderSize;

  finally
    Sha256.Free;
  end;

end;

function TKdbxFile.ReadHeaderField: Boolean;
var
  BytesRead: LongInt;
  FieldID: Byte;
  FieldSize: Word;
  FieldData: TBytes;
begin
  BytesRead := FStream.Read(FieldID, SizeOf(FieldID));
  if BytesRead <> SizeOf(FieldID) then
    raise EKdbxError.Create('Kdbx file header parse error: field ID read failed.');
  BytesRead := FStream.Read(FieldSize, SizeOf(FieldSize));
  if BytesRead <> SizeOf(FieldSize) then
    raise EKdbxError.Create('Kdbx file header parse error: field size read failed.');
  SetLength(FieldData, FieldSize);
  BytesRead := FStream.Read(FieldData[0], FieldSize);
  if BytesRead <> FieldSize then
    raise EKdbxError.Create('Kdbx file header parse error: field data read failed.');

  Result := True;
  case FieldID of
    kfEndOfHeader:
    begin
      Result := False;
    end;
    kfCipherID:
    begin
      FDataCipherUuid := TGUID.Create(FieldData);
    end;
    kfCompressionFlags:
    begin
      if FieldSize <> 4 then
        raise EKdbxError.Create('Kdbx file header parse error: CompressionAlgorithm field size <> 4 bytes.');
      case FieldData[0] of
        0: FCompressionAlgorithm := TPwCompressionAlgorithm.None;
        1: FCompressionAlgorithm := TPwCompressionAlgorithm.GZip;
      else
        raise EKdbxError.Create('Kdbx file header parse error: unknown compression algorithm.');
      end;
    end;
    kfMasterSeed:
    begin
      FMasterSeed := Copy(FieldData, 0, FieldSize);
    end;
    kfTransformSeed:
    begin
      FTransformSeed := Copy(FieldData, 0, FieldSize);
    end;
    kfTransformRounds:
    begin
      if FieldSize <> SizeOf(FTransformRounds) then
        raise EKdbxError.Create('Kdbx file header parse error: TransformRounds field size <> 4 bytes.');
      Move(FieldData[0], FTransformRounds, SizeOf(FTransformRounds));
    end;
    kfEncryptionIV:
    begin
      FEncryptionIV := Copy(FieldData, 0, FieldSize);
    end;
    kfProtectedStreamKey:
    begin
      FProtectedStreamKey := Copy(FieldData, 0, FieldSize);
    end;
    kfStreamStartBytes:
    begin
      FStreamStartBytes := Copy(FieldData, 0, FieldSize);
    end;
    kfInnerRandomStreamID:
    begin
      if FieldSize <> 4 then
        raise EKdbxError.Create('Kdbx file header parse error: InnerRandomStreamID field size <> 4 bytes.');
      Move(FieldData[0], FInnerRandomStreamID, SizeOf(FInnerRandomStreamID));
    end
    else
    // Unknown, but correct fields?
    begin
    end;
  end;
end;

procedure TKdbxFile.SetColor(const Value: TColor);
begin
  FColor := Value;
end;

procedure TKdbxFile.SetDefaultUserName(const Value: string);
begin
  if Value <> FDefaultUserName then
  begin
    FDefaultUserName := Value;
    FDefaultUsernameChanged := Now;
  end;
end;

procedure TKdbxFile.SetEntryTemplatesGroup(const Value: TGUID);
begin
  FEntryTemplatesGroup := Value;
end;

procedure TKdbxFile.SetGenerator(const Value: string);
begin
  FGenerator := Value;
end;

procedure TKdbxFile.SetHistoryMaxItems(const Value: Integer);
begin
  FHistoryMaxItems := Value;
end;

procedure TKdbxFile.SetHistoryMaxSize(const Value: Int64);
begin
  FHistoryMaxSize := Value;
end;

procedure TKdbxFile.SetLastSelectedGroup(const Value: TGUID);
begin
  FLastSelectedGroup := Value;
end;

procedure TKdbxFile.SetLastTopVisibleGroup(const Value: TGUID);
begin
  FLastTopVisibleGroup := Value;
end;

procedure TKdbxFile.SetMaintenanceHistoryDays(const Value: Cardinal);
begin
  FMaintenanceHistoryDays := Value;
end;

procedure TKdbxFile.SetMasterKeyChangeForce(const Value: Int64);
begin
  FMasterKeyChangeForce := Value;
end;

procedure TKdbxFile.SetMasterKeyChangeRec(const Value: Int64);
begin
  FMasterKeyChangeRec := Value;
end;

procedure TKdbxFile.SetName(const Value: string);
begin
  if Value <> FName then
  begin
    FName := Value;
    FNameChanged := Now;
  end;
end;

procedure TKdbxFile.SetRecycleBinEnabled(const Value: Boolean);
begin
  FRecycleBinEnabled := Value;
end;

procedure TKdbxFile.SetRecycleBinUUID(const Value: TGUID);
begin
  FRecycleBinUUID := Value;
end;

procedure TKdbxFile.SetMemoryProtection(const Value: TMemoryProtection);
begin
  FMemoryProtection := Value;
end;

function TKdbxFile.DecryptDataStream(const AMasterKey: TBytes): TStream;

  function DecryptPayloadArea(const InputStream: TStream; hKey: HCRYPTKEY): TMemoryStream;
  var
    DecryptedStream: TMemoryStream;
    BytesRead      : DWORD;
    ReadBuffer     : packed array[0..65536 - 1] of Byte;
  begin
    Assert(InputStream <> nil);
    Assert(hKey <> 0);

    Result := nil;

    DecryptedStream := TMemoryStream.Create;
    try
      while True do
      begin
        BytesRead := InputStream.Read(ReadBuffer[0], SizeOf(ReadBuffer));
        if BytesRead = 0 then
          Break;

        if BytesRead = SizeOf(ReadBuffer) then
          Win32Check(CryptDecrypt(hKey, 0, False, 0, ReadBuffer[0], BytesRead))
        else
          Win32Check(CryptDecrypt(hKey, 0, True, 0, ReadBuffer[0], BytesRead));

        DecryptedStream.Write(ReadBuffer[0], BytesRead);
      end;

      DecryptedStream.Position := 0;
      Result := DecryptedStream;
    except
      DecryptedStream.Free;
    end;
  end;

  function DecompressPayloadArea(const InputStream: TStream): TMemoryStream;
  var
    MemoryStream: TMemoryStream;
  begin
    Assert(InputStream <> nil);

    if InputStream.Position <> 0 then
      InputStream.Position := 0;

    MemoryStream := TMemoryStream.Create;
    try
      DecompressStream(InputStream, MemoryStream);
      Result := MemoryStream;
    except
      MemoryStream.Free;
      Result := nil;
    end;
  end;

var
  hProv             : HCRYPTPROV;
  hKey              : HCRYPTKEY;
  KeyBlob           : TAes256KeyBlob;
  BlockHeader       : TKdbxPayloadAreaBlockHeader;
  AesMode           : DWORD;

  BytesRead         : DWORD;
  ReadBuffer        : packed array[0..65536 - 1] of Byte;
  I                 : NativeInt;
  StartBytes        : TBytes;
  StartBytesFail    : Boolean;
  DecryptedStream   : TMemoryStream;
  BlockData         : TBytes;
  BlockDataHash     : TBytes;
  DeblockedStream   : TMemoryStream;
  DecompressedStream: TMemoryStream;
begin
  Result := nil;

  try
    Win32Check(CryptAcquireContext(hProv, nil, nil, PROV_RSA_AES, CRYPT_VERIFYCONTEXT));
    FillChar(KeyBlob, SizeOf(TAes256KeyBlob), 0);
    KeyBlob.Header.bType    := PLAINTEXTKEYBLOB;
    KeyBlob.Header.bVersion := CUR_BLOB_VERSION;
    KeyBlob.Header.aiKeyAlg := CALG_AES_256;
    KeyBlob.KeySize := 32;
    Move(AMasterKey[0], KeyBlob.KeyData[0], 32);
    FillChar(AMasterKey[0], Length(AMasterKey), 0);
    Win32Check(CryptImportKey(hProv, KeyBlob, SizeOf(TAes256KeyBlob), 0, 0, hKey));

    Win32Check(CryptSetKeyParam(hKey, KP_IV, FEncryptionIV[0], 0));
    AesMode := CRYPT_MODE_CBC;
    Win32Check(CryptSetKeyParam(hKey, KP_MODE, AesMode, 0));

    // check pattern
    SetLength(StartBytes, Length(FStreamStartBytes));
    BytesRead := FStream.Read(ReadBuffer[0], Length(StartBytes));
    Win32Check(CryptDecrypt(hKey, 0, False, 0, ReadBuffer[0], BytesRead));
    Move(ReadBuffer[0], StartBytes[0], Length(StartBytes));

    StartBytesFail := False;
    for I := 0 to Length(StartBytes) - 1 do
      if FStreamStartBytes[I] <> ReadBuffer[I] then
      begin
        StartBytesFail := True;
        Break;
      end;
    if StartBytesFail then
      raise EKdbxPasswordError.Create('Password incorrect!');

    // Decrypting data
    DecryptedStream := nil;
    try
      DecryptedStream := DecryptPayloadArea(FStream, hKey);
      if DecryptedStream = nil then
        raise EKdbxError.Create('Failed to decrypt data!');

      // Now data is decrypted, but splitted to blocks
      // We must check block header of TKdbxPayloadAreaBlockHeader type, get
      // its length compare its hash and copy to Deblocked stream.
      DeblockedStream := nil;
      try
        DeblockedStream := TMemoryStream.Create;

        while True do
        begin
          BytesRead := DecryptedStream.Read(BlockHeader, SizeOf(BlockHeader));
          // Final block with data size = 0
          if BlockHeader.Size = 0 then
            Break;

          // Read block data
          SetLength(BlockData, BlockHeader.Size);
          BytesRead := DecryptedStream.Read(BlockData, BlockHeader.Size);

          // Check block hash
          BlockDataHash := GetSHA256(BlockData);
          if not CompareMem(@BlockHeader.Hash[0], @BlockDataHash[0], Length(BlockHeader.Hash)) then
            raise EKdbxError.Create('Kdbx file is damaged, data block hash is incorrect.');

          // Write pure data
          DeblockedStream.Write(BlockData[0], Length(BlockData));
          DeblockedStream.Position := 0;
        end;
        FreeAndNil(DecryptedStream);

        // Last step, if stream is compressed we must decompress it
        if FCompressionAlgorithm = TPwCompressionAlgorithm.None then
        begin
          Result := DeblockedStream;
        end
        else
        begin
          DecompressedStream := DecompressPayloadArea(DeblockedStream);

          if DecompressedStream = nil then
          begin
            raise EKdbxError.Create('Failed to decompress stream.');
          end;

          DecompressedStream.Position := 0;
          Result := DecompressedStream;
        end;

      except
        DeblockedStream.Free;
      end;

    finally
      DecryptedStream.Free;
    end;

  finally
    if hKey <> 0 then
      CryptDestroyKey(hKey);
    if hProv <> 0 then
      CryptReleaseContext(hProv, 0);
  end;

end;

function TKdbxFile.TransformKey(const CompositeKey: TBytes; Seed: TBytes;
  Rounds: UInt64): TBytes;
var
  hProv           : HCRYPTPROV;
  hKey            : HCRYPTKEY;
  hHash           : HCRYPTHASH;
  KeyBlob         : TAes256KeyBlob;
  AesMode         : DWORD;
  TransformedKey  : array[0..31] of Byte;
  i               : UInt64;
  dwDataLen       : DWORD;
begin
  if not Assigned(CompositeKey) then
    raise EKdbxError.Create('CompositeKey argument cannot be nil!');
  if Length(CompositeKey) <> 32 then
    raise EKdbxError.Create('CompositeKey size <> 32 bit!');
  if not Assigned(Seed) then
    raise EKdbxError.Create('Seed argument cannot be nil!');
  if Length(Seed) <> 32 then
    raise EKdbxError.Create('Seed size <> 32 bit!');

  Result := nil;
  hProv := 0;
  hKey := 0;
  hHash := 0;

 try
    Win32Check(CryptAcquireContext(hProv, nil, nil, PROV_RSA_AES, CRYPT_VERIFYCONTEXT));
    FillChar(KeyBlob, SizeOf(TAes256KeyBlob), 0);
    KeyBlob.Header.bType    := PLAINTEXTKEYBLOB;
    KeyBlob.Header.bVersion := CUR_BLOB_VERSION;
    KeyBlob.Header.aiKeyAlg := CALG_AES_256;
    KeyBlob.KeySize := 32;
    Move(FTransformSeed[0], KeyBlob.KeyData[0], 32);
    Win32Check(CryptImportKey(hProv, KeyBlob, SizeOf(TAes256KeyBlob), 0, 0, hKey));
    AesMode := CRYPT_MODE_ECB;
    Win32Check(CryptSetKeyParam(hKey, KP_MODE, AesMode, 0));
    Move(CompositeKey[0], TransformedKey[0], 32);
    dwDataLen := 16;
    for i := 0 to Rounds - 1 do
    begin
      Win32Check(CryptEncrypt(hKey, 0, False, 0, TransformedKey[0], dwDataLen, 16));
      Win32Check(CryptEncrypt(hKey, 0, False, 0, TransformedKey[16], dwDataLen, 16));
    end;

    try
      Win32Check(CryptCreateHash(hProv, CALG_SHA_256, 0, 0, hHash));
      Win32Check(CryptHashData(hHash, TransformedKey[0], Length(TransformedKey), 0));
      dwDataLen := 32;
      CryptGetHashParam(hHash, HP_HASHVAL, TransformedKey[0], dwDataLen, 0);
      SetLength(Result, 32);
      Move(TransformedKey[0], Result[0], 32);
    finally
      CryptDestroyHash(hHash);
    end;

  finally
    if hKey <> 0 then
      CryptDestroyKey(hKey);
    if hProv <> 0 then
      CryptReleaseContext(hProv, 0);
  end;
end;

end.
