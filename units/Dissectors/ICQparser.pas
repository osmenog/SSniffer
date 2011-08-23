unit ICQparser;

interface
uses
  Types,WinSock,MagentaPackhdrs,SysUtils,SSUtils;

type
  //Flap header = 6 bytes
  PFlapHdr = ^TFlapHdr;
  TFlapHdr = packed record
    StartMarker: Byte;
    Ident: Byte;
    ChID: Byte;
    Seq: Word;
    DataLen: Word;
  end;

  //Snac header = 10 bytes
  PSnacHdr = ^TSnacHdr;
  TSnacHdr = packed record
    Family: Word;
    SubType: Word;
    Flags: Word;
    ReqID: LongWord;
  end;

var
	CurDateTime:TDateTime; // Текущее время и дата. Для протоколирования.
  IPSource: String;      // IP Адреса
  IPDestination: String;
  LogHeader:String;
  //Logger: TLogger; - old
  Logger: TLogLine; // - new

procedure ProcessICQPacket(PacketInfo:TPacketInfo);

implementation

function BufToWord(Buffer: PAnsiString; ofst: integer; convert: Boolean = false): Word;
var
  CurTLV: integer;
begin
  if convert = true then
    Result := ntohs(Word((@(Buffer^[ofst]))^))
  else
    Result := Word((@(Buffer^[ofst]))^);
end;

function UCS2ToAnsi(Buffer: PAnsiString): WideString;
var
  ofst: integer;
  MsgWideChar: WideChar;
  MsgWideText: WideString;
begin
  ofst := 1;
  while ofst < Length(Buffer^) do
  begin
    MsgWideChar := WideChar(ntohs(Word((@(Buffer^[ofst]))^)));
    ofst := ofst + 2;
    MsgWideText := MsgWideText + MsgWideChar;
  end;
  Result := MsgWideText;
end;

function FindTLV(Buffer: PAnsiString; ofst: integer; TLVType: Word; TLVCount: integer = 0): integer;
var
  CurTLV:integer;
  tmpType,tmpLen:word;
begin
  CurTLV := 1;
  while ofst < Length(Buffer^) do
  begin
    tmpType := BufToWord(Buffer, ofst, true);
    ofst := ofst + 2;
    tmpLen := BufToWord(Buffer, ofst, true);
    ofst := ofst + 2;
    //Код ниже уебищен, надо оптимизировать
    if TLVCount <> 0 then
    begin
      if (tmpType = TLVType) and (CurTLV > TLVCount) then break;
    end
    else
      if (tmpType = TLVType) then break;

    ofst := ofst + tmpLen;
    Inc(CurTLV);
  end;
  Result:=ofst;
end;

function ParcePlainText (Buffer:PAnsiString; ofst:integer ):AnsiString;
var
  MSGLen: Word;  			 //Длина сообщения
  MSGText: AnsiString; //Само сообщение
  tmpLen:integer;
  CharSet01,CharSet02:word;
begin
  Logger.Dbg_info.Add('PLAIN');
	ofst:=ofst+2; //Теперь находимся на Feature Len
	tmpLen := ntohs(Word((@(Buffer^[ofst]))^));
	ofst:=ofst + tmpLen;
	ofst:=ofst+4; //на Block Len
	MSGLen := ntohs(Word((@(Buffer^[ofst]))^));
	ofst:=ofst+2;
	CharSet01 := ntohs(Word((@(Buffer^[ofst]))^));
	ofst:=ofst+2;
	CharSet02 := ntohs(Word((@(Buffer^[ofst]))^));
	ofst:=ofst+2; //На message data
	MSGText := Copy(Buffer^, ofst, MSGLen-4);
  Logger.Dbg_info.Add('chset:$'+inttohex(Charset01,2)+',$'+inttohex(Charset02,2));
  Logger.Dbg_info.Add('len:'+inttostr(MSGLen));
  //Logger.AddHexBlock(MSGText);
  if (CharSet01 = $0000) or (CharSet01 = $0003) then // ASCII or LATIN
		Result:=MSGText
  else if CharSet01 = $0002 then // UCS-2
  	Result:=UCS2ToAnsi(@MSGText);
  {else
  	SavePacket(Buffer, IPSource+' -> '+IPDestination+ ' ' + 'ParcePlainText: Неизвестная кодировка. CharacterSet01= $'+inttohex (CharSet01,2));}
end;

function ParseRendevouz(Buffer:PAnsiString; ofst:integer ):AnsiString;
var
	MSGLen    : Word;        //Длина сообщения
	MSGText   : AnsiString;  //Само сообщение
	MSGSubtype: Word;
begin
	Logger.Dbg_info.Add('REND');
	//Находимся в TLVRendData
	ofst := ofst + 2 + 8 + 16;
	//Пропускаем MessageType, ICMBCookie, Relay Data.
	// Находимся на FirstInsideTLVHeader (Sequence..)
	// Ищем TLV2711
	ofst := FindTLV(Buffer, ofst, $2711);
	// После окончания поиска ofst находится в TLV2711Data (1b00 ...)
	// Пропускаем хуйню
	ofst := ofst + 26 + 7;
	while Buffer^[ofst] = #$00 do
	begin
		inc(ofst);
	end;
	// Проверяем тип сообщения (msg_Subtype)
	MSGSubtype:=Word((@(Buffer^[ofst]))^);
	Logger.Dbg_info.Add('msg_st:$'+inttoHex(MsgSubtype,2));
	if (MSGSubtype = $01) then
	begin
		ofst := ofst + 6;
		MSGLen := Word((@(Buffer^[ofst]))^);
		ofst := ofst + 2;
		MSGText := Copy(Buffer^, ofst, MSGLen-1);
    Logger.Dbg_info.Add('l:'+inttostr(MSGLen));
  	//Logger.AddHexBlock(MSGText);
	end
	else
  if (MSGSubtype = $1a) then
  begin
  	ofst := ofst + 6;
		MSGLen := Word((@(Buffer^[ofst]))^);
		ofst := ofst + 2;
		MSGText := Copy(Buffer^, ofst, MSGLen);
    Logger.Dbg_info.Add('l:'+inttostr(MSGLen));
  	Logger.Dbg_info.Add(LogData(@MSGText));
		{SavePacket(Buffer, IPSource+' -> '+IPDestination+ ' ' + 'ParseRendevouz: Неизвестный MSG_SUBTYPE в TLV');}
	end;
	Result:=MSGText;
end;

function ProcessMessage (Buffer:PAnsiString; ofst:integer;Channel:word; TLVCount:word):AnsiString;
var
	MSGText:AnsiString;
begin
	if Channel = $01 then // Если Plain Text
	begin
		ofst:=FindTLV (Buffer,ofst,$02,TLVCount);
		MSGText:=ParcePlainText(Buffer, ofst);
	end
	else
	if Channel = $02 then  //Rendevouz message
	begin
		ofst := FindTLV(Buffer, ofst, $05, TLVCount);
		MSGText:=UTF8ToAnsi(ParseRendevouz(Buffer, ofst));
	end;
	Result:=MSGText;
end;

procedure ProcessSNACPacket (Buffer: AnsiString; ofst:integer);
var
	SNAC_hdr      : PSnacHdr;   //Заголовок SNAC
  Channel       : Word;       //Тип канала
  ScreenNameLen : Byte;       //Длина UIN
  ScreenName    : String;     //UIN
  MSGText       : AnsiString; //Само сообщение
  TLVCount      : Word;       //Количество TLV перед TLV с сообщением (для входящих)
  //LogHeader     : String;
  FileName      :String;
  A:Pointer;
begin
	SNAC_hdr := PSnacHdr(PAnsiChar(@Buffer[ofst]));
	ofst:=ofst+10; //На SNAC Data
	if (ntohs(SNAC_hdr.Family) = $04) and (ntohs(SNAC_hdr.SubType) = $06)  then
	begin //Исходящее сообщение
		Logger.Dbg_info.Add('snac(4,6)');
		ofst:=ofst+8; //На Channel
		Channel := ntohs(Word((@(Buffer[ofst]))^));
		ofst := ofst + 2; // Смещаемся на SN len
		// Определяем Screen Name
		ScreenNameLen:= Byte(Buffer[ofst]);
		Inc(ofst);
		ScreenName:= Copy(Buffer, ofst, ScreenNameLen);
		ofst:= ofst+ScreenNameLen; //На FirstTLVHeader

  	Logger.Dbg_info.Add('ch:$'+inttohex(Channel,2));
		MSGText:=ProcessMessage(@Buffer,ofst,Channel,0);
		{NewMessage(CurDateTime, IPSource, IPDestination, 2, ScreenName, MSGText);}
    //Logger.AddTitle('Исходящее сообщение для ' + ScreenName + ':');
    Logger.Msg_To:=ScreenName;
    Logger.Msg_Text:=MSGText;
    Logger.Print;
	end;

	if (ntohs(SNAC_hdr.Family) = $04) and (ntohs(SNAC_hdr.SubType) = $07)  then
	begin //Входящее сообщение
  	Logger.Dbg_info.Add('snac(4,7)');
		ofst := 1;
		ofst := ofst + 16; // Смещаемся на НАЧАЛО SNACData
		ofst := ofst + 8; // Пропускаем Куки, смещаемся на начало MessageChannel
		// Получаем тип канала
		Channel := ntohs(Word((@(Buffer[ofst]))^));
		ofst := ofst + 2; // Смещаемся на SN len
		ScreenNameLen := Byte(Buffer[ofst]);
		Inc(ofst);
		ScreenName := Copy(Buffer, ofst, ScreenNameLen);
		ofst := ofst + ScreenNameLen; // Смещаемся на WarningLevel
		ofst := ofst + 2;
		TLVCount := ntohs(Word((@(Buffer[ofst]))^)); // Количество блоков TLV перед Text Data
		ofst := ofst + 2; // Смещаемся на FirstTLVHeader
    Logger.Dbg_info.Add('ch:$'+inttohex(Channel,2));
    Logger.Dbg_info.Add('tlv_cnt:'+inttostr(TLVCount));
		MSGText:=ProcessMessage(@Buffer,ofst,Channel,TLVCount);

		{NewMessage(CurDateTime, IPSource, IPDestination, 1, ScreenName, MSGText);}
    //Logger.AddTitle('Входящее сообщение от ' + ScreenName + ':');
    Logger.Msg_From:=ScreenName;
    Logger.Msg_Text:=MSGText;
    Logger.Print;
	end;

end;

procedure ProcessICQPacket(PacketInfo:TPacketInfo);
var
  FLAP_hdr: PFlapHdr;
  ofst: integer; // Для любых целей
  Aa:Pointer;
begin
  Logger:=TLogLine.Create; //Создаем Логгер
	//Logger.AddHeader('('+DateTimeToStr(PacketInfo.PacketDT)+') '+IpToStr(PacketInfo.AddrSrc)+' -> '+IpToStr(PacketInfo.AddrDest));
  logger.Date:=PacketInfo.PacketDT;
  Logger.Ip_Src:=PacketInfo.AddrSrc;
  Logger.Ip_Dst:=PacketInfo.AddrDest;

  //Получаем FLAP заголовок
  ofst:=1; //На начало FLAP пакета
  FLAP_hdr:= PFlapHdr(PAnsiChar(@PacketInfo.DataBuf[ofst]));
  inc (ofst,6); //На FLAP Data (SNAC hdr)

  // Определяем тип FLAP пакета
  if FLAP_hdr.Ident = $01 then exit;  // New Connection
  if FLAP_hdr.Ident = $02 then ProcessSNACPacket (PacketInfo.DataBuf,ofst); // SNAC
  if FLAP_hdr.Ident = $03 then exit;  // FLAP Error
  if FLAP_hdr.Ident = $04 then exit;  // Close Connection
  if FLAP_hdr.Ident = $05 then exit;  // Keep Alive


  Logger.Free;						//Чистимся
end;

end.
