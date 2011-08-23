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
	CurDateTime:TDateTime; // ������� ����� � ����. ��� ����������������.
  IPSource: String;      // IP ������
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
    //��� ���� �������, ���� ��������������
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
  MSGLen: Word;  			 //����� ���������
  MSGText: AnsiString; //���� ���������
  tmpLen:integer;
  CharSet01,CharSet02:word;
begin
  Logger.Dbg_info.Add('PLAIN');
	ofst:=ofst+2; //������ ��������� �� Feature Len
	tmpLen := ntohs(Word((@(Buffer^[ofst]))^));
	ofst:=ofst + tmpLen;
	ofst:=ofst+4; //�� Block Len
	MSGLen := ntohs(Word((@(Buffer^[ofst]))^));
	ofst:=ofst+2;
	CharSet01 := ntohs(Word((@(Buffer^[ofst]))^));
	ofst:=ofst+2;
	CharSet02 := ntohs(Word((@(Buffer^[ofst]))^));
	ofst:=ofst+2; //�� message data
	MSGText := Copy(Buffer^, ofst, MSGLen-4);
  Logger.Dbg_info.Add('chset:$'+inttohex(Charset01,2)+',$'+inttohex(Charset02,2));
  Logger.Dbg_info.Add('len:'+inttostr(MSGLen));
  //Logger.AddHexBlock(MSGText);
  if (CharSet01 = $0000) or (CharSet01 = $0003) then // ASCII or LATIN
		Result:=MSGText
  else if CharSet01 = $0002 then // UCS-2
  	Result:=UCS2ToAnsi(@MSGText);
  {else
  	SavePacket(Buffer, IPSource+' -> '+IPDestination+ ' ' + 'ParcePlainText: ����������� ���������. CharacterSet01= $'+inttohex (CharSet01,2));}
end;

function ParseRendevouz(Buffer:PAnsiString; ofst:integer ):AnsiString;
var
	MSGLen    : Word;        //����� ���������
	MSGText   : AnsiString;  //���� ���������
	MSGSubtype: Word;
begin
	Logger.Dbg_info.Add('REND');
	//��������� � TLVRendData
	ofst := ofst + 2 + 8 + 16;
	//���������� MessageType, ICMBCookie, Relay Data.
	// ��������� �� FirstInsideTLVHeader (Sequence..)
	// ���� TLV2711
	ofst := FindTLV(Buffer, ofst, $2711);
	// ����� ��������� ������ ofst ��������� � TLV2711Data (1b00 ...)
	// ���������� �����
	ofst := ofst + 26 + 7;
	while Buffer^[ofst] = #$00 do
	begin
		inc(ofst);
	end;
	// ��������� ��� ��������� (msg_Subtype)
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
		{SavePacket(Buffer, IPSource+' -> '+IPDestination+ ' ' + 'ParseRendevouz: ����������� MSG_SUBTYPE � TLV');}
	end;
	Result:=MSGText;
end;

function ProcessMessage (Buffer:PAnsiString; ofst:integer;Channel:word; TLVCount:word):AnsiString;
var
	MSGText:AnsiString;
begin
	if Channel = $01 then // ���� Plain Text
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
	SNAC_hdr      : PSnacHdr;   //��������� SNAC
  Channel       : Word;       //��� ������
  ScreenNameLen : Byte;       //����� UIN
  ScreenName    : String;     //UIN
  MSGText       : AnsiString; //���� ���������
  TLVCount      : Word;       //���������� TLV ����� TLV � ���������� (��� ��������)
  //LogHeader     : String;
  FileName      :String;
  A:Pointer;
begin
	SNAC_hdr := PSnacHdr(PAnsiChar(@Buffer[ofst]));
	ofst:=ofst+10; //�� SNAC Data
	if (ntohs(SNAC_hdr.Family) = $04) and (ntohs(SNAC_hdr.SubType) = $06)  then
	begin //��������� ���������
		Logger.Dbg_info.Add('snac(4,6)');
		ofst:=ofst+8; //�� Channel
		Channel := ntohs(Word((@(Buffer[ofst]))^));
		ofst := ofst + 2; // ��������� �� SN len
		// ���������� Screen Name
		ScreenNameLen:= Byte(Buffer[ofst]);
		Inc(ofst);
		ScreenName:= Copy(Buffer, ofst, ScreenNameLen);
		ofst:= ofst+ScreenNameLen; //�� FirstTLVHeader

  	Logger.Dbg_info.Add('ch:$'+inttohex(Channel,2));
		MSGText:=ProcessMessage(@Buffer,ofst,Channel,0);
		{NewMessage(CurDateTime, IPSource, IPDestination, 2, ScreenName, MSGText);}
    //Logger.AddTitle('��������� ��������� ��� ' + ScreenName + ':');
    Logger.Msg_To:=ScreenName;
    Logger.Msg_Text:=MSGText;
    Logger.Print;
	end;

	if (ntohs(SNAC_hdr.Family) = $04) and (ntohs(SNAC_hdr.SubType) = $07)  then
	begin //�������� ���������
  	Logger.Dbg_info.Add('snac(4,7)');
		ofst := 1;
		ofst := ofst + 16; // ��������� �� ������ SNACData
		ofst := ofst + 8; // ���������� ����, ��������� �� ������ MessageChannel
		// �������� ��� ������
		Channel := ntohs(Word((@(Buffer[ofst]))^));
		ofst := ofst + 2; // ��������� �� SN len
		ScreenNameLen := Byte(Buffer[ofst]);
		Inc(ofst);
		ScreenName := Copy(Buffer, ofst, ScreenNameLen);
		ofst := ofst + ScreenNameLen; // ��������� �� WarningLevel
		ofst := ofst + 2;
		TLVCount := ntohs(Word((@(Buffer[ofst]))^)); // ���������� ������ TLV ����� Text Data
		ofst := ofst + 2; // ��������� �� FirstTLVHeader
    Logger.Dbg_info.Add('ch:$'+inttohex(Channel,2));
    Logger.Dbg_info.Add('tlv_cnt:'+inttostr(TLVCount));
		MSGText:=ProcessMessage(@Buffer,ofst,Channel,TLVCount);

		{NewMessage(CurDateTime, IPSource, IPDestination, 1, ScreenName, MSGText);}
    //Logger.AddTitle('�������� ��������� �� ' + ScreenName + ':');
    Logger.Msg_From:=ScreenName;
    Logger.Msg_Text:=MSGText;
    Logger.Print;
	end;

end;

procedure ProcessICQPacket(PacketInfo:TPacketInfo);
var
  FLAP_hdr: PFlapHdr;
  ofst: integer; // ��� ����� �����
  Aa:Pointer;
begin
  Logger:=TLogLine.Create; //������� ������
	//Logger.AddHeader('('+DateTimeToStr(PacketInfo.PacketDT)+') '+IpToStr(PacketInfo.AddrSrc)+' -> '+IpToStr(PacketInfo.AddrDest));
  logger.Date:=PacketInfo.PacketDT;
  Logger.Ip_Src:=PacketInfo.AddrSrc;
  Logger.Ip_Dst:=PacketInfo.AddrDest;

  //�������� FLAP ���������
  ofst:=1; //�� ������ FLAP ������
  FLAP_hdr:= PFlapHdr(PAnsiChar(@PacketInfo.DataBuf[ofst]));
  inc (ofst,6); //�� FLAP Data (SNAC hdr)

  // ���������� ��� FLAP ������
  if FLAP_hdr.Ident = $01 then exit;  // New Connection
  if FLAP_hdr.Ident = $02 then ProcessSNACPacket (PacketInfo.DataBuf,ofst); // SNAC
  if FLAP_hdr.Ident = $03 then exit;  // FLAP Error
  if FLAP_hdr.Ident = $04 then exit;  // Close Connection
  if FLAP_hdr.Ident = $05 then exit;  // Keep Alive


  Logger.Free;						//��������
end;

end.
