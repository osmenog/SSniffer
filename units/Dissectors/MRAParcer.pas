unit MRAParcer;

interface

uses
	Types,WinSock,SysUtils,SSUtils,MagentaPackhdrs;

type
  //Заголовок протокола Mail.Ru
	TMRAHdr= packed record //len=44d
    magic   : DWORD;  // Magic
    proto   : DWORD;  // Версия протокола
    seq     : DWORD;  // Sequence
    msg     : DWORD;  // Тип пакета
    dlen    : DWORD;  // Длина данных
    from    : TInAddr; // Адрес отправителя
    fromport: DWORD;  // Порт отправителя
    reserved: array [0..15] of byte; // Зарезервировано
  end;
  PMRAHdr=^TMRAHdr;

const
	MRIM_CS_MESSAGE=$1008;      //Исходящее сообщение
  MRIM_CS_MESSAGE_ACK=$1009;  //Входящее сообщение
  MRIM_CS_CUSTOM_LOGIN=$1078; //Логин. (ОТСУТСТВУЕТ В ОФФ. ДОКУМЕНТАЦИИ!)

procedure ProcessMRAPacket(PacketInfo:TPacketInfo);

implementation

function UCS2ToAnsi(Buffer: PAnsiString): WideString;
var
  ofst: integer;
  MsgWideChar: WideChar;
  MsgWideText: WideString;
begin
  ofst := 1;
  while ofst < Length(Buffer^) do
  begin
    MsgWideChar := WideChar((Word((@(Buffer^[ofst]))^)));
    ofst := ofst + 2;
    MsgWideText := MsgWideText + MsgWideChar;
  end;
  Result := MsgWideText;
end;

procedure ProcessMRAPacket(PacketInfo:TPacketInfo);
var
	Header    : PMRAHdr;
  LogHeader : String;
  ofst      : Integer;
  tmpLen    : Integer;
  ScreenName: String;
  MSGText   : AnsiString;
  Flags     : DWORD;
  Log       : TLogLine;
  Login     : String;
  Pass      : AnsiString;
  I: Integer;
  tmp: String;
  msg_id:DWORD;
begin
	Log:=TLogLine.Create;
  ofst:=1;
  Header:= PMRAHdr(@PacketInfo.DataBuf[1]);
  Log.Date:=PacketInfo.PacketDT;
  Log.Ip_Src:=PacketInfo.AddrSrc;
  Log.Ip_Dst:=PacketInfo.AddrDest;
  Log.Dbg_info.Add('p:$'+inttoHex(Header.proto,8));
	Log.Dbg_info.Add('seq:$'+inttoHex(Header.seq,8));
	Log.Dbg_info.Add('msg:$'+inttoHex(Header.msg,8));
	Log.Dbg_info.Add('l:'+inttoStr(Header.dlen));
	Log.Dbg_info.Add('f:'+IPToStr(Header.from));
	Log.Dbg_info.Add('fp:'+inttoStr(Header.fromport));

  ofst:=ofst+sizeof(TMRAHdr); //На MRA Data. Пропускаем заголовок.

  case Header.msg of
  	MRIM_CS_MESSAGE{ OR MRIM_CS_MESSAGE_ACK}:
    begin
    	Flags:=DWORD((@PacketInfo.DataBuf[ofst])^);  //Определяем флаги
		  Log.Dbg_info.Add('flags:$'+inttohex(Flags,8));
      ofst:=ofst+4; //На LPS_TO_len Пропустил flags.
  		tmpLen:=DWORD((@PacketInfo.DataBuf[ofst])^); // Длина ScreenName
    	ofst:=ofst+4; //На LPS_TO_data. Пропустил LPS_TO_Len
    	ScreenName:= Copy(PacketInfo.DataBuf, ofst, tmpLen);
    	ofst:=ofst+tmpLen; // На LPS_Message_len
    	tmpLen:=DWORD((@PacketInfo.DataBuf[ofst])^); //Длина LPSText
    	ofst:=ofst+4;
    	//ofst:= ofst+tmpLen; //На LPS Message Data
    	MSGText:= Copy(PacketInfo.DataBuf, ofst, tmpLen);
      Log.Msg_To:=ScreenName;
      Log.Msg_Text:=UCS2ToAnsi(@MsgText);
      Log.Print;
    end;

    MRIM_CS_MESSAGE_ACK:
    begin
      //tmp:=LogData(@PacketInfo.DataBuf);
      //Log.Dbg_info.Add(tmp);
      //Log.Print;
      msg_id:=DWORD((@PacketInfo.DataBuf[ofst])^); //Получаем msg_id
      Inc(ofst,4); //Смещаемся с msg_id на Flags
      Flags:=DWORD((@PacketInfo.DataBuf[ofst])^);  //Определяем флаги
		  Log.Dbg_info.Add('flags:$'+inttohex(Flags,8));
    	ofst:=ofst+4; //Смещаемся с Flags на LPS_From_len
  		tmpLen:=DWORD((@PacketInfo.DataBuf[ofst])^); //Длина ScreenName
    	ofst:=ofst+4; //Смещаемся с LPS_From_len на LPS_From_data
    	ScreenName:= Copy(PacketInfo.DataBuf, ofst, tmpLen);
    	ofst:=ofst+tmpLen; //Смещаемся с LPS_From_data на LPS_Message_len
    	tmpLen:=DWORD((@PacketInfo.DataBuf[ofst])^); //Длина LPS_Message
    	ofst:=ofst+4; //Смещаемся с LPS_Message_len на LPS_Message_data
    	//ofst:= ofst+tmpLen; //На LPS Message Data
    	MSGText:= Copy(PacketInfo.DataBuf, ofst, tmpLen);
      Log.Msg_From:=ScreenName;
      Log.Msg_Text:=UCS2ToAnsi(@MsgText);
      Log.Print;
    end;

    MRIM_CS_CUSTOM_LOGIN:
    begin
      tmpLen:=DWORD((@PacketInfo.DataBuf[ofst])^); // Длина Логина
    	ofst:=ofst+4;
    	Login:=Copy(PacketInfo.DataBuf, ofst, tmpLen);
    	ofst:=ofst+tmpLen; // На LPS_Message_len
    	tmpLen:=DWORD((@PacketInfo.DataBuf[ofst])^); //Длина пароля
    	ofst:=ofst+4;
      Pass:=Copy(PacketInfo.DataBuf, ofst, tmpLen);
      tmp:='';
      for I := 1 to tmpLen do
      	tmp:=tmp+inttohex(ord(Pass[I]),2);
      Log.Msg_From:=Login;
      Log.Msg_Text:='MD5 password hash: '+tmp;
      Log.Print;
    end;
  end;

  Log.Free;
end;

end.
