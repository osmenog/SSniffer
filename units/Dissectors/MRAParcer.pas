unit MRAParcer;

interface

uses
	Types,WinSock,SysUtils,SSUtils,MagentaPackhdrs;

type
  //��������� ��������� Mail.Ru
	TMRAHdr= packed record //len=44d
    magic   : DWORD;  // Magic
    proto   : DWORD;  // ������ ���������
    seq     : DWORD;  // Sequence
    msg     : DWORD;  // ��� ������
    dlen    : DWORD;  // ����� ������
    from    : TInAddr; // ����� �����������
    fromport: DWORD;  // ���� �����������
    reserved: array [0..15] of byte; // ���������������
  end;
  PMRAHdr=^TMRAHdr;

const
	MRIM_CS_MESSAGE=$1008;      //��������� ���������
  MRIM_CS_MESSAGE_ACK=$1009;  //�������� ���������
  MRIM_CS_CUSTOM_LOGIN=$1078; //�����. (����������� � ���. ������������!)

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

  ofst:=ofst+sizeof(TMRAHdr); //�� MRA Data. ���������� ���������.

  case Header.msg of
  	MRIM_CS_MESSAGE{ OR MRIM_CS_MESSAGE_ACK}:
    begin
    	Flags:=DWORD((@PacketInfo.DataBuf[ofst])^);  //���������� �����
		  Log.Dbg_info.Add('flags:$'+inttohex(Flags,8));
      ofst:=ofst+4; //�� LPS_TO_len ��������� flags.
  		tmpLen:=DWORD((@PacketInfo.DataBuf[ofst])^); // ����� ScreenName
    	ofst:=ofst+4; //�� LPS_TO_data. ��������� LPS_TO_Len
    	ScreenName:= Copy(PacketInfo.DataBuf, ofst, tmpLen);
    	ofst:=ofst+tmpLen; // �� LPS_Message_len
    	tmpLen:=DWORD((@PacketInfo.DataBuf[ofst])^); //����� LPSText
    	ofst:=ofst+4;
    	//ofst:= ofst+tmpLen; //�� LPS Message Data
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
      msg_id:=DWORD((@PacketInfo.DataBuf[ofst])^); //�������� msg_id
      Inc(ofst,4); //��������� � msg_id �� Flags
      Flags:=DWORD((@PacketInfo.DataBuf[ofst])^);  //���������� �����
		  Log.Dbg_info.Add('flags:$'+inttohex(Flags,8));
    	ofst:=ofst+4; //��������� � Flags �� LPS_From_len
  		tmpLen:=DWORD((@PacketInfo.DataBuf[ofst])^); //����� ScreenName
    	ofst:=ofst+4; //��������� � LPS_From_len �� LPS_From_data
    	ScreenName:= Copy(PacketInfo.DataBuf, ofst, tmpLen);
    	ofst:=ofst+tmpLen; //��������� � LPS_From_data �� LPS_Message_len
    	tmpLen:=DWORD((@PacketInfo.DataBuf[ofst])^); //����� LPS_Message
    	ofst:=ofst+4; //��������� � LPS_Message_len �� LPS_Message_data
    	//ofst:= ofst+tmpLen; //�� LPS Message Data
    	MSGText:= Copy(PacketInfo.DataBuf, ofst, tmpLen);
      Log.Msg_From:=ScreenName;
      Log.Msg_Text:=UCS2ToAnsi(@MsgText);
      Log.Print;
    end;

    MRIM_CS_CUSTOM_LOGIN:
    begin
      tmpLen:=DWORD((@PacketInfo.DataBuf[ofst])^); // ����� ������
    	ofst:=ofst+4;
    	Login:=Copy(PacketInfo.DataBuf, ofst, tmpLen);
    	ofst:=ofst+tmpLen; // �� LPS_Message_len
    	tmpLen:=DWORD((@PacketInfo.DataBuf[ofst])^); //����� ������
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
