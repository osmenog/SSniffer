{
	���� ���� ����� ����� ������� :)
}
unit SSBox;

interface

uses MagentaPackHdrs,Windows;

type
  TSBoxItem = class (TObject)
    private
    	FPort: Integer;                          //��������� ���� (�� ���� ������������� ��� �������)
      FBuffer: AnsiString;                     //������.
      FSeq: DWORD;														 //����� ������������������
    public
    	constructor Create(Buffer:PAnsiChar; Seq:DWORD; Port:Integer);
      destructor Destroy;
      property Buffer:AnsiString read FBuffer; //������, ���������� ������ � �������
      property Port:Integer read FPort;        //��������� ����
      procedure Add(subBuffer:PAnsiString);    //�������� ������ � ������ �������.
      procedure Save;                          //��������� ����������� ������ � ����
  end;

{	TSBox = class (TObject)
    private
    public
			Item: array of TSBoxItem;
      constructor Create;
      destructor Destroy;
  end; }


implementation

{TSBoxItem}
constructor TSBoxItem.Create(Buffer:PAnsiChar; Seq:DWORD; Port:Integer);
begin
  FPort:=Port;
	FSeq:=Seq;
  SetLength(FBuffer,Length(Buffer^)); // �������� ������ �������
  Move(Buffer,FBuffer,Length(Buffer^)); //�������� ������
  inherited Create;
end;

destructor TSBoxItem.Destroy;
begin
end;

procedure TSBoxItem.Add(subBuffer:PAnsiString);
var
	newLen:integer;
begin
	newLen:=Length(FBuffer)+Length(subBuffer^);
  SetLength(FBuffer,newLen);
	Move(SubBuffer,FBuffer,newLen);
end;

procedure TSBoxItem.Save;
begin

end;
{end of TSBoxItem}
end.
