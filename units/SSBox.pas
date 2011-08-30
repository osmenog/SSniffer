{
	Этот файл скоро будет ненужен :)
}
unit SSBox;

interface

uses MagentaPackHdrs,Windows;

type
  TSBoxItem = class (TObject)
    private
    	FPort: Integer;                          //Связанный порт (по сути идентификатор для обьекта)
      FBuffer: AnsiString;                     //Буффер.
      FSeq: DWORD;														 //Номер последовательности
    public
    	constructor Create(Buffer:PAnsiChar; Seq:DWORD; Port:Integer);
      destructor Destroy;
      property Buffer:AnsiString read FBuffer; //Буффер, собирающий данные с пакетов
      property Port:Integer read FPort;        //Связанный порт
      procedure Add(subBuffer:PAnsiString);    //Добавить данные к общему буфферу.
      procedure Save;                          //Сохраняет накопленные данные в файл
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
  SetLength(FBuffer,Length(Buffer^)); // Изменяем размер буффера
  Move(Buffer,FBuffer,Length(Buffer^)); //Копируем память
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
