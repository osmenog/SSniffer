unit magclasses ;

{$IFNDEF VER140}
  {$WARN UNSAFE_TYPE off}
  {$WARN UNSAFE_CAST off}
  {$WARN UNSAFE_CODE off}
{$ENDIF}

{ various classes
Updated by Angus Robertson, Magenta Systems Ltd, England, 11th August 2010
delphi@magsys.co.uk, http://www.magsys.co.uk/delphi/
Copyright Magenta Systems Ltd    }

// 25 July 2005 - Angus - added  AddSorted and Sorted
// 1 Aug 2005 - added CompareGTMem
// 8 Aug 2008 - made compatible with Delphi 2009
// 6 May 2010 - added TStringPairs, stringlist with key and value



interface

uses
  Classes ;

type

// descendent of TList added a Find function using binary search identical to sorting

  TFindList = class(TList)
  private
    { Private declarations }
  protected
    { Protected declarations }
  public
    { Public declarations }
    Sorted: boolean ;
    function AddSorted(const Item2: Pointer; Compare: TListSortCompare): Integer; virtual;
    function Find(const Item2: Pointer; Compare: TListSortCompare;
                                    var index: longint): Boolean; virtual;
  end;

// StringList with keys and values (stored as objects)

    TStringPairs = class(TObject)
    protected
        FList : TStringList;
    public
        constructor Create;
        destructor Destroy; override;
        procedure Add(const Key, Value : String);
        function  Find(const Key : String; var Value : String) : Boolean;
        function  Count : Integer;
        procedure Clear;
    end;

    TStringPairsObject = class(TObject)
    public
        Value : String;
        constructor Create(const Data : String);
    end;

  function CompareGTMem (P1, P2: Pointer; Length: Integer): Integer ;

implementation

// compare two memory buffers, used for sorting
// ideally ASM SysUtils.CompareMem should be modified to return less or greater

function CompareGTMem (P1, P2: Pointer; Length: Integer): Integer ;
var
    I: Integer;
    PC1, PC2: PAnsiChar; // 8 Aug 2008
begin
    result := 0 ;   // equals
    if Length <= 0 then exit ;
    PC1 := P1 ;
    PC2 := P2 ;
    for I := 1 to Length do
    begin
        if (PC1^ <> PC2^) then
        begin
            if (PC1^ < PC2^) then
                result := -1   // less than
            else
                result := 1 ;  // greater than
            exit ;
        end ;
        Inc (PC1) ;
        Inc (PC2) ;
    end;
end;


// descendent of TList, adding sorted, works on sorted list

function TFindList.AddSorted(const Item2: Pointer; Compare: TListSortCompare): Integer;
begin
    if not Sorted then
        Result := Count
    else
    begin
       if Find (Item2, Compare, Result) then exit ;
    end ;
    Insert (Result, Item2) ;
end;

// adding binary FIND works on sorted list

function TFindList.Find(const Item2: Pointer; Compare: TListSortCompare;
                                            var index: longint): Boolean;
var
    l, h, i, c: longint;
begin
    Result := False;
    index := 0 ;
    if (List = nil) or (Count = 0) then exit ;
    l := 0;
    h := Count - 1;
    while l <= h do
    begin
        i := (l + h) shr 1;  // binary shifting
        c := Compare (List[i], Item2) ;
        if c < 0 then
            l := i + 1
        else
        begin
            h := i - 1;
            if c = 0 then
            begin
                Result := True;
                l := i;
            end;
        end;
    end;
    index := l;
end;

// TStringPairs

procedure TStringPairs.Add(const Key, Value: String);
begin
    if NOT Assigned(Flist) then exit;
    FList.AddObject(Key, TStringPairsObject.Create(Value));
end;

function TStringPairs.Find(const Key: String; var Value: String): Boolean;
var
    Index: Integer;
begin
    if not Assigned(Flist) then
    begin
        Result := false;
        exit;
    end;
    Index := FList.IndexOf(Key);
    Result := (Index >= 0);
    if Result then Value := TStringPairsObject(FList.Objects[Index]).Value;
end;

procedure TStringPairs.Clear;
var
    I : Integer;
begin
    if NOT Assigned(Flist) then exit;
    for I := FList.Count - 1 downto 0 do FList.Objects[I].Free;
    FList.Clear;
end;

constructor TStringPairs.Create;
begin
    inherited Create;
    FList := TStringList.Create;
    FList.CaseSensitive := false;
    FList.Sorted := true;
end;

destructor TStringPairs.Destroy;
begin
    Clear;
    if Assigned(FList) then
    begin
        FList.Free;
        FList := nil;
    end;
    inherited Destroy;
end;

constructor TStringPairsObject.Create(const Data: String);
begin
    Value := Data;
end;

function TStringPairs.Count: Integer;
begin
    if NOT Assigned(Flist) then
        Result := 0
    else
        Result := FList.Count;
end;


end.
