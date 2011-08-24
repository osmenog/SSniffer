unit AdaptorSelector;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs,MagentaPackHdrs,MagentaMonpcap, StdCtrls;

type
  TfrmAdapterSelect = class(TForm)
    grp1: TGroupBox;
    btnSave: TButton;
    cbAdapterList: TComboBox;
    Label1: TLabel;
    Label2: TLabel;
    lblAdapterName: TLabel;
    lblAdapterDesc: TLabel;
    procedure btnSaveClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure cbAdapterListChange(Sender: TObject);
  private
    AdapterListName: TStringList;
    AdapterListDesc: TStringList;
  public
    SelAdapterName: string; //Параметры выбранного адаптера
    SelAdapterDesc: string; //
  end;

var
  frmAdapterSelect: TfrmAdapterSelect;

implementation

{$R *.dfm}

procedure TfrmAdapterSelect.btnSaveClick(Sender: TObject);
begin
	SelAdapterName:=AdapterListName[cbAdapterList.ItemIndex];
  SelAdapterDesc:=AdapterListDesc[cbAdapterList.ItemIndex];
  ModalResult:=mrOk;
	Hide;
end;

procedure TfrmAdapterSelect.cbAdapterListChange(Sender: TObject);
begin
  with cbAdapterList do
  begin
    lblAdapterDesc.Caption:=Items[ItemIndex];
    lblAdapterName.Caption:=AdapterListName[ItemIndex];
  end;
end;

procedure TfrmAdapterSelect.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  if ModalResult<>mrOk then ModalResult:=mrCancel;
  if AdapterListDesc<>nil then AdapterListDesc.Free;
  if AdapterListName<>nil then AdapterListName.Free;
end;

procedure TfrmAdapterSelect.FormCreate(Sender: TObject);
var
	Mon:TMonitorPcap;
begin
  cbAdapterList.Clear;
  AdapterListDesc:=TStringList.Create;
  AdapterListName:=TStringList.Create;

  Mon:=TMonitorPcap.Create(nil);
  AdapterListName.Assign(Mon.AdapterNameList);
  AdapterListDesc.Assign(Mon.AdapterDescList);
  Mon.Free;

  cbAdapterList.Items.Assign (AdapterListDesc);
  cbAdapterList.ItemIndex:=0;
  cbAdapterList.OnChange(Self);
end;

end.
