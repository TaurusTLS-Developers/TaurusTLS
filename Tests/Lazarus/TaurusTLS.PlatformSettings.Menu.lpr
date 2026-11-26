program TaurusTLSPlatformSettingsMenu;

{$mode delphi}{$H+}

uses
  Interfaces, Classes, SysUtils, Controls,
  TaurusTLSLoader, TaurusTLSExceptionHandlers;

type
  EPlatformSettingsMenuTest = class(Exception);

  TDesignLoader = class(TTaurusTLSLoader)
  public
    constructor Create(AOwner: TComponent); override;
  end;

constructor TDesignLoader.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  SetDesigning(True);
end;

procedure Check(ACondition: Boolean; const AMessage: string);
begin
  if not ACondition then
    raise EPlatformSettingsMenuTest.Create(AMessage);
end;

procedure CheckMenuCapacity;
var
  LLoader: TDesignLoader;
  LMenu: Controls.IObjInspInterface;
  LTarget, LRemovedTarget: TTaurusTLSPlatform;
  LRejected: Boolean;
  LCapacity: Integer;
begin
  LLoader := TDesignLoader.Create(nil);
  try
    // Use the real LCL declaration and the same query as the Object Inspector.
    // This checks the GUID, CORBA convention and method order of the adapter.
    Check(LLoader.PlatformSettings.GetInterface(Controls.GUID_ObjInspInterface,
      LMenu), 'Object Inspector interface must be available');
    Check(LMenu.AllowDelete, 'Existing deletion policy must be preserved');
    for LTarget := Low(TTaurusTLSPlatform) to High(TTaurusTLSPlatform) do
    begin
      Check(LMenu.AllowAdd, 'Add Item must be offered while a target is available');
      LLoader.PlatformSettings.Add;
    end;
    LCapacity := Ord(High(TTaurusTLSPlatform)) - Ord(Low(TTaurusTLSPlatform)) + 1;
    Check(LLoader.PlatformSettings.Count = LCapacity, 'All targets must be present');
    Check(not LMenu.AllowAdd, 'Add Item must be hidden when the collection is full');

    // Menu filtering supplements the runtime guard; it must not remove it.
    LRejected := False;
    try
      LLoader.PlatformSettings.Add;
    except
      on ETaurusTLSLoaderError do
        LRejected := True;
    end;
    Check(LRejected, 'Direct overflow must still raise the loader exception');
    Check(LLoader.PlatformSettings.Count = LCapacity, 'Rejected Add must not attach an item');

    LRemovedTarget := LLoader.PlatformSettings[2].Target;
    LLoader.PlatformSettings[2].Free;
    Check(LMenu.AllowAdd, 'Add Item must return after deletion');
    Check(LLoader.PlatformSettings.Add.Target = LRemovedTarget,
      'The newly available target must be selected');
    Check(not LMenu.AllowAdd, 'Add Item must be hidden again after replacement');
  finally
    LMenu := nil;
    LLoader.Free;
  end;
end;

procedure CheckRuntimeGuard;
var
  LLoader: TTaurusTLSLoader;
  LRejected: Boolean;
begin
  LLoader := TTaurusTLSLoader.Create(nil);
  try
    LRejected := False;
    try
      LLoader.PlatformSettings.Add;
    except
      on ETaurusTLSLoaderError do
        LRejected := True;
    end;
    Check(LRejected, 'Runtime collection edits must remain forbidden');
    Check(LLoader.PlatformSettings.Count = 0, 'Runtime rejection must preserve the collection');
  finally
    LLoader.Free;
  end;
end;

begin
  try
    CheckMenuCapacity;
    CheckRuntimeGuard;
    Writeln('PASS: Lazarus menu capacity, deletion, replacement, overflow and runtime guards');
  except
    on E: Exception do
    begin
      Writeln(ErrOutput, E.ClassName, ': ', E.Message);
      ExitCode := 1;
    end;
  end;
end.
