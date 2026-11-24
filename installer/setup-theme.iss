{ Native controls, VELIQ palette. Theme selection affects this wizard only. }
var VeliqThemeChoice: TNewComboBox;
    VeliqAccentLine: TPanel;
    VeliqDark: Boolean;
    VeliqBackground, VeliqSurface, VeliqText: TColor;

function VeliqSetWindowTheme(Window: HWND; AppName, IDList: String): Integer;
 external 'SetWindowTheme@uxtheme.dll stdcall delayload';
function VeliqCaptionAttribute(Window: HWND; Attribute: Integer; var Value: Integer; Size: Integer): Integer;
 external 'DwmSetWindowAttribute@dwmapi.dll stdcall delayload';

procedure PaintVeliqControl(Control: TControl);
var I: Integer;
begin
 if Control is TPanel then begin
   TPanel(Control).Color := VeliqBackground;
   TPanel(Control).Font.Color := VeliqText;
 end else if Control is TNewNotebookPage then
   TNewNotebookPage(Control).Color := VeliqBackground
 else if Control is TNewStaticText then begin
   TNewStaticText(Control).Color := VeliqBackground;
   TNewStaticText(Control).Font.Color := VeliqText;
 end else if Control is TNewCheckListBox then begin
   TNewCheckListBox(Control).Color := VeliqBackground;
   TNewCheckListBox(Control).Font.Color := VeliqText;
 end else if Control is TMemo then begin
   TMemo(Control).Color := VeliqSurface;
   TMemo(Control).Font.Color := VeliqText;
 end else if Control is TEdit then begin
   TEdit(Control).Color := VeliqSurface;
   TEdit(Control).Font.Color := VeliqText;
 end else if Control is TComboBox then begin
   TComboBox(Control).Color := VeliqSurface;
   TComboBox(Control).Font.Color := VeliqText;
 end else if Control is TButton then
   TButton(Control).Font.Color := clBlack
 else if Control is TCheckBox then begin
   VeliqSetWindowTheme(TCheckBox(Control).Handle, '', '');
   TCheckBox(Control).Font.Color := VeliqText;
 end else if Control is TRadioButton then begin
   VeliqSetWindowTheme(TRadioButton(Control).Handle, '', '');
   TRadioButton(Control).Font.Color := VeliqText;
 end;
 if Control is TWinControl then
   for I := 0 to TWinControl(Control).ControlCount-1 do
     PaintVeliqControl(TWinControl(Control).Controls[I]);
end;

procedure ApplyVeliqTheme;
var DarkCaption, CaptionColor: Integer;
begin
 if VeliqDark then begin
   VeliqBackground := $0B0A0A; VeliqSurface := $171413; VeliqText := clWhite;
 end else begin
   VeliqBackground := clWhite; VeliqSurface := $F7F5F4; VeliqText := $0B0A0A;
 end;
 WizardForm.Color := VeliqBackground;
 WizardForm.Font.Color := VeliqText;
 PaintVeliqControl(WizardForm);
 WizardForm.WizardSmallBitmapImage.BackColor := VeliqBackground;
 WizardForm.WizardSmallBitmapImage.ReplaceColor := clWhite;
 WizardForm.WizardSmallBitmapImage.ReplaceWithColor := VeliqBackground;
 if VeliqAccentLine<>nil then VeliqAccentLine.Color := $2A50F0;
 if VeliqThemeChoice<>nil then begin
   if VeliqDark then VeliqThemeChoice.ItemIndex := 0 else VeliqThemeChoice.ItemIndex := 1;
 end;
 { Older Windows versions can ignore caption attributes without affecting setup. }
 try
   DarkCaption := 0; if VeliqDark then DarkCaption := 1;
   if VeliqCaptionAttribute(WizardForm.Handle, 20, DarkCaption, 4)<>0 then
     VeliqCaptionAttribute(WizardForm.Handle, 19, DarkCaption, 4);
   CaptionColor := VeliqBackground;
   VeliqCaptionAttribute(WizardForm.Handle, 35, CaptionColor, 4);
 except
   Log('VELIQ_THEME_CAPTION_UNAVAILABLE');
 end;
 WizardForm.Refresh;
end;

procedure VeliqThemeChanged(Sender: TObject);
begin
 VeliqDark := VeliqThemeChoice.ItemIndex=0;
 ApplyVeliqTheme;
end;

procedure InitializeVeliqTheme;
begin
 VeliqDark := True;
 VeliqThemeChoice := TNewComboBox.Create(WizardForm);
 VeliqThemeChoice.Parent := WizardForm;
 VeliqThemeChoice.Style := csDropDownList;
 VeliqThemeChoice.SetBounds(ScaleX(16), WizardForm.BackButton.Top, ScaleX(152), WizardForm.BackButton.Height);
 VeliqThemeChoice.Items.Add('Тёмная тема');
 VeliqThemeChoice.Items.Add('Светлая тема');
 VeliqThemeChoice.ItemIndex := 0;
 VeliqThemeChoice.OnChange := @VeliqThemeChanged;
 VeliqAccentLine := TPanel.Create(WizardForm);
 VeliqAccentLine.Parent := WizardForm;
 VeliqAccentLine.BevelOuter := bvNone;
 VeliqAccentLine.SetBounds(0, WizardForm.Bevel.Top, WizardForm.ClientWidth, ScaleY(2));
 ApplyVeliqTheme;
end;
