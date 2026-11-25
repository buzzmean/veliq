{ Оформление мастера не меняет выбранное действие и состояние установки. }
var VeliqThemeButton: TNewButton;
    VeliqVersionLabel: TNewStaticText;
    VeliqFooterLine: TPanel;
    VeliqDark: Boolean;
    VeliqBackground, VeliqSurface, VeliqText, VeliqMuted, VeliqLine: TColor;

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
 end else if Control is TNewNotebook then
   TNewNotebook(Control).Color := VeliqBackground
 else if Control is TNewNotebookPage then
   TNewNotebookPage(Control).Color := VeliqBackground
 else if Control is TBitmapImage then
   TBitmapImage(Control).BackColor := VeliqBackground
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

procedure LayoutVeliqWizard;
var Left, Width, Top, Height, Gap: Integer;
begin
 { Все размеры проходят через масштабирование шрифта/DPI самого Inno. }
 WizardForm.Bevel.Visible := False;
 WizardForm.Bevel1.Visible := False;
 WizardForm.WizardSmallBitmapImage.Visible := False;
 WizardForm.MainPanel.Height := ScaleY(98);
 WizardForm.PageNameLabel.SetBounds(ScaleX(32), ScaleY(18),
   WizardForm.MainPanel.Width-ScaleX(64), ScaleY(28));
 WizardForm.PageNameLabel.Font.Size := 14;
 WizardForm.PageNameLabel.Font.Style := [fsBold];
 WizardForm.PageDescriptionLabel.SetBounds(ScaleX(32), ScaleY(54),
   WizardForm.MainPanel.Width-ScaleX(64), ScaleY(36));
 WizardForm.InnerNotebook.SetBounds(ScaleX(32), ScaleY(110),
   WizardForm.InnerPage.Width-ScaleX(64), WizardForm.InnerPage.Height-ScaleY(130));

 Left := WizardForm.WizardBitmapImage.Width+ScaleX(32);
 Width := WizardForm.WelcomePage.Width-Left-ScaleX(32);
 WizardForm.WelcomeLabel1.SetBounds(Left, ScaleY(38), Width, ScaleY(60));
 WizardForm.WelcomeLabel2.SetBounds(Left, ScaleY(116), Width,
   WizardForm.WelcomePage.Height-ScaleY(148));
 WizardForm.FinishedHeadingLabel.SetBounds(Left, ScaleY(38), Width, ScaleY(60));
 WizardForm.FinishedLabel.SetBounds(Left, ScaleY(116), Width, ScaleY(66));
 WizardForm.RunList.SetBounds(Left, ScaleY(206), Width,
   WizardForm.FinishedPage.Height-ScaleY(230));

 Gap := ScaleX(8);
 Top := WizardForm.Bevel.Top+ScaleY(12);
 Height := ScaleY(30);
 WizardForm.CancelButton.SetBounds(WizardForm.ClientWidth-ScaleX(108), Top, ScaleX(88), Height);
 WizardForm.NextButton.SetBounds(WizardForm.CancelButton.Left-Gap-ScaleX(120), Top, ScaleX(120), Height);
 WizardForm.BackButton.SetBounds(WizardForm.NextButton.Left-Gap-ScaleX(88), Top, ScaleX(88), Height);
 if not WizardForm.CancelButton.Visible then
   WizardForm.NextButton.Left := WizardForm.ClientWidth-ScaleX(140);
 if VeliqThemeButton<>nil then VeliqThemeButton.SetBounds(ScaleX(20), Top, ScaleX(116), Height);
 if VeliqVersionLabel<>nil then VeliqVersionLabel.SetBounds(ScaleX(148), Top+ScaleY(8), ScaleX(100), ScaleY(18));
 if VeliqVersionLabel<>nil then
   VeliqVersionLabel.Visible := VeliqVersionLabel.Left+VeliqVersionLabel.Width+ScaleX(12)<WizardForm.BackButton.Left;
 if VeliqFooterLine<>nil then VeliqFooterLine.SetBounds(0, WizardForm.Bevel.Top, WizardForm.ClientWidth, ScaleY(1));
end;

procedure ApplyVeliqTheme;
var DarkCaption, CaptionColor: Integer;
begin
 if VeliqDark then begin
   VeliqBackground := $0B0A0A; VeliqSurface := $171413; VeliqText := clWhite;
   VeliqMuted := $BFB9B5; VeliqLine := $3B3430;
 end else begin
   VeliqBackground := clWhite; VeliqSurface := $F7F5F4; VeliqText := $0B0A0A;
   VeliqMuted := $554C47; VeliqLine := $EEEBE9;
 end;
 WizardForm.Color := VeliqBackground;
 WizardForm.Font.Color := VeliqText;
 PaintVeliqControl(WizardForm);
 { Фон изображения рисуется отдельно от родителя. Он и давал белую рамку. }
 WizardForm.WizardBitmapImage.BackColor := $0B0A0A;
 WizardForm.WizardBitmapImage2.BackColor := $0B0A0A;
 WizardForm.ReadyMemo.Color := VeliqSurface;
 WizardForm.ReadyMemo.Font.Color := VeliqText;
 WizardForm.ReadyMemo.BorderStyle := bsNone;
 WizardForm.ReadyMemo.ScrollBars := ssVertical;
 WizardForm.PageDescriptionLabel.Font.Color := VeliqMuted;
 WizardForm.WelcomeLabel2.Font.Color := VeliqMuted;
 WizardForm.FinishedLabel.Font.Color := VeliqMuted;
 if VeliqFooterLine<>nil then VeliqFooterLine.Color := VeliqLine;
 if VeliqVersionLabel<>nil then VeliqVersionLabel.Font.Color := VeliqMuted;
 if VeliqThemeButton<>nil then begin
   if VeliqDark then VeliqThemeButton.Caption := 'Светлая тема'
   else VeliqThemeButton.Caption := 'Тёмная тема';
 end;
 LayoutVeliqWizard;
 { Старые Windows могут не поддерживать цвет заголовка. }
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
 VeliqDark := not VeliqDark;
 ApplyVeliqTheme;
end;

procedure InitializeVeliqTheme;
begin
 VeliqDark := True;
 VeliqThemeButton := TNewButton.Create(WizardForm);
 VeliqThemeButton.Parent := WizardForm;
 VeliqThemeButton.Font.Size := 9;
 VeliqThemeButton.OnClick := @VeliqThemeChanged;
 VeliqThemeButton.TabStop := True;
 VeliqVersionLabel := TNewStaticText.Create(WizardForm);
 VeliqVersionLabel.Parent := WizardForm;
 VeliqVersionLabel.Caption := 'VELIQ {#AppVersion}';
 VeliqVersionLabel.Font.Size := 8;
 VeliqFooterLine := TPanel.Create(WizardForm);
 VeliqFooterLine.Parent := WizardForm;
 VeliqFooterLine.BevelOuter := bvNone;
 ApplyVeliqTheme;
end;
