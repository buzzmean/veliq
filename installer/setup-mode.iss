{ Pure policy shared by the actual wizard and the compiled inert Windows tests. }
type TVeliqVersionParts = array[0..3] of Integer;

function ParseVeliqVersion(Value: String; var Parts: TVeliqVersionParts): Boolean;
var I, Part, Digit: Integer;
begin
 Result := False;
 for I := 0 to 3 do Parts[I] := 0;
 if Value='' then Exit;
 Part := 0;
 for I := 1 to Length(Value) do begin
   if Value[I]='.' then begin
     if (I=1) or (Value[I-1]='.') or (Part=3) then Exit;
     Part := Part + 1;
   end else begin
     if (Value[I]<'0') or (Value[I]>'9') then Exit;
     Digit := Ord(Value[I]) - Ord('0');
     if Parts[Part]>6553 then Exit;
     Parts[Part] := Parts[Part]*10 + Digit;
     if Parts[Part]>65535 then Exit;
   end;
 end;
 Result := (Part>=2) and (Value[Length(Value)]<>'.');
end;

function CompareVeliqVersions(Installed, Incoming: String; var Comparison: Integer): Boolean;
var A, B: TVeliqVersionParts; I: Integer;
begin
 Comparison := 0;
 Result := ParseVeliqVersion(Installed, A) and ParseVeliqVersion(Incoming, B);
 if not Result then Exit;
 for I := 0 to 3 do begin
   if A[I]<B[I] then begin Comparison := -1; Exit; end;
   if A[I]>B[I] then begin Comparison := 1; Exit; end;
 end;
end;

function ResolveVeliqOperation(Existing: Boolean; Installed, Incoming, Requested: String): String;
var Comparison: Integer; Known: Boolean;
begin
 Requested := Uppercase(Requested);
 Result := 'INSTALL_ACTION_INVALID';
 if (Requested<>'') and (Requested<>'INSTALL') and (Requested<>'UPDATE') and (Requested<>'REINSTALL') then Exit;
 if not Existing then begin
   if (Requested='UPDATE') or (Requested='REINSTALL') then Result := 'INSTALL_EXISTING_INSTALL_REQUIRED'
   else Result := 'INSTALL';
   Exit;
 end;
 Known := CompareVeliqVersions(Installed, Incoming, Comparison);
 if Known and (Comparison>0) then begin Result := 'INSTALL_DOWNGRADE_REFUSED'; Exit; end;
 if Requested='INSTALL' then begin Result := 'INSTALL_ALREADY_PRESENT'; Exit; end;
 if Requested<>'' then begin
   if (Requested='UPDATE') and not Known then Result := 'INSTALL_VERSION_UNKNOWN'
   else Result := Requested;
   Exit;
 end;
 if Known and (Comparison<0) then Result := 'UPDATE' else Result := 'REINSTALL';
end;

function VeliqOperationCaption(Operation: String): String;
begin
 if Operation='UPDATE' then Result := 'Обновить'
 else if Operation='REINSTALL' then Result := 'Переустановить'
 else Result := 'Установить';
end;

function VeliqFailureMessage(Code: String): String;
begin
 if (Code='INSTALL_GUI_GRACEFUL_CLOSE_FAILED') or (Code='INSTALL_GUI_CLOSE_TIMEOUT') or
    (Code='INSTALL_RECOVERY_HELPER_CLOSE_TIMEOUT') then
   Result := 'Не удалось закрыть окно VELIQ. Выберите «Выход» в меню значка VELIQ возле часов и повторите обновление.'
 else if Code='INSTALL_FILE_IN_USE_OR_NOT_WRITABLE' then
   Result := 'Файл VELIQ занят или недоступен для записи. Закройте окно VELIQ через «Выход». Если отказ повторится, журнал укажет конкретный файл.'
 else if Code='INSTALL_REBOOT_REQUIRED' then
   Result := 'Ожидающая операция Windows затрагивает VELIQ или WinDivert. Замена файлов заблокирована; перезагрузка не выполняется.'
 else if Code='INSTALL_FOREIGN_SERVICE_REFUSED' then
   Result := 'Путь зарегистрированной службы VELIQ отличается от ожидаемого. Требуется проверить существующую установку.'
 else if Code='INSTALL_REPARSE_POINT_REJECTED' then
   Result := 'В каталоге установки обнаружена файловая ссылка. Требуется проверить путь к существующей установке.'
 else if Code='INSTALL_DOWNGRADE_REFUSED' then
   Result := 'Установлена более новая версия VELIQ. Скачайте актуальный установщик с veliqapp.ru/download.'
 else if Code='INSTALL_VERSION_UNKNOWN' then
   Result := 'Не удалось определить установленную версию. Для восстановления файлов выберите «Переустановить».'
 else if Code='INSTALL_EXISTING_INSTALL_REQUIRED' then
   Result := 'VELIQ не найден. Для этого компьютера выберите «Установить».'
 else if Code='INSTALL_ALREADY_PRESENT' then
   Result := 'VELIQ уже установлен. Выберите «Обновить» или «Переустановить».'
 else if Code='INSTALL_ACTION_INVALID' then
   Result := 'Некорректный режим установщика. Запустите его обычным двойным щелчком.'
 else Result := 'Не удалось подготовить VELIQ. Подробности сохранены в журнале диагностики.';
end;

function IsVeliqErrorCode(Value: String): Boolean;
var I: Integer;
begin
 Result := False;
 if (Length(Value)<4) or (Length(Value)>80) then Exit;
 for I := 1 to Length(Value) do
   if not (((Value[I]>='A') and (Value[I]<='Z')) or
           ((Value[I]>='0') and (Value[I]<='9')) or (Value[I]='_')) then Exit;
 Result := True;
end;
