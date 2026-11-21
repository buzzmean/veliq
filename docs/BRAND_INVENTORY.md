# E1: инвентаризация и импорт утверждённого бренда

21.10.2026. Инвентаризация выполнена **перед** импортом assets/brand из
2dfdb483e15abf7a0714347c973647b2c38b31f1. Это четыре SVG, не слияние постороннего
runtime/истории ветки. Исходные SVG сохраняются байт-в-байт, без выдуманного логотипа.

| Поверхность | Что найдено / решение |
|---|---|
| MainWindow title, sidebar text, tray | Уже VELIQ; header получает утверждённый symbol как WPF drawing из SVG |
| Resources/Strings.resx, activation/UI errors | Пользовательские строки уже VELIQ; поиск старого имени в значениях resources — без совпадений |
| Desktop csproj | AssemblyName/Product VELIQ; namespace/project file остаются совместимыми |
| Service DisplayName | VELIQ Routing Service; SCM name neexitlag не менять |
| Setup/ярлык | VELIQ-Setup.exe, VELIQ в Inno/Start menu; нет нового NeExitLag ярлыка |
| EXE alias | VELIQ.exe + идентичный NeExitLag.exe; один прежний SID-scoped mutex/pipe |
| ICO resource | Assets/NeExitLag.ico сохраняется; это совместимый internal resource. В этой поставке не генерируется новый ICO наугад; Windows/tray ICO export из SVG — оставшаяся задача упаковки |
| Хранилище/IPC | ProgramData/neexitlag, LOCALAPPDATA/NeExitLag, neexitlag-v1, Run value, journals без миграции |
| PAC/recovery | Прежние owned host/registry markers, owner SID, ACL и форматы — без замены |
| Go module, server, mTLS | GitHub repo/module, ALPN neexitlag/*, identities/certificates/schema/VPS пути — без изменений |
| README/технические docs | Старые имена в командах/путях описывают совместимость; не blind replace |
| Старый branding doc | Исправлена устаревшая инструкция закрывать Chrome; браузеры не закрываются |
| website/brand тексты | Уже сохранены отдельным merge; сейчас не переписываются |

Импорт: veliq3-symbol.svg / symbol-reverse.svg и wordmark-dark.svg /
wordmark-light.svg. Source metadata/geometry/цвета сохраняются. WPF-версия
symbol-reverse использует те же paths, transforms, slit и source accent; тело
UI остаётся чёрно-белым. Внешний SVG renderer, новая библиотека и random icon
не добавляются. SVG не содержит скриптов/внешних ресурсов/шрифтов.

Обновление существующей установки — обычные build-desktop/install-desktop:
binary backup/alias/ярлыки обрабатываются текущим installer; конфигурация, device
identity, owner SID, credentials и браузерные recovery данные не переименовываются.
Ресурсный импорт не вызывает service/enroll/registry/network operations.

Проверки: XML/geometry/source SHA, C# regressions и WPF cross-build. Существующие
native upgrade fixtures остаются в tests/desktop-native и tests/windows-tools;
их свежий Windows runtime прогон здесь недоступен. Внешний вид нового header,
installer/tray raster и фактический upgrade на ПК ещё не проверены. Этот документ
не выдаёт импорт SVG за проверенную миграцию всех Windows shell icons.
