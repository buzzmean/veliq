# Каталог игр VELIQ — минимальная версия1

Страница «Игры» в обычном GUI: карточки, поиск по игре/лаунчеру, выбор маршрута
и «Применить». Просмотр не создаёт профили и не запускает процессы.10 записей:
VALORANT, League of Legends, CS2, Dota2, PUBG, Fortnite, Apex, Rust, GTAV, RDR2.
Exe allowlist находится в embedded Resources/GameCatalog.json: это известные
имена Windows-дистрибутивов, не скан памяти/обещание установки именно на этом ПК.
Варианты других магазинов/новые версии exe требуют обновления каталога; GTAV
Enhanced и другие непроверенные имена не подставляются автоматически. Иконки —
текстовые монограммы, не заимствованные логотипы и не новая брендовая иконка.

## Данные и доверие
JSON version1 встроен в desktop-core, SHA256 закреплён в сборке. Установленные
файлы не используются как unsigned override; загрузки из сети нет. Доверие
bundled-каталогу следует доверию установленной сборке; это НЕ заявление, что
текущая сборка имеет production code signature. Чистая Parse проверяет hash,
version, уникальность и ограничение<=64entries/64KiB, exe без каталогов, безопасные
DIRECT defaults. VerifySigned предусматривает RSA-PSS/SHA256 envelope с отдельно
доверенным публичным ключом владельца (ключ не берётся из самого каталога).
Подпись проверяется до разбора. Подписание/доставка обновлений НЕ включены;
новый private key не создавался, CA/CP/activation не используются. Перед внешними
обновлениями нужен отдельный owner-pinned public key и release signing workflow.
Это не дублирует существующий server strategy catalog и не исполняет команды.

## Маршруты и сохранность
Все10 рекомендаций DIRECT. AUTO игры сохраняет service-контракт: обычный DIRECT,
не выбор иностранного relay по общему тестовому RTT. Единственное автоматическое
исключение — уже существующие opt-in game UDP presets со своими guards/настройками.
Существующий подходящий профиль копируется со всеми extension metadata; новый
профиль создаётся лишь при «Применить», custom game-<id>. exe списка относятся
к игре; Riot Client — отдельный встроенный профиль. Owner SID, identity, config,
ACL/IPC и формат профилей не меняются. Новые соединения; existing TCP/UDP pinned.

DIRECT+ в этой минимальной странице включает существующий gameudp для уже
обнаруженного точного полного пути и готового UDP-пресета (PUBG/Dota2). Это не
автоматически выбранная TCP desync-стратегия для всех игр. Без preset/path или
при unsafe mode запрос не посылается, показывается причина, маршрут сохраняется.
Служба повторно проверяет compatibility/guard, не UI. При DIRECT для готового
профиля UDP-обход выключается; при ошибке второй операции UI сообщает, что
режим не подтверждён — надо обновить статус. Для RELAY нужен живой server route,
предупреждение о возможном увеличении пинга видно до выбора; сохраняется MANUAL.
Релею не приписывается снижение ping без RTT/jitter/loss реального сервера.

Vanguard/FACEIT: по умолчанию не включаем обход, совместимость не проверена.
Никаких инъекций в игру, чтения памяти/файлов игры, изменений античита. Условия
PUBG/BattlEye остаются прежними. «Исправить лаунчер» работает только для Riot:
переводит существующий riot-client в AUTO, не меняет exe игры/античит/оптимизацию
в целом. Другие launcher repair пока disabled: нельзя объявлять их исправленными.
Riot status отражает наблюдённые LOCAL/RELAY bytes, не логин/успешный patch; без
обмена честно ожидает подтверждения. Refresh читает service profiles, riot.status,
gameudp.status; Apply — profile.set/gameudp.set/status, все через controller.

Клубный гостевой ClubWindow не менялся, technical/admin функции туда не добавлены.
Служебный CLUB_ADMIN_MANAGED сохраняется: каталог не обходит блокировку клубных
настроек. Для изменения образа/клубной политики остаётся штатный администраторский
процесс; этот этап не добавляет удалённое управление40ПК.

## Проверка
Unit: embedded schema/hash/signature rejection,10safe defaults, поиск без мутаций,
AUTO не включает relay/UDP, guarded DIRECT+ отказ, repair толькоRiot с metadata,
статус с bytes не обещает запуск. WPF compile проверяет BAML/handlers/resources;
это не native Windows UI/driver/ISP acceptance. На ПК: обновить service+GUI,
посмотреть каталог, включить Riot AUTO, запустить Riot безwinws, проверить
patch/login; игры/античит DIRECT. Diag -Only riot,browser даёт TCP/TLS по A и
фактические flow routes. Без SSH/VPS deployment и без закрытия браузеров.

Результаты24.10:208 C# tests PASS; WPF cross-target build PASS (4 прежних
CS8604 в recovery files). Native Windows WPF/visual bindings не запускались.
Go race/vet/Linux+Windows build/Windows vet и pinned DLL gates выполнены в
Riot этапе после последней Go-правки. PS7 formatter/legacy fixtures PASS;
native Windows PowerShell5.1 недоступен, совместимость синтаксиса не заменяет
его runtime acceptance. Ошибки нового экрана передают только phase/type/code
в существующий gui-failure.json; сырые IPC payload/exception text не пишутся.
