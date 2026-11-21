# Автоматическая маршрутизация уже открытых браузеров

## A. Конфигурация и подготовка

Новая установка и восстановление после freeze создают Chrome/Edge AUTO с
`browser_transport=native`. Это конфигурация, а не утверждение о доступности
сайта. Пока Optimize выключен, capture не запускается ради создания профиля.
При активном Optimize публикация native требует готового backend; перед
включением проверяется конфигурация capture и owner SID. PAC/nonce не являются
предпосылкой для native AUTO. Прежний legacy PAC-путь остаётся отдельным режимом.

Старые автоматически созданные DIRECT/pending без пользовательских правил,
стратегии и явного отказа мигрируют в native AUTO. ID, полный путь, identity,
правила и остальные приложения не пересоздаются. Явный выбор режима, отличного
от AUTO, сохраняет `browser_auto_disabled`; startup его не отменяет.

Каталог использует стандартные системные/пользовательские пути и read-only
App Paths / Clients StartMenuInternet в обеих registry views. Нет process scan,
чтения памяти или elevation GUI. Opera GX учитывается отдельно.

Brave, Яндекс, Opera/GX и Firefox обнаруживаются, но пока не объявлены
автоматически поддерживаемыми: нет их native Windows acceptance, Firefox имеет
другой policy/HTTP3 стек, а browser.exe не уникален для Яндекса. Не регистрируем
их как Chrome и не записываем им чужой PAC. Расширение поддержки требует
отдельного owner-bound native browser fixture, а не переименования exe.

## Ограничения проверки

В облачном окружении Linux нельзя подтвердить Chrome157/Edge live policy refresh,
WinDivert/SCM, пользовательский ISP или фактический срок запуска сайта. Ни
`RefreshPolicyEx`, ни registry presence не выдаются за live uptake. Нативный путь
не расшифровывает TLS и не меняет уже существующие TCP; они PINNED_UNTIL_CLOSED.

Native capture не является независимым kernel crash guard: при падении процесса
WinDivert освобождает handles. Сохранён прежний разрешённый владельцем availability
contract; новый WFP/driver guard здесь не добавляется. Во время активного capture
неоднозначный TLS/ECH не получает DIRECT-авторизацию. Нельзя заявлять безусловный
protected no-leak при смерти всего процесса без независимого guard.

## B. Основной путь без PAC

GUI не ждёт PolicyReady для native и не вызывает silent PAC prepare для native
профилей. Fresh/repair используют тот же native prepare и проверяют capture,
а не наличие ProxySettings. Classifier больше не заменяет native AUTO на DIRECT
из-за неготового PAC. Legacy PAC путь проверяется по-прежнему. При восстановлении
старого журнала native-профили не вызывают новую запись политики; owned policy
снимается, cached PAC обслуживается совместимым listener до прекращения запросов.
Чужая policy не удаляется.

Новый IPv4 TCP выбранного браузера сначала принимается WinDivert deferred
backend, затем bounded исходный ClientHello/HTTP Host определяет маршрут.
Известные заблокированные группы идут relay-first; обычный видимый домен —
DIRECT-first с существующим bounded recovery. ECH outer name не считается
доменом назначения: исходные TLS bytes идут в authenticated relay к исходному IP,
без DIRECT fallback. Никакой расшифровки, подмены сертификатов или ECH stripping.

Opaque UDP/443 идёт authenticated RELAY_REQUIRED; DNS/53 остаётся DIRECT.
При отказе QUIC возможен штатный TCP fallback браузера, его время не обещается.
IPv6 native транспорт не реализован: существующий app-scoped IPv6 guard блокирует
неподдерживаемый flow; IPv4 попытка браузера обслуживается. Нельзя заявлять IPv6
support. DoH, coalescing и ECH могут сделать домен непрозрачным: тогда relay-only,
не эвристическая DIRECT-авторизация по IP. Это может повысить нагрузку VPS.
Лимит googlevideo8, очередь2с и byte/tunnel accounting сохраняются.

Chrome157 live policy uptake не подтверждён и НЕ является условием native пути.
Доказательство native-only — реальные записи NATIVE_TCP, owner PID/birth и
bidirectional bytes отдельно от PAC_CONNECT/PAC_NATIVE_UPSTREAM; сами bytes не
доказывают HTTP/TLS/page success. Старые TCP не сбрасываются и не мигрируют;
новая вкладка может переиспользовать старый HTTP/2 connection до его закрытия.

## C. Готовность и время

Главная показывает «Подготавливаем браузер…», затем готовность новых соединений
по actual backend + relay, без требования PAC. browser.native.status содержит
state/reason/configured_profiles/guard, отдельно native-only и PAC upstream.
Время AUTO-публикации при уже включённом capture сохраняется до первого flow;
последующий enable не сбрасывает часы. First-open/first-exchange — наблюдаемые
события, не обещание «сайт готов за N секунд». На ISP/Chrome157 требуемый срок
ещё не измерен. Обычный polling GUI — до2с во время подготовки; нет restart wait.

## D. Выключение и выход

Fresh native не записывает ProxySettings и не требует proxy listener. OFF
сразу прекращает классификацию новых потоков выбранного браузера; AUTO-намерение
остаётся, чтобы ON снова работал автоматически. Отключение только браузера
сохраняет opt-out и касается новых соединений: established TCP не пересоздаются
при редактировании профиля. Игры/остальные приложения не получают новый режим.

Для прежнего cached PAC действуют BROWSER_DISABLE_RECOVERY.md: OS DIRECT у
owner-validated listener после OFF/Exit, retirement только после idle без
активных sockets, уведомление user GP и завершение helper при штатном SCM stop.
Нельзя выдавать уведомление за фактическое обновление chrome://policy.
Современный availability PAC имеет DIRECT; чужой/старый PAC без DIRECT — явно
описанное ограничение. Никаких browser kill/quit/restart в выключении нет.

## E. Обычный интерфейс

PAC Chrome/Edge, ручные lane-кнопки и origin-probe таблицы доступны только в
«Расширенной диагностике». Обычный Optimize и AUTO для строки браузера используют
native; фоновый startup не запускает optional PAC подготовку. Legacy AUTO с
правилами/проверенной стратегией мигрирует в native с сохранением этих полей и
relay ID; явный DIRECT/custom/opt-out не перезаписывается. Ошибка регистрации
видима понятным статусом; fixed IPC code/phase записываются в журнал без payload.
Неуспешный native prepare повторяется через2с, успешный проверяется периодически.
Видимая готовность снимается при потере capture/connected, а не остаётся от
предыдущего успешного опроса. Реальный WPF внешний вид здесь не проверен.

## F. Проверки и границы доказательства

TestWindowsNativeBrowserStartsBeforeControllerWithoutPAC запускает настоящий
Chrome/Edge раньше контроллера. Без policy/proxy flags тот же PID/birth получает
контролируемый HTTP body до запуска, через native deferred Host + QUIC/mTLS
one-shot ticket relay после запуска, DIRECT после OFF/host close. Источник
relay127.0.0.3 отличается от DIRECT127.0.0.1; required open не имеет fallback.
Имитируется только privileged packet reflection в TCP accept; это не запуск
WinDivert/SCM и не Internet/HTTPS PASS. Фикстура включена отдельным шагом Windows
workflow; здесь скомпилирована, не выполнена. TLS с проверкой сертификата через
relay отдельно покрывается integration/relay_origin_test.go.

Проверки обнаружили отсутствие автоматического старта при повторном запуске GUI
после Exit: добавлен один автоматический start для нового GUI lifetime при
Automatic и native AUTO. Явный OFF/Exit подавляет дальнейший auto-start в этом
окне; настройка Automatic=false не обходится. Нет browser process manipulation.
Новые C# регрессии проверяют оба случая.

## G. Приёмка владельца

Команды по одной: [BROWSER_AUTOMATIC_ACCEPTANCE.md](BROWSER_AUTOMATIC_ACCEPTANCE.md).
Read-only test-browser-startup.ps1 фиксирует оба уже открытых браузера до GUI,
затем требует native-only exchanges каждого профиля и сохранённые PID/birth.
Ни policy presence, ни PAC bytes, ни один односторонний пакет не дают PASS.
Скрипт не управляет браузерами, не выполняет install/enroll и не ходит на VPS.

Для новой native установки/install/update app-scoped TCP firewall admission
проверяется автоматически (прежний helper, без расширения scope). Это нужно
для Windows reflected SYN в service listener; отсутствие правила не должно
превращаться в требование ручного -NativeTcpFirewall. Denial/foreign policy
не обходится. Identity/ACL/certs и правила игр не меняются.

Ограничение opaque ECH: без достоверного hostname per-domain DNS recovery не
может безопасно восстановить ошибочный исходный IP. Такой flow остаётся relay-only
к исходному адресу и может завершиться ошибкой; Internet успех не обещается.
Лимит googlevideo применяется к достоверно определённому домену; opaque relay
остаётся в общем bounded pool и отображается отдельно, его нагрузку надо измерить.

Запоздалый native enable после OFF отвергается самой службой под общим
activationMu и не запускает driver заново; старая GUI-задача не отменяет OFF.
Отдельный тест проверяет NATIVE_OPTIMIZATION_DISABLED и отсутствие capture start.
Fresh browser.status/edge.status показывают native readiness отдельно от
listening/policy_ready=false: отсутствие PAC listener теперь ожидаемо.
