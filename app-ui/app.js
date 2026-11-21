/* VELIQ — логика кликабельного макета. Состояния: off, connecting, on, error. */
(function () {
  var root = document.documentElement;
  var win = document.getElementById('win');
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };

  var S = { screen: 'home', state: 'off', error: null, warn: null, club: false, lang: 'ru', theme: 'dark',
    act: null, actErr: null, actExpiring: false, gamesNotice: '', game: 'cs2', search: '' };
  var timer;

  /* ---------- Тексты (RU + EN для ключевых строк) ---------- */
  var T = {
    ru: {
      'nav.home': 'Главная', 'nav.services': 'Сервисы', 'nav.games': 'Игры', 'nav.diag': 'Диагностика', 'nav.settings': 'Настройки', 'nav.about': 'О программе',
      'st.off': 'Выключено', 'st.connecting': 'Подключение', 'st.on': 'Работает', 'st.error': 'Ошибка',
      'go.off': 'Оптимизировать', 'go.off.sub': 'выключено', 'go.connecting': 'Подключаем', 'go.connecting.sub': 'строим маршруты', 'go.on': 'Работает', 'go.error': 'Повторить',
      'home.off': 'Выключено', 'home.off.sub': 'Нажмите кнопку — VELIQ построит оптимальный маршрут для каждого соединения.',
      'home.connecting': 'Подключение', 'home.connecting.sub': 'Замеряем пути и подключаем браузер. Обычно это занимает пару секунд.',
      'home.on': 'Работает', 'home.on.sub': 'Маршруты построены: заблокированное открывается, игры идут по самому быстрому пути. Браузер перезапускать не нужно.',
      'home.error': 'Не работает', 'club.chip': 'Клубный ПК 14',
      'set.start': 'Запуск', 'set.autostart': 'Запускать вместе с Windows', 'set.autostart.d': 'Программа стартует свёрнутой в трей',
      'set.autoopt': 'Оптимизировать при запуске', 'set.autoopt.d': 'Не нужно нажимать кнопку после включения компьютера',
      'set.close': 'Закрытие окна сворачивает в трей', 'set.close.d': 'Маршрут продолжает работать',
      'set.server': 'Сервер', 'set.server.choice': 'Сервер для сервисов', 'set.server.d': '«Авто» выбирает самый быстрый и переключает при сбое',
      'set.look': 'Внешний вид', 'set.theme': 'Тема', 'set.theme.sys': 'Как в Windows', 'set.theme.light': 'Светлая', 'set.theme.dark': 'Тёмная', 'set.lang': 'Язык',
      'set.updates': 'Обновления', 'set.autoupd': 'Устанавливать обновления автоматически', 'set.autoupd.d': 'Ночью или при следующем запуске, без перезапуска браузера', 'set.check': 'Проверить обновления',
      'set.club': 'Компьютерный клуб', 'set.club.mode': 'Режим клуба', 'set.club.d': 'Простой экран для гостя, настройки под паролем, оптимизация при входе', 'set.club.on': 'Включить'
    },
    en: {
      'nav.home': 'Home', 'nav.services': 'Services', 'nav.games': 'Games', 'nav.diag': 'Diagnostics', 'nav.settings': 'Settings', 'nav.about': 'About',
      'st.off': 'Off', 'st.connecting': 'Connecting', 'st.on': 'Working', 'st.error': 'Error',
      'go.off': 'Optimize', 'go.off.sub': 'off', 'go.connecting': 'Connecting', 'go.connecting.sub': 'building routes', 'go.on': 'Working', 'go.error': 'Try again',
      'home.off': 'Off', 'home.off.sub': 'Press the button and VELIQ builds the best route for every connection.',
      'home.connecting': 'Connecting', 'home.connecting.sub': 'Checking servers and connecting the browser. Usually takes a couple of seconds.',
      'home.on': 'Working', 'home.on.sub': 'Routes are set: blocked services open, games take the fastest path. No browser restart needed.',
      'home.error': 'Not working', 'club.chip': 'Club PC 14',
      'set.start': 'Startup', 'set.autostart': 'Start with Windows', 'set.autostart.d': 'Starts minimized to the tray',
      'set.autoopt': 'Optimize on startup', 'set.autoopt.d': 'No need to press the button after the PC starts',
      'set.close': 'Closing the window keeps VELIQ in the tray', 'set.close.d': 'Routing keeps working',
      'set.server': 'Server', 'set.server.choice': 'Server for services', 'set.server.d': 'Auto picks the fastest and switches on failure',
      'set.look': 'Appearance', 'set.theme': 'Theme', 'set.theme.sys': 'Like Windows', 'set.theme.light': 'Light', 'set.theme.dark': 'Dark', 'set.lang': 'Language',
      'set.updates': 'Updates', 'set.autoupd': 'Install updates automatically', 'set.autoupd.d': 'At night or on next start, without restarting the browser', 'set.check': 'Check for updates',
      'set.club': 'Computer club', 'set.club.mode': 'Club mode', 'set.club.d': 'Simple guest screen, password-protected settings, optimizes at sign-in', 'set.club.on': 'Turn on'
    }
  };
  function t(k) { return (T[S.lang] && T[S.lang][k]) || T.ru[k] || k; }

  /* ---------- Ошибки: что случилось и что сделать (те же тексты — в brand/copy.md) ---------- */
  var ERR = {
    service: { short: 'VELIQ не может запуститься', title: 'VELIQ не может запуститься', text: 'Программа не может начать работу. Закройте VELIQ и откройте заново. Если не помогло — переустановите VELIQ или напишите нам.', act: 'Повторить', act2: 'Поддержка' },
    relay: { short: 'нет связи с сервером', title: 'Нет связи с сервером', text: 'Серверы VELIQ не отвечают с этого подключения. Интернет без VELIQ работает.', act: 'Повторить', act2: 'Диагностика' },
    browser: { short: 'часть сайтов не открывается', title: 'Часть сайтов не открывается', text: 'Для сайтов маршрут пока не построен, а приложения работают. Обычно помогает повтор.', act: 'Повторить', act2: 'Подробнее' },
    identity: { short: 'код активации не принят', title: 'Код активации не принят', text: 'Сервер не принял код активации для этого устройства. Введите код ещё раз. Если не помогло — напишите нам.', act: 'Ввести код', act2: 'Поддержка' }
  };
  var WARN = {
    update: { cls: 'banner--info', icon: 'download', title: 'Доступна версия 1.0.1', text: 'Обновление установится без перезапуска браузера и займёт около минуты.', act: 'Обновить' },
    fallback: { cls: 'banner--warn', icon: 'alert', title: 'Хельсинки не отвечает — работаем через Швецию', text: 'Сервисы открываются, пинг до них выше обычного. Вернём Хельсинки сами, когда он заработает.', act: 'Понятно' }
  };


  /* ---------- Активация: состояния и ошибки (соответствуют кодам службы, тексты — brand/copy.md) ---------- */
  var ACT_ERR = {
    ACTIVATION_INVALID: { title: 'Неверный код', text: 'Проверьте код и попробуйте ещё раз.' },
    ACTIVATION_EXPIRED: { title: 'Срок действия кода истёк', text: 'Запросите новый код.' },
    ACTIVATION_REVOKED: { title: 'Код отозван', text: 'Запросите новый код.' },
    ACTIVATION_LIMIT: { title: 'Для этого кода нет свободных мест', text: 'Попросите освободить место или выдать другой код.' },
    ACTIVATION_RATE_LIMIT: { title: 'Слишком много попыток', text: 'Подождите немного и попробуйте снова.' },
    DEVICE_REVOKED: { title: 'Доступ этого компьютера отключён', text: 'Напишите в поддержку.' },
    MACHINE_DISABLED: { title: 'Этот компьютер отключён', text: 'Напишите в поддержку.' },
    ACTIVATION_UNAVAILABLE: { title: 'Нет связи с VELIQ', text: 'Проверьте интернет и попробуйте ещё раз.' },
    HARDWARE_ID_UNAVAILABLE: { title: 'Не удалось определить этот компьютер', text: 'Код и интернет в порядке. Напишите в поддержку — поможем.' },
    ACTIVATION_TRUST_NOT_CONFIGURED: { title: 'Эта версия не готова к активации', text: 'Обновите VELIQ.' },
    ACTIVATION_STORAGE_FAILED: { title: 'Не удалось сохранить активацию', text: 'Закройте VELIQ и откройте заново. Если не помогло — напишите в поддержку.' },
    ACTIVATION_IDENTITY_CONFLICT: { title: 'Данные установки изменились', text: 'Напишите в поддержку — проверим регистрацию компьютера.' }
  };

  /* ---------- Каталог игр (как apps/desktop-core/Resources/GameCatalog.json) ---------- */
  var GAMES = [
    { id: 'valorant', name: 'VALORANT', icon: 'VAL', launcher: 'Riot Client', ac: 'Vanguard', udp: false, riot: true },
    { id: 'lol', name: 'League of Legends', icon: 'LOL', launcher: 'Riot Client', ac: 'Vanguard', udp: false, riot: true },
    { id: 'cs2', name: 'Counter-Strike 2', icon: 'CS2', launcher: 'Steam', ac: 'VAC / FACEIT', udp: false },
    { id: 'dota2', name: 'Dota 2', icon: 'DOT', launcher: 'Steam', ac: 'VAC', udp: true },
    { id: 'pubg', name: 'PUBG: BATTLEGROUNDS', icon: 'PUB', launcher: 'Steam', ac: 'BattlEye', udp: true },
    { id: 'fortnite', name: 'Fortnite', icon: 'FOR', launcher: 'Epic Games', ac: 'EAC / BattlEye', udp: false },
    { id: 'apex', name: 'Apex Legends', icon: 'APE', launcher: 'Steam / EA', ac: 'EAC', udp: false },
    { id: 'rust', name: 'Rust', icon: 'RUS', launcher: 'Steam', ac: 'EAC', udp: false },
    { id: 'gtav', name: 'Grand Theft Auto V', icon: 'GTA', launcher: 'Rockstar / Steam / Epic', ac: 'BattlEye (Online)', udp: false },
    { id: 'rdr2', name: 'Red Dead Redemption 2', icon: 'RDR', launcher: 'Rockstar / Steam / Epic', ac: 'Rockstar Online', udp: false }
  ];
  /* Режимы: AUTO, DIRECT, DIRECT_PLUS, MANUAL (RELAY) — в интерфейсе без технических слов */
  var MODES = [
    { v: 'AUTO', name: 'Авто', d: 'VELIQ сам решает для каждого соединения игры.' },
    { v: 'DIRECT', name: 'Обычный', d: 'Игра работает как без VELIQ. Режим по умолчанию.' },
    { v: 'DIRECT_PLUS', name: 'Обычный +', d: 'Обычный путь с улучшением игрового трафика.', udpOnly: true },
    { v: 'MANUAL', name: 'Через VELIQ', d: 'Весь трафик игры идёт через сервер VELIQ. Пинг может вырасти.' }
  ];
  var G = {}; GAMES.forEach(function (g) { G[g.id] = { saved: 'DIRECT', draft: 'DIRECT', profile: false, msg: '' }; });
  var riotFixed = false;
  function modeName(v) { for (var i = 0; i < MODES.length; i++) if (MODES[i].v === v) return MODES[i].name; return v; }
  function esc(x) { return String(x).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }

  function renderGames() {
    var q = S.search.trim().toLowerCase();
    var list = GAMES.filter(function (g) { return !q || g.name.toLowerCase().indexOf(q) >= 0 || g.launcher.toLowerCase().indexOf(q) >= 0; });
    var locked = S.gamesNotice === 'club' || S.gamesNotice === 'service';
    var box = $('[data-game-list]');
    box.innerHTML = list.length ? list.map(function (g) {
      var st = G[g.id];
      return '<button role="option" data-game="' + g.id + '" aria-selected="' + (g.id === S.game) + '" aria-pressed="' + (g.id === S.game) + '"><span class="mono">' + g.icon + '</span><span>' + esc(g.name) + '<small>' + esc(g.launcher) + '</small></span>' + (st.saved === 'DIRECT' ? '<span></span>' : '<span class="tag tag--relay">' + modeName(st.saved) + '</span>') + '</button>';
    }).join('') : '<p class="faint" style="padding:10px">Ничего не найдено. Проверьте название игры или лаунчера.</p>';
    var notice = { '': '', service: '<div class="banner banner--warn" style="margin-bottom:16px"><svg class="i"><use href="#i-alert"/></svg><div><strong>Служба VELIQ не отвечает</strong><p>Каталог открыт, но режимы сейчас не сохранить. Закройте VELIQ и откройте заново.</p></div></div>',
      club: '<div class="banner banner--info" style="margin-bottom:16px"><svg class="i"><use href="#i-lock"/></svg><div><strong>Настройками клуба управляет администратор</strong><p>Режимы игр на этом компьютере меняет администратор клуба.</p></div></div>' }[S.gamesNotice];
    $('[data-games-notice]').innerHTML = notice;
    var g = GAMES.filter(function (x) { return x.id === S.game; })[0] || list[0];
    var det = $('[data-game-detail]');
    if (!g) { det.innerHTML = ''; return; }
    var st = G[g.id];
    var risky = /Vanguard|FACEIT/.test(g.ac);
    var html = '<div class="gd__head"><span class="mono mono--lg">' + g.icon + '</span><div><h2>' + esc(g.name) + '</h2><p>' + esc(g.launcher) + ' · Античит: ' + esc(g.ac) + '</p></div></div>';
    html += '<div class="note-line' + (risky ? ' note-line--warn' : '') + '"><svg class="i i--sm"><use href="#i-' + (risky ? 'alert' : 'info') + '"/></svg><span>' + (risky ? 'Совместимость с античитом ' + (g.ac.indexOf('Vanguard') >= 0 ? 'Vanguard' : 'FACEIT') + ' не проверена. Сами игру не трогаем — режим меняется только по вашему выбору.' : 'Снижение пинга пока не измерено. По умолчанию игра идёт обычным путём.') + '</span></div>';
    html += '<fieldset class="modes"' + (locked ? ' disabled' : '') + '><legend>Режим для игры</legend>';
    MODES.forEach(function (m) {
      var off = m.udpOnly && !g.udp;
      html += '<label class="mode' + (off ? ' mode--off' : '') + '"><input type="radio" name="mode-' + g.id + '" value="' + m.v + '"' + (st.draft === m.v ? ' checked' : '') + (off ? ' disabled' : '') + ' data-mode><span class="mode__name">' + m.name + (st.saved === m.v ? ' <span class="tag">сейчас</span>' : '') + '</span><span class="mode__d">' + (off ? 'Для этой игры пока недоступно.' : m.d) + '</span></label>';
    });
    html += '</fieldset>';
    var dirty = st.draft !== st.saved;
    html += '<div class="gd__apply"><button class="btn" data-game-apply' + (dirty && !locked ? '' : ' disabled') + '>Применить</button><span class="gd__status" role="status">' + (st.msg || (st.profile ? 'Сейчас: ' + modeName(st.saved) + '.' : 'Сейчас: обычный путь. Изменения — только по вашему выбору.')) + '</span></div>';
    if (g.riot) {
      html += '<div class="launcher"><div><strong>Лаунчер Riot Client</strong><p>' + (riotFixed ? 'Лаунчер настроен. Запустите игру, чтобы проверить. Режим игры и античит не менялись.' : 'Если лаунчер не запускается или не обновляется, VELIQ подберёт для него путь. Режим игры и античит не меняются.') + '</p></div><button class="btn btn--ghost btn--sm" data-riot-fix' + (riotFixed || locked ? ' disabled' : '') + '>' + (riotFixed ? 'Настроено' : 'Исправить лаунчер') + '</button></div>';
    }
    det.innerHTML = html;
  }

  function renderActivation() {
    var ov = $('[data-activate]'), a = S.act;
    ov.hidden = !a || a === 'expiring';
    var code = $('[data-act-code]'), msg = $('[data-act-msg]'), submit = $('[data-act-submit]');
    ov.setAttribute('data-act', a || '');
    $('[data-act-form]').hidden = a === 'done';
    $('[data-act-done]').hidden = a !== 'done';
    $('[data-act-cancel]').hidden = a !== 'change' && !(a === 'error' && S.actChange);
    $('[data-act-help]').hidden = a === 'done';
    $('[data-act-mark]').src = 'assets/img/' + (S.theme === 'light' ? 'veliq-symbol.svg' : 'veliq-symbol-reverse.svg');
    var title = { code: 'Введите код активации', change: 'Введите новый код активации', busy: 'Проверяем код…', error: 'Введите код активации', done: 'VELIQ активирован' }[a] || '';
    var lead = { code: 'Код выдаётся после заявки для клуба или отдельно для игрока.', change: 'Текущая активация действует, пока новый код не принят.', busy: 'Это займёт пару секунд.', error: 'Код выдаётся после заявки для клуба или отдельно для игрока.', done: 'Всё готово. Можно пользоваться.' }[a] || '';
    $('[data-act-title]').textContent = title; $('[data-act-lead]').textContent = lead;
    code.disabled = a === 'busy'; submit.disabled = a === 'busy';
    submit.textContent = a === 'busy' ? 'Проверяем…' : 'Активировать';
    code.classList.toggle('is-invalid', a === 'error');
    code.setAttribute('aria-invalid', String(a === 'error'));
    if (a === 'error' && ACT_ERR[S.actErr]) { msg.hidden = false; msg.innerHTML = '<svg class="i i--sm"><use href="#i-error"/></svg><div><strong>' + ACT_ERR[S.actErr].title + '.</strong> ' + ACT_ERR[S.actErr].text + '</div>'; }
    else msg.hidden = true;
    // строка в настройках
    $('[data-act-set-title]').textContent = S.actExpiring ? 'Скоро закончится срок активации' : 'VELIQ активирован';
    $('[data-act-set-sub]').textContent = S.actExpiring ? 'Действует до 02.11.2026. Для продления напишите в поддержку.' : 'Действует до 24.01.2027';
    $('[data-act-set-title]').closest('.setrow').classList.toggle('setrow--warn', S.actExpiring);
    $$('[data-act-set]').forEach(function (b) { b.setAttribute('aria-current', String(b.getAttribute('data-act-set') === (S.actExpiring ? 'expiring' : a))); });
    $$('[data-games-notice-set]').forEach(function (b) { b.setAttribute('aria-current', String(b.getAttribute('data-games-notice-set') === S.gamesNotice)); });
    var pick = $('[data-act-error-pick]'); if (pick) pick.value = a === 'error' ? S.actErr : '';
  }

  function banner(kind, data) {
    var cls = kind === 'error' ? '' : data.cls;
    var icon = kind === 'error' ? 'error' : data.icon;
    return '<div class="banner ' + cls + '" role="' + (kind === 'error' ? 'alert' : 'status') + '"><svg class="i"><use href="#i-' + icon + '"/></svg><div><strong>' + data.title + '</strong><p>' + data.text + '</p></div>' +
      '<div class="banner__actions">' + (data.act2 ? '<button class="btn btn--quiet btn--sm" data-banner-alt>' + data.act2 + '</button>' : '') + '<button class="btn btn--sm" data-banner-act>' + data.act + '</button></div></div>';
  }

  /* ---------- Отрисовка состояния ---------- */
  function render() {
    var st = S.state;
    win.setAttribute('data-state', st);
    var server = S.warn === 'fallback' ? 'Швеция' : 'Хельсинки';
    var ping = S.warn === 'fallback' ? 46 : 38;

    $$('[data-go]').forEach(function (go) {
      go.setAttribute('data-state', st);
      go.setAttribute('aria-pressed', String(st === 'on'));
      var l = $('[data-go-label]', go), sub = $('[data-go-sub]', go);
      if (st === 'off') { l.textContent = t('go.off'); sub.textContent = t('go.off.sub'); }
      if (st === 'connecting') { l.textContent = t('go.connecting'); sub.textContent = t('go.connecting.sub'); }
      if (st === 'on') { l.textContent = t('go.on'); sub.textContent = server + ', ' + ping + ' мс'; }
      if (st === 'error') { l.textContent = t('go.error'); sub.textContent = ERR[S.error].short; }
    });

    $('[data-home-title]').textContent = t('home.' + st);
    $('[data-home-sub]').textContent = st === 'error' ? 'Пока ошибка не исправлена, интернет работает как без VELIQ.' : t('home.' + st + '.sub');
    var slot = $('[data-banner-slot]');
    slot.innerHTML = st === 'error' ? banner('error', ERR[S.error]) : (S.warn && st === 'on' ? banner('warn', WARN[S.warn]) : '');

    var on = st === 'on';
    $('[data-m-server]').textContent = on ? server : '—';
    $('[data-m-server-sub]').textContent = on ? (server === 'Хельсинки' ? 'veliq-hel-01, выбран автоматически' : 'veliq-swe-01, запасной') : 'выбирается автоматически';
    $('[data-m-ping]').innerHTML = (on ? ping : '—') + ' <small>мс</small>';
    $('[data-m-traffic]').innerHTML = (on ? '1,24' : '—') + ' <small>ГБ</small>';
    $('[data-m-routes]').innerHTML = (on ? '12' : '—') + ' <small>активно</small>';
    $('[data-m-traffic-sub]').textContent = on ? '↓ 1,21 ГБ   ↑ 83 МБ' : 'получено и отправлено';
    $$('[data-via]').forEach(function (v) { v.textContent = server; });

    var statusCls = 'status status--' + (st === 'error' ? 'error' : st);
    var statusTxt = t('st.' + st);
    var rs = $('[data-rail-status]'); rs.className = statusCls; rs.lastChild.textContent = statusTxt;
    $('[data-rail-server]').textContent = on ? server + ', ' + ping + ' мс' : (st === 'error' ? ERR[S.error].title : '—');

    // клуб
    $('[data-club-title]').textContent = st === 'on' ? 'Работает' : st === 'connecting' ? 'Подключаем' : st === 'error' ? 'Не работает' : 'Выключено';
    $('[data-club-sub]').textContent = st === 'on' ? 'Маршруты построены: заблокированное открывается, игры идут по самому быстрому пути.'
      : st === 'error' ? 'Позовите администратора: ' + ERR[S.error].short + '. Остальной интернет работает.'
      : st === 'connecting' ? 'Пара секунд, и всё заработает.' : 'Нажмите кнопку, чтобы включить.';
    $('[data-club-server]').textContent = on ? server + ', ' + ping + ' мс' : '—';

    // трей и мини-окно
    var trayTheme = S.theme === 'light' ? 'light' : 'dark';
    var trayState = st === 'error' ? 'error' : st;
    $('[data-tray-img]').src = 'assets/img/tray/tray-' + trayState + '-' + trayTheme + '.svg';
    var trayLabel = 'VELIQ: ' + statusTxt.toLowerCase() + (on ? ', ' + server + ', ' + ping + ' мс' : '');
    $('[data-tray]').setAttribute('aria-label', trayLabel); $('[data-tray]').title = trayLabel;
    $('[data-taskbar]').classList.toggle('taskbar--light', S.theme === 'light');
    var fs = $('[data-fly-status]'); fs.className = statusCls; fs.lastChild.textContent = statusTxt;
    $('[data-fly-title]').textContent = st === 'error' ? ERR[S.error].title : t('home.' + st);
    $('[data-fly-sub]').textContent = on ? 'Маршруты построены' : st === 'connecting' ? 'Строим маршруты' : st === 'error' ? 'Откройте VELIQ, чтобы исправить' : 'Интернет работает как без VELIQ';
    $('[data-fly-switch]').checked = on || st === 'connecting';
    $('[data-fly-server]').textContent = on ? server : '—';
    $('[data-fly-ping]').textContent = on ? ping + ' мс' : '—';
    $('[data-fly-traffic]').textContent = on ? '1,24 ГБ' : '—';
    $('[data-ctx-toggle-label]').textContent = on || st === 'connecting' ? 'Выключить' : 'Оптимизировать';

    // экраны
    var screen = S.club ? 'club' : S.screen;
    $$('.screen').forEach(function (s) { s.classList.toggle('is-active', s.getAttribute('data-screen') === screen); });
    $$('[data-screen-btn]').forEach(function (b) { if (b.closest('.rail')) b.setAttribute('aria-current', b.getAttribute('data-screen-btn') === S.screen ? 'page' : 'false'); });
    win.classList.toggle('win--club', S.club);
    $$('[data-club-only]').forEach(function (e) { e.hidden = !S.club; });

    // панель макета
    $$('[data-go-screen]').forEach(function (b) { b.setAttribute('aria-current', String(!S.club && b.getAttribute('data-go-screen') === S.screen)); });
    $$('[data-proto-nav] [data-go-club]').forEach(function (b) { b.setAttribute('aria-current', String(S.club)); });
    $$('[data-set-state]').forEach(function (b) {
      var match = b.getAttribute('data-set-state') === st && (b.getAttribute('data-error') || null) === (st === 'error' ? S.error : null) && (b.getAttribute('data-warn') || null) === (st === 'on' ? S.warn : null);
      b.setAttribute('aria-current', String(match));
    });
    var names = { home: 'Главная', services: 'Сервисы', games: 'Игры', diag: 'Диагностика', settings: 'Настройки', about: 'О программе', club: 'Режим клуба' };
    $('[data-desk-label]').textContent = (S.act && S.act !== 'expiring' ? 'Активация — ' : '') + names[screen] + ' — ' + (st === 'error' ? ERR[S.error].short : statusTxt.toLowerCase()) + (S.warn && st === 'on' ? '. ' + WARN[S.warn].title : '');

    // тексты
    $$('[data-i18n]').forEach(function (e) { e.textContent = t(e.getAttribute('data-i18n')); });
    root.lang = S.lang;
    $$('[data-lang-set]').forEach(function (b) { b.setAttribute('aria-pressed', String(b.getAttribute('data-lang-set') === S.lang)); });
    $('[data-lang-select]').value = S.lang;

    // логотипы по теме
    $$('[data-wm]').forEach(function (img) { img.src = 'assets/img/veliq-wordmark-' + (S.theme === 'light' ? 'light' : 'dark') + '.svg'; });
    $$('[data-theme-set]').forEach(function (b) { b.setAttribute('aria-pressed', String(b.getAttribute('data-theme-set') === S.theme)); });

    renderGames(); renderActivation();
    var actPart = S.act === 'error' ? 'act-err-' + S.actErr : S.act ? 'act-' + S.act : (S.actExpiring ? 'act-expiring' : '');
    try { history.replaceState(null, '', '#' + [screen, st, S.error || '', S.warn || '', actPart].join('/')); } catch (e) {}
  }

  function setState(st, opts) {
    clearTimeout(timer);
    opts = opts || {};
    S.state = st; S.error = st === 'error' ? (opts.error || 'relay') : null; S.warn = st === 'on' ? (opts.warn || null) : null;
    render();
  }
  function toggleGo() {
    if (S.state === 'off' || S.state === 'error') {
      setState('connecting');
      timer = setTimeout(function () { setState('on'); toast('on'); }, 1600);
    } else setState('off');
  }

  /* ---------- Уведомления ---------- */
  var TOASTS = {
    on: { cls: 'toast--ok', icon: 'ok', title: 'VELIQ работает', text: 'Маршруты построены. Ближайший сервер: Хельсинки, 38 мс.' },
    lost: { cls: 'toast--error', icon: 'error', title: 'Связь с сервером потеряна', text: 'Перестраиваем маршрут через другой сервер. Это займёт пару секунд.' },
    back: { cls: 'toast--info', icon: 'route', title: 'Связь восстановлена', text: 'Снова через Хельсинки, 38 мс.' }
  };
  function toast(kind) {
    var d = TOASTS[kind]; var box = $('[data-toasts]');
    var el = document.createElement('div');
    el.className = 'toast ' + d.cls; el.setAttribute('role', 'status');
    el.innerHTML = '<svg class="toast__icon"><use href="#i-' + d.icon + '"/></svg><div><strong>' + d.title + '</strong><p>' + d.text + '</p></div><button class="btn btn--quiet" aria-label="Закрыть"><svg class="i i--sm"><use href="#i-close"/></svg></button>';
    el.querySelector('button').onclick = function () { el.remove(); };
    box.appendChild(el);
    setTimeout(function () { el.remove(); }, 5000);
  }

  /* ---------- Модальные окна ---------- */
  var lastFocus;
  function openModal(id) {
    lastFocus = document.activeElement;
    var m = $('[data-modal="' + id + '"]'); m.hidden = false;
    var f = m.querySelector('input, button'); if (f) f.focus();
  }
  function closeModals() { $$('[data-modal]').forEach(function (m) { m.hidden = true; }); if (lastFocus) lastFocus.focus(); }

  function closePopups() { $('[data-flyout]').classList.remove('is-open'); $('[data-ctx]').classList.remove('is-open'); $('[data-tray]').setAttribute('aria-expanded', 'false'); }

  /* ---------- Тема ---------- */
  function setTheme(th) {
    S.theme = th === 'system' ? (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light') : th;
    root.setAttribute('data-theme', S.theme);
    render();
  }

  /* ---------- События ---------- */
  document.addEventListener('click', function (e) {
    var b;
    if ((b = e.target.closest('[data-act-set]'))) { var v = b.getAttribute('data-act-set'); S.actExpiring = v === 'expiring'; S.act = v === 'expiring' ? null : v; S.actChange = v === 'change'; if (v === 'expiring') { S.club = false; S.screen = 'settings'; } render(); return; }
    if ((b = e.target.closest('[data-act-change]'))) { S.act = 'change'; S.actChange = true; render(); var c = $('[data-act-code]'); c.value = ''; c.focus(); return; }
    if ((b = e.target.closest('[data-act-cancel]'))) { S.act = null; S.actChange = false; render(); return; }
    if ((b = e.target.closest('[data-act-finish]'))) { S.act = null; S.actChange = false; S.actExpiring = false; render(); return; }
    if ((b = e.target.closest('[data-games-notice-set]'))) { S.gamesNotice = b.getAttribute('data-games-notice-set'); S.club = false; S.screen = 'games'; render(); return; }
    if ((b = e.target.closest('[data-game]'))) { S.game = b.getAttribute('data-game'); renderGames(); return; }
    if ((b = e.target.closest('[data-game-apply]'))) { var gs = G[S.game]; gs.saved = gs.draft; gs.profile = true; gs.msg = 'Сохранено: ' + modeName(gs.saved) + '. Действует для новых соединений игры — если матч уже идёт, изменения подхватятся в следующем.'; renderGames(); return; }
    if ((b = e.target.closest('[data-riot-fix]'))) { b.disabled = true; b.textContent = 'Настраиваем…'; setTimeout(function () { riotFixed = true; renderGames(); }, 900); return; }
    if ((b = e.target.closest('[data-go]'))) { if (S.club && S.state === 'on') return; toggleGo(); return; }
    if ((b = e.target.closest('[data-screen-btn]'))) { S.screen = b.getAttribute('data-screen-btn'); render(); return; }
    if ((b = e.target.closest('[data-go-screen]'))) { S.club = false; S.screen = b.getAttribute('data-go-screen'); render(); return; }
    if ((b = e.target.closest('[data-go-club]'))) { closeModals(); S.club = true; if (S.state === 'off') S.state = 'on'; render(); return; }
    if ((b = e.target.closest('[data-leave-club]'))) { closeModals(); S.club = false; S.screen = 'settings'; render(); return; }
    if ((b = e.target.closest('[data-set-state]'))) { setState(b.getAttribute('data-set-state'), { error: b.getAttribute('data-error'), warn: b.getAttribute('data-warn') }); return; }
    if ((b = e.target.closest('[data-banner-act]'))) {
      if (S.state === 'error') toggleGo(); else setState('on'); return;
    }
    if ((b = e.target.closest('[data-banner-alt]'))) { S.screen = 'diag'; render(); return; }
    if ((b = e.target.closest('[data-theme-set]'))) { setTheme(b.getAttribute('data-theme-set')); return; }
    if ((b = e.target.closest('[data-lang-set]'))) { S.lang = b.getAttribute('data-lang-set'); render(); return; }
    if ((b = e.target.closest('[data-modal-open]'))) { openModal(b.getAttribute('data-modal-open')); return; }
    if ((b = e.target.closest('[data-modal-close]'))) { closeModals(); return; }
    if (e.target.matches('.modal-backdrop')) { closeModals(); return; }
    if ((b = e.target.closest('[data-toast]'))) { toast(b.getAttribute('data-toast')); return; }
    if ((b = e.target.closest('[data-tray]')) || (b = e.target.closest('[data-open-flyout]'))) {
      var f = $('[data-flyout]'); var open = !f.classList.contains('is-open'); closePopups();
      f.classList.toggle('is-open', open); $('[data-tray]').setAttribute('aria-expanded', String(open)); return;
    }
    if ((b = e.target.closest('[data-open-ctx]'))) { var c = $('[data-ctx]'); var o = !c.classList.contains('is-open'); closePopups(); c.classList.toggle('is-open', o); return; }
    if ((b = e.target.closest('[data-fly-open]'))) { closePopups(); S.club = false; S.screen = 'home'; render(); win.scrollIntoView({ block: 'center' }); return; }
    if ((b = e.target.closest('[data-fly-close]')) || (b = e.target.closest('[data-ctx-close]'))) { closePopups(); return; }
    if ((b = e.target.closest('[data-ctx-toggle]'))) { closePopups(); toggleGo(); return; }
    if ((b = e.target.closest('[data-cmp]'))) { $$('[data-cmp]').forEach(function (x) { x.setAttribute('aria-pressed', String(x === b)); }); return; }
    if ((b = e.target.closest('.game-list button[aria-pressed]'))) { $$('.game-list button[aria-pressed]').forEach(function (x) { x.setAttribute('aria-pressed', String(x === b)); }); return; }
    if ((b = e.target.closest('.seg button')) && !b.hasAttribute('data-theme-set') && !b.hasAttribute('data-lang-set')) {
      $$('button', b.parentNode).forEach(function (x) { x.setAttribute('aria-pressed', String(x === b)); }); return;
    }
    if ((b = e.target.closest('[data-apply-route]'))) {
      var hel = $('.cmp--hel'); $$('[data-cmp]').forEach(function (x) { x.setAttribute('aria-pressed', String(x === hel)); });
      b.textContent = 'Закреплено'; b.disabled = true;
      $('.game-list button[aria-pressed="true"] .tag').className = 'tag tag--relay'; $('.game-list button[aria-pressed="true"] .tag').textContent = 'HEL';
      return;
    }
    if ((b = e.target.closest('[data-measure]'))) { var n = $('[data-measure-note]'); n.textContent = 'замеряем…'; setTimeout(function () { n.textContent = 'замер 20 пакетов, только что'; drawChart(); }, 1200); return; }
    if (!e.target.closest('.flyout, .ctxmenu')) closePopups();
  });
  $('[data-fly-switch]').addEventListener('change', function () { toggleGo(); });
  document.addEventListener('change', function (e) {
    if (e.target.matches('[data-mode]')) { G[S.game].draft = e.target.value; G[S.game].msg = ''; renderGames(); }
    if (e.target.matches('[data-act-error-pick]') && e.target.value) { S.act = 'error'; S.actErr = e.target.value; S.actExpiring = false; render(); }
  });
  $('[data-game-search]').addEventListener('input', function (e) { S.search = e.target.value; renderGames(); });
  $('[data-act-form]').addEventListener('submit', function (e) {
    e.preventDefault();
    var v = $('[data-act-code]').value.trim();
    S.act = 'busy'; render();
    setTimeout(function () {
      if (!v || v.length < 4) { S.act = 'error'; S.actErr = 'ACTIVATION_INVALID'; }
      else S.act = 'done';
      render(); if (S.act === 'error') $('[data-act-code]').focus();
    }, 1400);
  });
  (function () { var pick = $('[data-act-error-pick]'); Object.keys(ACT_ERR).forEach(function (k) { var o = document.createElement('option'); o.value = k; o.textContent = ACT_ERR[k].title; pick.appendChild(o); }); })();
  $('[data-lang-select]').addEventListener('change', function (e) { S.lang = e.target.value; render(); });
  $('[data-tray]').addEventListener('contextmenu', function (e) { e.preventDefault(); closePopups(); $('[data-ctx]').classList.add('is-open'); });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') { closeModals(); closePopups(); } });

  function drawChart() {
    var jitter = function (base, amp) { var a = []; for (var i = 0; i < 24; i++) a.push(Math.round(base + (Math.random() - .5) * amp)); return a; };
    if (window.veliqPingChart && $('[data-app-chart]')) window.veliqPingChart($('[data-app-chart]'), { height: 180, series: [
      { id: 'direct', name: 'обычный', values: jitter(72, 8) },
      { id: 'swe', name: 'Швеция', values: jitter(48, 4) },
      { id: 'hel', name: 'Хельсинки', values: jitter(41, 3) }
    ] });
  }

  /* ---------- Старт: состояние из адреса (#экран/состояние/ошибка/предупреждение) ---------- */
  var parts = (location.hash || '').replace('#', '').split('/');
  if (parts[0]) { if (parts[0] === 'club') S.club = true; else S.screen = parts[0]; }
  if (parts[1]) { S.state = parts[1]; S.error = parts[2] || (parts[1] === 'error' ? 'relay' : null); S.warn = parts[3] || null; }
  if (parts[4]) {
    var ap = parts[4].replace(/^act-/, '');
    if (ap.indexOf('err-') === 0) { S.act = 'error'; S.actErr = ap.slice(4); }
    else if (ap === 'expiring') { S.actExpiring = true; }
    else S.act = ap;
    S.actChange = S.act === 'change';
  }
  root.setAttribute('data-theme', S.theme);
  drawChart();
  render();
})();
