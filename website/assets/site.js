/* VELIQ website — без зависимостей. */
(function () {
  var root = document.documentElement;

  /* Тема: системная по умолчанию, выбор запоминается в браузере */
  try { var saved = localStorage.getItem('veliq-theme'); if (saved) root.setAttribute('data-theme', saved); } catch (e) {}
  function currentTheme() {
    var t = root.getAttribute('data-theme');
    if (t) return t;
    return window.matchMedia && matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  document.addEventListener('click', function (e) {
    var b = e.target.closest('[data-theme-toggle]');
    if (!b) return;
    var next = currentTheme() === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    b.setAttribute('aria-label', next === 'dark' ? 'Включить светлую тему' : 'Включить тёмную тему');
    try { localStorage.setItem('veliq-theme', next); } catch (e2) {}
  });

  /* Мобильное меню */
  var menuBtn = document.querySelector('[data-menu]');
  var nav = document.getElementById('nav');
  if (menuBtn && nav) {
    menuBtn.addEventListener('click', function () {
      var open = nav.classList.toggle('is-open');
      menuBtn.setAttribute('aria-expanded', String(open));
      document.body.classList.toggle('menu-open', open);
    });
    nav.addEventListener('click', function (e) { if (e.target.closest('a')) { nav.classList.remove('is-open'); document.body.classList.remove('menu-open'); menuBtn.setAttribute('aria-expanded', 'false'); } });
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && nav.classList.contains('is-open')) { nav.classList.remove('is-open'); document.body.classList.remove('menu-open'); menuBtn.setAttribute('aria-expanded', 'false'); menuBtn.focus(); }
    });
  }

  /* Линия под шапкой после прокрутки */
  var top = document.querySelector('.top');
  if (top) {
    var onScroll = function () { top.classList.toggle('is-scrolled', window.scrollY > 8); };
    window.addEventListener('scroll', onScroll, { passive: true }); onScroll();
  }

  /* Сигнальная линия: прогресс чтения под шапкой */
  if (top) {
    var ticking = false;
    var readProgress = function () {
      ticking = false;
      var h = document.documentElement.scrollHeight - window.innerHeight;
      top.style.setProperty('--read', h > 0 ? Math.min(1, Math.max(0, window.scrollY / h)).toFixed(4) : '0');
    };
    window.addEventListener('scroll', function () { if (!ticking) { ticking = true; requestAnimationFrame(readProgress); } }, { passive: true });
    window.addEventListener('resize', readProgress); readProgress();
  }

  /* Линии маршрутов прочерчиваются, когда блок появляется на экране */
  var traced = document.querySelectorAll('.sec__head, [data-trace]');
  if ('IntersectionObserver' in window) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) { if (en.isIntersecting) { en.target.classList.add('is-in'); io.unobserve(en.target); } });
    }, { rootMargin: '0px 0px -12% 0px', threshold: 0.2 });
    traced.forEach(function (el) { io.observe(el); });
  } else {
    traced.forEach(function (el) { el.classList.add('is-in'); });
  }

  /* Скачать: компьютер или телефон */
  var platformBtns = document.querySelectorAll('[data-platform-btn]');
  if (platformBtns.length) {
    var showPlatform = function (pl) {
      document.querySelectorAll('[data-platform]').forEach(function (sec) { sec.hidden = sec.getAttribute('data-platform') !== pl; });
      document.querySelectorAll('.platforms [data-platform-btn]').forEach(function (b) { b.setAttribute('aria-pressed', String(b.getAttribute('data-platform-btn') === pl)); });
    };
    platformBtns.forEach(function (b) { b.addEventListener('click', function () { showPlatform(b.getAttribute('data-platform-btn')); }); });
    var isPhone = /Android|iPhone|iPad|iPod/i.test(navigator.userAgent) || location.hash === '#phone';
    if (isPhone) showPlatform('phone');
  }

  /* Проверка: что открывается у посетителя прямо сейчас (примерно, из браузера) */
  var checkSec = document.querySelector('[data-access-check]');
  if (checkSec && window.fetch && window.AbortController) {
    checkSec.hidden = false;
    var CONTROL = 'https://ya.ru/favicon.ico';
    var probe = function (url, ms) {
      var ctl = new AbortController(); var t0 = performance.now();
      var timer = setTimeout(function () { ctl.abort(); }, ms);
      return fetch(url + (url.indexOf('?') < 0 ? '?' : '&') + 'veliq=' + Date.now(), { mode: 'no-cors', cache: 'no-store', credentials: 'omit', signal: ctl.signal, referrerPolicy: 'no-referrer' })
        .then(function () { clearTimeout(timer); return { ok: true, ms: performance.now() - t0 }; })
        .catch(function () { clearTimeout(timer); return { ok: false, ms: performance.now() - t0 }; });
    };
    var rows = checkSec.querySelectorAll('[data-check-url]');
    var lead = checkSec.querySelector('[data-check-lead]');
    var again = checkSec.querySelector('[data-check-again]');
    var LABEL = { wait: 'проверяем', ok: 'открывается', slow: 'медленно', fail: 'не открывается' };
    var setRow = function (row, st) { row.setAttribute('data-st', st); row.querySelector('.check__st').textContent = LABEL[st]; };
    var running = false;
    var runCheck = function () {
      if (running) return; running = true; again.hidden = true;
      lead.textContent = 'Проверяем несколько сервисов для примера…';
      rows.forEach(function (row) { setRow(row, 'wait'); });
      probe(CONTROL, 6000).then(function (ctrl) {
        if (!ctrl.ok) { checkSec.hidden = true; running = false; return; } /* проверить нельзя — не показываем ничего */
        return Promise.all([].map.call(rows, function (row) {
          return probe(row.getAttribute('data-check-url'), 6000).then(function (r) {
            var st = !r.ok ? 'fail' : (r.ms > Math.max(2500, ctrl.ms * 4) ? 'slow' : 'ok');
            setRow(row, st); return { name: row.querySelector('.check__name').textContent, st: st };
          });
        })).then(function (res) {
          var bad = res.filter(function (x) { return x.st !== 'ok'; }).map(function (x) { return x.name; });
          lead.innerHTML = '';
          if (bad.length) {
            var s1 = document.createElement('strong'); s1.textContent = (bad.length === 1 ? 'Сейчас у вас плохо открывается ' : 'Сейчас у вас плохо открываются ') + bad.join(', ') + '.';
            lead.appendChild(s1); lead.appendChild(document.createTextNode(' С VELIQ они снова заработают — без настроек.'));
          } else {
            lead.textContent = 'Сейчас эти сервисы у вас открываются. VELIQ пригодится, когда что-то перестанет, — и для игр: он сам найдёт самый быстрый путь.';
          }
          again.hidden = false; running = false;
        });
      });
    };
    again.addEventListener('click', function (e) { e.preventDefault(); runCheck(); });
    if ('IntersectionObserver' in window) {
      var cio = new IntersectionObserver(function (en) { if (en[0].isIntersecting) { cio.disconnect(); runCheck(); } }, { threshold: 0.3 });
      cio.observe(checkSec);
    } else runCheck();
  }

  /* Помощь: ссылка вида support.html#err-relay открывает нужную ошибку */
  var openTarget = function () {
    var id = location.hash.slice(1); if (!id) return;
    var el = document.getElementById(id);
    if (el && el.tagName === 'DETAILS') { el.open = true; el.scrollIntoView({ block: 'start' }); }
  };
  window.addEventListener('hashchange', openTarget); openTarget();

  /* Демо большой кнопки на главной */
  var demo = document.querySelector('[data-demo]');
  if (demo) {
    var go = demo.querySelector('.go');
    var label = go.querySelector('[data-go-label]');
    var sub = go.querySelector('[data-go-sub]');
    var status = demo.querySelector('[data-demo-status]');
    var live = demo.querySelector('[data-demo-live]');
    var timer;
    function set(state) {
      demo.setAttribute('data-state', state);
      go.setAttribute('data-state', state);
      if (state === 'off') {
        label.textContent = 'Оптимизировать'; sub.textContent = 'выключено';
        status.className = 'status status--off'; status.lastChild.textContent = 'Выключено';
        go.setAttribute('aria-pressed', 'false');
      } else if (state === 'connecting') {
        label.textContent = 'Подключаем'; sub.textContent = 'строим маршруты';
        status.className = 'status status--connecting'; status.lastChild.textContent = 'Подключение';
      } else {
        label.textContent = 'Работает'; sub.textContent = 'маршруты построены';
        status.className = 'status status--on'; status.lastChild.textContent = 'Работает';
        go.setAttribute('aria-pressed', 'true');
      }
      demo.querySelectorAll('[data-on]').forEach(function (v) { v.textContent = state === 'on' ? v.getAttribute('data-on') : '—'; });
      if (live) live.textContent = status.lastChild.textContent;
    }
    var touched = false;
    go.addEventListener('click', function () {
      touched = true;
      clearTimeout(timer);
      if (demo.getAttribute('data-state') === 'off') { set('connecting'); timer = setTimeout(function () { set('on'); }, 1500); }
      else set('off');
    });
    /* Один раз запускается сам, когда демо видно, — чтобы было понятно, как строятся маршруты */
    var reduce = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (!reduce && 'IntersectionObserver' in window) {
      var dio = new IntersectionObserver(function (en) {
        if (!en[0].isIntersecting) return;
        dio.disconnect();
        setTimeout(function () { if (!touched && demo.getAttribute('data-state') === 'off') { set('connecting'); timer = setTimeout(function () { set('on'); }, 1500); } }, 900);
      }, { threshold: 0.6 });
      dio.observe(demo);
    }
  }

  /* График пинга */
  document.querySelectorAll('[data-ping-chart]').forEach(function (box) {
    if (!window.veliqPingChart) return;
    var data = JSON.parse(box.getAttribute('data-ping-chart'));
    window.veliqPingChart(box, data);
  });

  /* Калькулятор для клубов */
  var calc = document.querySelector('[data-calc]');
  if (calc) {
    var fmt = new Intl.NumberFormat('ru-RU', { maximumFractionDigits: 0 });
    var inputs = calc.querySelectorAll('[data-k]');
    function v(k) { var el = calc.querySelector('[data-k="' + k + '"].input'); return Math.max(0, parseFloat(el.value.replace(',', '.')) || 0); }
    function recalc() {
      var pcs = v('pcs'), hours = v('hours'), load = v('load') / 100, price = v('price'), lost = v('lost') / 100, cost = v('cost');
      var paidHours = pcs * hours * 30 * load;
      var revenue = paidHours * price;
      var back = revenue * lost;
      var veliq = pcs * cost;
      var net = back - veliq;
      calc.querySelector('[data-out="net"]').textContent = (net < 0 ? '−' : '') + fmt.format(Math.abs(net)) + ' ₽';
      calc.querySelector('[data-out="hours"]').textContent = fmt.format(paidHours) + ' ч';
      calc.querySelector('[data-out="revenue"]').textContent = fmt.format(revenue) + ' ₽';
      calc.querySelector('[data-out="back"]').textContent = '+' + fmt.format(back) + ' ₽';
      calc.querySelector('[data-out="cost"]').textContent = (veliq > 0 ? '−' : '') + fmt.format(veliq) + ' ₽';
    }
    inputs.forEach(function (el) {
      el.addEventListener('input', function () {
        var k = el.getAttribute('data-k');
        calc.querySelectorAll('[data-k="' + k + '"]').forEach(function (other) { if (other !== el) other.value = el.value; });
        recalc();
      });
    });
    recalc();
  }

  /* Копирование контрольной суммы */
  document.addEventListener('click', function (e) {
    var b = e.target.closest('[data-copy]');
    if (!b) return;
    var text = document.getElementById(b.getAttribute('data-copy')).textContent.trim();
    if (navigator.clipboard) navigator.clipboard.writeText(text).then(function () {
      var old = b.getAttribute('aria-label'); b.setAttribute('aria-label', 'Скопировано'); b.dataset.done = '1';
      setTimeout(function () { b.setAttribute('aria-label', old); delete b.dataset.done; }, 1600);
    });
  });
})();

/* Shared website support widget. */
(function () {
  if (document.querySelector('script[data-veliq-support]')) return;
  var css = document.createElement('link');
  css.rel = 'stylesheet'; css.href = '/assets/support-chat.css?v=4619b2e0f1fd'; document.head.appendChild(css);
  var script = document.createElement('script');
  script.src = '/assets/support-chat.js?v=68fd66d245f7'; script.defer = true;
  script.setAttribute('data-veliq-support', ''); document.body.appendChild(script);
})();
