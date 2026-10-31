/* Личный кабинет VELIQ: вход по коду из письма, подписки, места, оплата.
   API на том же домене: /api/v1/account. Сессия — служебная cookie (HttpOnly). */
(function () {
  'use strict';
  var root = document.querySelector('[data-account]');
  if (!root) return;
  var API = '/api/v1/account';
  var $ = function (sel) { return root.querySelector(sel); };
  var state = { email: '', plans: [] };

  var MESSAGES = {
    EMAIL_INVALID: 'Проверьте адрес почты.',
    LOGIN_CODE_INVALID: 'Код не подошёл или устарел. Запросите новый.',
    ACCOUNT_RATE_LIMIT: 'Слишком много попыток. Подождите пару минут.',
    MAIL_NOT_CONFIGURED: 'Вход временно недоступен. Напишите нам — поможем.',
    MAIL_UNAVAILABLE: 'Не удалось отправить письмо. Попробуйте ещё раз через минуту.',
    ACCOUNT_NOT_CONFIGURED: 'Личный кабинет скоро откроется. Пока напишите нам — оформим подписку вручную.',
    PAYMENT_NOT_CONFIGURED: 'Онлайн-оплата скоро появится. Пока напишите нам — выставим счёт.',
    PRICE_NOT_SET: 'Цена тарифа ещё не утверждена. Напишите нам.',
    SUBSCRIPTION_LIMIT: 'Слишком много подписок в одном кабинете. Напишите нам.',
    SUBSCRIPTION_INVALID: 'Проверьте число компьютеров.',
    SEAT_NOT_FOUND: 'Этот компьютер уже освобождён.'
  };
  function message(code) { return MESSAGES[code] || 'Не получилось. Проверьте интернет и попробуйте ещё раз.'; }

  function call(method, path, body) {
    var opt = { method: method, credentials: 'same-origin', headers: {} };
    if (method !== 'GET') { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body || {}); }
    return fetch(API + path, opt).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (data) {
        // 404/405: сервер кабинета ещё не запущен на этом домене.
        if (!r.ok) { var err = new Error(data.error || (r.status === 404 || r.status === 405 ? 'ACCOUNT_NOT_CONFIGURED' : 'HTTP_' + r.status)); err.status = r.status; throw err; }
        return data;
      });
    });
  }
  function show(name) {
    root.querySelectorAll('[data-step]').forEach(function (el) { el.hidden = el.getAttribute('data-step') !== name; });
  }
  function say(el, text) { el.textContent = text || ''; el.hidden = !text; }
  function date(s) { return s ? new Date(s).toLocaleDateString('ru-RU') : ''; }
  function rub(n) { return n.toLocaleString('ru-RU') + ' ₽'; }
  function el(tag, cls, text) { var e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }
  function busy(btn, on) { btn.disabled = on; btn.setAttribute('aria-busy', on ? 'true' : 'false'); }

  // --- вход
  var emailForm = $('[data-email-form]'), codeForm = $('[data-code-form]');
  emailForm.addEventListener('submit', function (e) {
    e.preventDefault();
    var btn = emailForm.querySelector('button'); busy(btn, true); say($('[data-email-error]'), '');
    state.email = emailForm.email.value.trim();
    call('POST', '/login/start', { email: state.email }).then(function () {
      $('[data-sent-to]').textContent = state.email; show('code'); codeForm.code.value = ''; codeForm.code.focus();
    }).catch(function (err) { say($('[data-email-error]'), message(err.message)); })
      .then(function () { busy(btn, false); });
  });
  codeForm.addEventListener('submit', function (e) {
    e.preventDefault();
    var btn = codeForm.querySelector('button[type=submit]'); busy(btn, true); say($('[data-code-error]'), '');
    call('POST', '/login/verify', { email: state.email, code: codeForm.code.value.trim() }).then(load)
      .catch(function (err) { say($('[data-code-error]'), message(err.message)); })
      .then(function () { busy(btn, false); });
  });
  $('[data-change-email]').addEventListener('click', function () { show('email'); });
  $('[data-logout]').addEventListener('click', function () { call('POST', '/logout').then(function () { show('email'); }); });

  // --- кабинет
  function planOf(id) { for (var i = 0; i < state.plans.length; i++) if (state.plans[i].id === id) return state.plans[i]; return null; }

  function renderPlans(target) {
    target.textContent = '';
    state.plans.forEach(function (p) {
      var card = el('form', 'card acc-plan');
      card.appendChild(el('h3', 'h3', p.title));
      card.appendChild(el('p', 'muted', p.price_per_seat_rub ? (rub(p.price_per_seat_rub) + (p.kind === 'club' ? ' за компьютер' : '') + ' на ' + p.period_days + ' дней') : 'Цена появится перед началом продаж'));
      var seats = null;
      if (p.max_seats > 1) {
        var label = el('label', 'field'); label.appendChild(el('span', null, 'Сколько компьютеров'));
        seats = el('input', 'input'); seats.type = 'number'; seats.min = 1; seats.max = p.max_seats; seats.value = 10; seats.required = true;
        label.appendChild(seats); card.appendChild(label);
      }
      var btn = el('button', 'btn', 'Оформить'); btn.type = 'submit'; card.appendChild(btn);
      var err = el('p', 'acc-error'); err.hidden = true; card.appendChild(err);
      card.addEventListener('submit', function (e) {
        e.preventDefault(); busy(btn, true); say(err, '');
        call('POST', '/subscriptions', { plan_id: p.id, seats: seats ? parseInt(seats.value, 10) : 1 }).then(load)
          .catch(function (x) { say(err, message(x.message)); }).then(function () { busy(btn, false); });
      });
      target.appendChild(card);
    });
  }

  function renderSubscription(s, paymentsOn) {
    var p = planOf(s.plan_id) || { title: 'Подписка', kind: s.kind };
    var card = el('article', 'card acc-sub');
    var head = el('div', 'acc-sub__head');
    head.appendChild(el('h3', 'h3', p.title + (s.kind === 'club' ? ' · ' + s.seats + ' ПК' : '')));
    var status = s.active ? 'Оплачено до ' + date(s.paid_until) : (s.paid_until ? 'Закончилась ' + date(s.paid_until) : 'Не оплачена');
    head.appendChild(el('span', 'acc-badge' + (s.active ? ' acc-badge--ok' : ''), status));
    card.appendChild(head);
    card.appendChild(el('p', 'muted', 'Занято компьютеров: ' + s.used_seats + ' из ' + s.seats));

    var actions = el('div', 'acc-actions');
    var err = el('p', 'acc-error'); err.hidden = true;
    var pay = el('button', 'btn', s.active ? 'Продлить' : 'Оплатить');
    pay.addEventListener('click', function () {
      busy(pay, true); say(err, '');
      call('POST', '/subscriptions/' + s.id + '/pay', { auto_renew: true }).then(function (r) { location.href = r.redirect; })
        .catch(function (x) { say(err, message(x.message)); busy(pay, false); });
    });
    actions.appendChild(pay);
    var codeBtn = el('button', 'btn btn--ghost', 'Получить код активации');
    var codeBox = el('div', 'acc-code'); codeBox.hidden = true;
    codeBtn.addEventListener('click', function () {
      if (s.used_seats > 0 && !confirm('Будет выпущен новый код. Старый перестанет подходить для новых активаций — компьютеры, которые активируются заново (например, клубные после перезагрузки), нужно будет перевести на новый код. Продолжить?')) return;
      busy(codeBtn, true); say(err, '');
      call('POST', '/subscriptions/' + s.id + '/code').then(function (r) {
        codeBox.textContent = ''; codeBox.hidden = false;
        codeBox.appendChild(el('code', 'mono', r.code));
        codeBox.appendChild(el('p', 'muted', 'Введите этот код в программе VELIQ. Сохраните его: показать этот же код ещё раз нельзя, только выпустить новый.'));
      }).catch(function (x) { say(err, message(x.message)); }).then(function () { busy(codeBtn, false); });
    });
    actions.appendChild(codeBtn);
    card.appendChild(actions);
    card.appendChild(codeBox);
    if (!paymentsOn) card.appendChild(el('p', 'muted acc-small', 'Онлайн-оплата скоро появится. Сейчас оплатить можно по счёту — напишите нам.'));
    if (paymentsOn) {
      var auto = el('label', 'acc-auto'); var box = el('input'); box.type = 'checkbox'; box.checked = s.auto_renew;
      box.addEventListener('change', function () { call('POST', '/subscriptions/' + s.id + '/auto-renew', { enabled: box.checked }).catch(function (x) { box.checked = !box.checked; say(err, message(x.message)); }); });
      auto.appendChild(box); auto.appendChild(el('span', null, 'Автопродление')); card.appendChild(auto);
    }
    if (s.devices.length) {
      var list = el('ul', 'acc-devices');
      s.devices.forEach(function (d, i) {
        var li = el('li');
        li.appendChild(el('span', null, 'Компьютер ' + (i + 1) + (d.last_seen ? ' · был в сети ' + date(d.last_seen) : '')));
        var rel = el('button', 'btn btn--sm btn--quiet', 'Освободить');
        rel.addEventListener('click', function () {
          if (!confirm('Освободить место? VELIQ на этом компьютере перестанет работать, место можно будет занять другим компьютером.')) return;
          busy(rel, true);
          call('POST', '/subscriptions/' + s.id + '/devices/' + d.machine + '/release').then(load)
            .catch(function (x) { say(err, message(x.message)); busy(rel, false); });
        });
        li.appendChild(rel); list.appendChild(li);
      });
      card.appendChild(list);
    }
    card.appendChild(err);
    return card;
  }

  function load() {
    return call('GET', '').then(function (data) {
      state.plans = data.plans || [];
      $('[data-account-email]').textContent = data.email;
      var subs = $('[data-subs]'); subs.textContent = '';
      (data.subscriptions || []).forEach(function (s) { subs.appendChild(renderSubscription(s, data.payments_enabled)); });
      $('[data-subs-empty]').hidden = (data.subscriptions || []).length > 0;
      renderPlans($('[data-plans]'));
      var pays = $('[data-payments]'); pays.textContent = '';
      (data.payments || []).forEach(function (p) {
        var li = el('li');
        li.appendChild(el('span', null, date(p.created_at) + ' · ' + rub(Math.round(p.amount_kopecks / 100)) + ' · ' + p.period_days + ' дней'));
        li.appendChild(el('span', 'muted', p.status === 'succeeded' ? 'оплачено' : p.status === 'pending' ? 'ожидает оплаты' : 'отменено'));
        pays.appendChild(li);
      });
      $('[data-payments-empty]').hidden = (data.payments || []).length > 0;
      show('cabinet');
    }).catch(function (err) {
      if (err.status === 401) { show('email'); return; }
      say($('[data-email-error]'), message(err.message)); show('email');
    });
  }
  load();
})();
