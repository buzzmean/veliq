/* Личный кабинет VELIQ: вход по коду из письма, подписки, места, оплата.
   API на том же домене: /api/v1/account. Сессия — служебная cookie (HttpOnly). */
(function () {
  'use strict';
  var root = document.querySelector('[data-account]');
  if (!root) return;
  var API = '/api/v1/account';
  var $ = function (sel) { return root.querySelector(sel); };
  var state = { email: '', plans: [], kind: '', subscriptions: [], enforced: false };
  var linkID = new URLSearchParams(location.hash.slice(1)).get('device') || '';
  if (!/^[a-f0-9]{32}$/.test(linkID)) linkID = '';

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
    ACCOUNT_PROFILE_INVALID: 'Выберите тип аккаунта и укажите название клуба.',
    ACCOUNT_PROFILE_CONFLICT: 'Тип аккаунта не подходит к уже оформленным подпискам.',
    ACCOUNT_SUBSCRIPTION_REQUIRED: 'Выберите свою подходящую подписку. Для клубного образа нужна клубная подписка.',
    ACCOUNT_LINK_EXPIRED: 'Ссылка устарела. Вернитесь в VELIQ и начните подключение снова.',
    ACCOUNT_LINK_INVALID: 'Не удалось подтвердить подключение. Начните его заново в VELIQ.',
    ACCOUNT_DEVICE_ALREADY_OWNED: 'Компьютер привязан к другому аккаунту. Сначала освободите его в прежнем кабинете.',
    ACCOUNT_IMAGE_LIMIT: 'Достигнут лимит активных клубных образов. Отзовите ненужный образ.',
    SUBSCRIPTION_EXPIRED: 'Сначала продлите подписку.',
    ACTIVATION_LIMIT: 'Нет свободного места. Освободите компьютер или увеличьте число мест.',
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
    if (!emailForm.reportValidity()) { busy(btn, false); return; }
    state.email = emailForm.email.value.trim();
    call('POST', '/login/start', { email: state.email }).then(function () {
      $('[data-sent-to]').textContent = state.email; show('code'); codeForm.code.value = ''; codeForm.code.focus();
    }).catch(function (err) { say($('[data-email-error]'), message(err.message)); })
      .then(function () { busy(btn, false); });
  });
  codeForm.addEventListener('submit', function (e) {
    e.preventDefault();
    var btn = codeForm.querySelector('button[type=submit]'); busy(btn, true); say($('[data-code-error]'), '');
    if (!/^[0-9]{6}$/.test(codeForm.code.value.trim())) { say($('[data-code-error]'), 'Введите шесть цифр из письма.'); busy(btn, false); return; }
    call('POST', '/login/verify', { email: state.email, code: codeForm.code.value.trim() }).then(load)
      .catch(function (err) { say($('[data-code-error]'), message(err.message)); })
      .then(function () { busy(btn, false); });
  });
  $('[data-change-email]').addEventListener('click', function () { show('email'); });
  $('[data-logout]').addEventListener('click', function () { call('POST', '/logout').then(function () { state={email:'',plans:[],kind:'',subscriptions:[],enforced:false};['[data-subs]','[data-payments]','[data-images]','[data-account-email]','[data-account-kind]'].forEach(function(selector){$(selector).textContent='';});codeForm.code.value='';show('email'); }); });

  // --- кабинет
  function planOf(id) { for (var i = 0; i < state.plans.length; i++) if (state.plans[i].id === id) return state.plans[i]; return null; }

  function renderPlans(target) {
    target.textContent = '';
    var plans = state.plans.filter(function(p){ return !state.kind || p.kind === state.kind; });
    $('[data-plans-empty]').hidden = plans.length > 0;
    $('[data-choose-plan]').hidden = plans.length === 0;
    $('[data-subs-hint]').textContent = plans.length ? 'Выберите тариф, чтобы подключить компьютеры к VELIQ.' : 'Здесь появятся ваша подписка и подключённые компьютеры.';
    plans.forEach(function (p) {
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

  function renderSubscription(s, paymentsOn, autoRenewAvailable) {
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
      call('POST', '/subscriptions/' + s.id + '/pay', { auto_renew: false }).then(function (r) { location.href = r.redirect; })
        .catch(function (x) { say(err, message(x.message)); busy(pay, false); });
    });
    actions.appendChild(pay);
    card.appendChild(actions);
    card.appendChild(el('p', 'muted acc-small', 'Чтобы подключить компьютер, откройте VELIQ на нём и нажмите «Войти или зарегистрироваться». Копировать код активации не нужно.'));
    if (!paymentsOn) card.appendChild(el('p', 'muted acc-small', 'Онлайн-оплата скоро появится. Сейчас оплатить можно по счёту — напишите нам.'));
    if (paymentsOn && autoRenewAvailable) {
      var auto = el('label', 'acc-auto'); var box = el('input'); box.type = 'checkbox'; box.checked = s.auto_renew;
      box.addEventListener('change', function () { call('POST', '/subscriptions/' + s.id + '/auto-renew', { enabled: box.checked }).catch(function (x) { box.checked = !box.checked; say(err, message(x.message)); }); });
      auto.appendChild(box); auto.appendChild(el('span', null, 'Автопродление')); card.appendChild(auto);
    }
    if (s.devices.length) {
      var list = el('ul', 'acc-devices');
      s.devices.forEach(function (d, i) {
        var li = el('li');
        li.appendChild(el('span', null, (d.name || 'Компьютер ' + (i + 1)) + (d.last_seen ? ' · был в сети ' + date(d.last_seen) : '')));
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
      state.plans = data.plans || []; state.kind=data.kind || ''; state.subscriptions=data.subscriptions || []; state.enforced=!!data.subscription_enforced;
      if(!state.kind){ updateProfileFields(); show('profile'); return; }
      $('[data-account-email]').textContent = data.email;
      $('[data-account-kind]').textContent = (data.kind === 'club' ? 'Клуб' : 'Пользователь') + (data.name ? ' · ' + data.name : '');
      var subs = $('[data-subs]'); subs.textContent = '';
      (data.subscriptions || []).forEach(function (s) { subs.appendChild(renderSubscription(s, data.payments_enabled, data.auto_renew_available)); });
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
      show('cabinet'); renderLink(); renderImages();
    }).catch(function (err) {
      if (err.status === 401) { show('email'); return; }
      say($('[data-email-error]'), message(err.message)); show('email');
    });
  }
  var profileForm = $('[data-profile-form]');
  function updateProfileFields() {
    var kind = profileForm.elements.namedItem('kind').value;
    var chosen = kind === 'player' || kind === 'club';
    var name = profileForm.elements.namedItem('name');
    $('[data-profile-name-field]').hidden = !chosen;
    $('[data-profile-name-help]').hidden = !chosen;
    $('[data-profile-continue]').disabled = !chosen;
    name.disabled = !chosen;
    name.required = kind === 'club';
    name.autocomplete = kind === 'club' ? 'organization' : 'name';
    $('[data-profile-name-label]').textContent = kind === 'club' ? 'Название клуба' : 'Ваше имя';
    $('[data-profile-name-help]').textContent = kind === 'club' ? 'Так клуб будет называться в вашем кабинете.' : 'Как к вам обращаться. Можно оставить пустым.';
  }
  profileForm.elements.namedItem('kind').addEventListener('change', updateProfileFields);
  updateProfileFields();
  profileForm.addEventListener('submit',function(e){
    e.preventDefault();var form=e.currentTarget,button=form.querySelector('button');busy(button,true);
    call('POST','/profile',{kind:form.elements.namedItem('kind').value,name:form.elements.namedItem('name').value.trim()}).then(load)
      .catch(function(err){say($('[data-profile-error]'),message(err.message));}).then(function(){busy(button,false);});
  });
  function renderLink(){
    var panel=$('[data-link-panel]');panel.hidden=!linkID;if(!linkID)return;
    call('GET','/device-links/'+linkID).then(function(info){
      $('[data-link-title]').textContent=info.mode==='image'?'Подключить клубный образ':'Подключить компьютер';
      $('[data-link-name]').textContent=info.name;
      var select=$('[data-link-subscription]');select.textContent='';
      state.subscriptions.filter(function(s){return (info.mode!=='image'||s.kind==='club')&&s.can_connect!==false;}).forEach(function(s){
        var p=planOf(s.plan_id),option=el('option',null,(p?p.title:s.kind)+' · '+s.used_seats+' / '+s.seats+' ПК');option.value=s.id;select.appendChild(option);
      });
      $('[data-link-approve]').disabled=info.approved||!select.options.length;
      select.disabled=info.approved;
      $('[data-link-message]').textContent=info.approved?'Разрешение отправлено. Вернитесь в VELIQ и дождитесь подтверждения подключения.':select.options.length?'Проверьте название компьютера и выбранную подписку. Подтверждайте только своё подключение.':'Сначала оформите подходящую подписку ниже'+(state.enforced?' и оплатите её.':'.');
    }).catch(function(err){say($('[data-link-error]'),message(err.message));$('[data-link-approve]').disabled=true;});
  }
  $('[data-link-form]').addEventListener('submit',function(e){
    e.preventDefault();var button=$('[data-link-approve]');busy(button,true);say($('[data-link-error]'),'');
    call('POST','/device-links/'+linkID+'/approve',{subscription_id:$('[data-link-subscription]').value}).then(renderLink)
      .catch(function(err){say($('[data-link-error]'),message(err.message));busy(button,false);});
  });
  function renderImages(){
    var target=$('[data-images]');target.textContent='';
    $('[data-images-section]').hidden=state.kind!=='club';
    $('[data-images-empty]').hidden=true;
    if(state.kind!=='club')return;
    call('GET','/club-images').then(function(data){$('[data-images-empty]').hidden=(data.images||[]).length>0;(data.images||[]).forEach(function(image){
      var card=el('article','card'),button=el('button','btn btn--quiet','Запретить новые подключения');
      card.appendChild(el('h3','h3',image.name));card.appendChild(el('p','muted',image.revoked?'Разрешение отозвано':'Разрешение до '+date(image.expires_at)));
      var err=el('p','acc-error');err.hidden=true;button.disabled=image.revoked;
      button.addEventListener('click',function(){if(!confirm('Запретить новые подключения из этого образа? Уже подключённые ПК останутся в подписке.'))return;busy(button,true);
        call('POST','/club-images/'+image.id+'/revoke',{}).then(renderImages).catch(function(error){say(err,message(error.message));busy(button,false);});});
      card.appendChild(button);card.appendChild(err);target.appendChild(card);
    });}).catch(function(error){target.appendChild(el('p','acc-error',message(error.message)));});
  }
  load();
})();
