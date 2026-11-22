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
    PROMO_REVIEW_REQUIRED: 'Для новой льготы нужно подтвердить историю клуба. Старые заказы сохраняют свои условия. Обратитесь в поддержку.',
    PAYMENT_CONFIRMATION_REQUIRED: 'Сначала проверьте и подтвердите условия заказа.',
    PAYMENT_IDEMPOTENCY_REQUIRED: 'Не удалось подготовить номер заказа. Обновите кабинет.',
    PAYMENT_IDEMPOTENCY_CONFLICT: 'Этот номер уже связан с другим заказом. Проверьте историю оплаты.',
    PROMO_INVALID: 'Промокод не подходит для этого аккаунта или срока.',
    PROMO_USED: 'Промокод уже использован.',
    TRIAL_UNAVAILABLE: 'Пробный день больше недоступен для этого аккаунта. Обновите кабинет.',
    PROMO_FIRST_PURCHASE_ONLY: 'Акция доступна только для первой оплаченной покупки клуба.',
    PROMO_RESERVED: 'Для этого промокода уже создан заказ. Проверьте его оплату или обратитесь в поддержку.',
    PROMO_EXHAUSTED: 'Все места в акции уже заняты.',
    PROMO_RECONCILIATION_REQUIRED: 'Предыдущий заказ ещё проверяется. Не оплачивайте повторно; обратитесь в поддержку.',
    EMAIL_INVALID: 'Проверьте адрес почты.',
    LOGIN_CODE_INVALID: 'Код не подошёл или устарел. Запросите новый.',
    ACCOUNT_RATE_LIMIT: 'Слишком много попыток. Подождите пару минут.',
    MAIL_NOT_CONFIGURED: 'Вход временно недоступен. Напишите нам — поможем.',
    MAIL_UNAVAILABLE: 'Не удалось отправить письмо. Попробуйте ещё раз через минуту.',
    ACCOUNT_NOT_CONFIGURED: 'Личный кабинет временно недоступен. Обратитесь в поддержку.',
    PAYMENT_NOT_CONFIGURED: 'Онлайн-оплата пока не подключена. Для подключения или продления обратитесь в поддержку.',
    PAYMENT_PERIOD_INVALID: 'Выберите срок 1, 3, 6 или 12 месяцев.',
    PAYMENT_PRICE_CHANGED: 'Условия оплаты изменились. Проверьте новый расчёт.',
    PAYMENT_UNAVAILABLE: 'Не удалось создать оплату. Если деньги уже списаны, не платите повторно: проверьте статус или обратитесь в поддержку.',
    PAYMENT_CHECK_UNAVAILABLE: 'Сервис оплаты пока не ответил. Доступ не изменён; повторите проверку позже.',
    PAYMENT_CHECK_TOO_SOON: 'Подождите 15 секунд перед повторной проверкой.',
    PAYMENT_AUTORENEW_UNAVAILABLE: 'Доступна только разовая оплата без автосписаний.',
    PRICE_NOT_SET: 'Для оформления доступа обратитесь в поддержку. Текущие цены опубликованы на странице тарифов.',
    SUBSCRIPTION_LIMIT: 'Слишком много подписок в одном кабинете. Напишите нам.',
    SUBSCRIPTION_INVALID: 'Проверьте число компьютеров.',
    ACCOUNT_PROFILE_INVALID: 'Выберите тип аккаунта и укажите название клуба.',
    ACCOUNT_PROFILE_CONFLICT: 'Тип аккаунта не подходит к уже оформленным подпискам.',
    PERSONAL_SUBSCRIPTION_CONFLICT: 'У аккаунта уже есть несколько личных подписок. Их можно открыть в разделе «Личный доступ».',
    ACCOUNT_SUBSCRIPTION_REQUIRED: 'Выберите свою подходящую подписку. Для клубного образа нужна клубная подписка.',
    ACCOUNT_LINK_EXPIRED: 'Ссылка устарела. Вернитесь в VELIQ и начните подключение снова.',
    ACCOUNT_LINK_INVALID: 'Не удалось подтвердить подключение. Начните его заново в VELIQ.',
    ACCOUNT_DEVICE_ALREADY_OWNED: 'Компьютер привязан к другому аккаунту. Сначала освободите его в прежнем кабинете.',
    ACCOUNT_IMAGE_LIMIT: 'Достигнут лимит активных клубных образов. Отзовите ненужный образ.',
    SUBSCRIPTION_EXPIRED: 'Сначала продлите подписку.',
    CLUB_PAYMENT_REQUIRED: 'Дождитесь подтверждения оплаты. Затем клубную подписку проверит оператор.',
    CLUB_VERIFICATION_PENDING: 'Оплата подтверждена. Клубная подписка ожидает проверки.',
    PERSONAL_SEAT_CHANGE_NOT_AVAILABLE: 'Число ПК в существующей подписке можно уточнить в поддержке.',
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
  function dateTime(s) { return new Date(s).toLocaleString('ru-RU', {dateStyle:'short', timeStyle:'short'}); }
  function rub(n) { return n.toLocaleString('ru-RU', {minimumFractionDigits: 2, maximumFractionDigits: 2}) + ' ₽'; }
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
  var trialCode = $('[data-trial-code]');
  var trialButton = $('[data-trial-activate]');
  var trialError = $('[data-trial-error]');
  $('[data-logout]').addEventListener('click', function () {
    trialCode.textContent = '';
    $('[data-trial-panel]').hidden = true;
    say(trialError, '');
  });
  trialButton.addEventListener('click', function () {
    if (trialButton.disabled || !trialCode.textContent) return;
    busy(trialButton, true);
    say(trialError, '');
    call('POST', '/trial/activate', {code: trialCode.textContent}).then(function () {
      return load().then(function () {
        var card = $('[data-subs] .acc-sub');
        if (card) card.focus();
      });
    }).catch(function (error) {
      say(trialError, message(error.message));
    }).then(function () { busy(trialButton, false); });
  });

  function planOf(id) { for (var i = 0; i < state.plans.length; i++) if (state.plans[i].id === id) return state.plans[i]; return null; }

  function renderPlans(target) {
    target.textContent = '';
    var hasPersonal = state.kind==='player' && state.subscriptions.some(function(s){return s.kind==='player';});
    $('#account-plans').style.display = hasPersonal ? 'none' : '';
    var plans = hasPersonal ? [] : state.plans.filter(function(p){ return !state.kind || p.kind === state.kind; });
    $('[data-plans-empty]').hidden = plans.length > 0;
    $('[data-choose-plan]').hidden = plans.length === 0;
    $('[data-subs-hint]').textContent = plans.length ? 'Выберите тариф, чтобы подключить компьютеры к VELIQ.' : 'Здесь появятся ваша подписка и подключённые компьютеры.';
    plans.forEach(function (p) {
      var card = el('form', 'card acc-plan');
      card.appendChild(el('h3', 'h3', p.title));
      var publicPrice = state.paymentsOn ? p.price_per_seat_rub : window.veliqPricing && window.veliqPricing.prices[p.kind];
      card.appendChild(el('p', 'muted', publicPrice ? (rub(publicPrice) + (p.kind === 'club' ? ' за ПК' : ' за одно место') + ' за 30 дней') : 'Условия подключения — в поддержке'));
      var seats = null;
      if (p.max_seats > 1) {
        var label = el('label', 'field'); label.appendChild(el('span', null, 'Сколько компьютеров'));
        if (p.kind === 'player') {
          seats = el('select', 'input');
          for (var count = 1; count <= Math.min(p.max_seats, 3); count++) {
            var option = el('option', null, count + ' ПК');
            option.value = count;
            seats.appendChild(option);
          }
        } else {
          seats = el('input', 'input');
          seats.type = 'number';
          seats.min = 1;
          seats.max = p.max_seats;
          seats.value = Math.min(10, p.max_seats);
          seats.required = true;
        }
        label.appendChild(seats); card.appendChild(label);
        if (p.kind === 'player' && publicPrice) {
          var total = el('p', 'muted');
          total.setAttribute('aria-live', 'polite');
          function showTotal() {
            total.textContent = 'За 30 дней: ' + rub(publicPrice * Number(seats.value));
          }
          seats.addEventListener('change', showTotal);
          showTotal();
          card.appendChild(total);
        }
      }
      var btn = el('button', 'btn', 'Оформить'); btn.type = 'submit'; card.appendChild(btn);
      var err = el('p', 'acc-error'); err.hidden = true; card.appendChild(err);
      card.addEventListener('submit', function (e) {
        e.preventDefault(); busy(btn, true); say(err, '');
        call('POST', '/subscriptions', { plan_id: p.id, seats: seats ? parseInt(seats.value, 10) : 1 }).then(function(result){state.selectedSubscription=result.id;return load();})
          .catch(function (x) { say(err, message(x.message)); }).then(function () { busy(btn, false); });
      });
      target.appendChild(card);
    });
  }

  function renderSubscription(s, paymentsOn, autoRenewAvailable) {
    var p = planOf(s.plan_id) || { title: 'Подписка', kind: s.kind };
    var card = el('article', 'card acc-sub');
    card.id='subscription-'+s.id;card.tabIndex=-1;card.style.overflowWrap='anywhere';
    card.appendChild(el('p','acc-small',(state.name || 'Мой аккаунт')+' · Подписка '+s.id));
    if(state.selectedSubscription===s.id){card.setAttribute('aria-label','Выбранная подписка '+s.id);card.appendChild(el('p','acc-badge','Выбрана эта подписка'));}
    var openOrders=(state.orders||[]).filter(function(o){return o.quote.subscription_id===s.id && o.status!=='succeeded';});
    openOrders.forEach(function(o){var box=el('div','acc-small');box.appendChild(el('p',null,'Заказ '+o.id+' · '+o.quote.seats+' ПК · '+o.quote.days+' дней · '+rub(o.quote.amount_kopecks/100)+'. Условия зафиксированы.'));box.appendChild(el('p',null,'Статус: '+(o.status==='canceled'?'отменён провайдером, но позднее подтверждение ещё возможно':'ожидает подтверждения')+'. Резерв не освобождён. Новый заказ может быть недоступен до проверки.'));if(o.redirect&&o.status==='pending'){var resume=el('a','btn btn--sm','Продолжить оплату этого заказа');resume.href=o.redirect;box.appendChild(resume);}card.appendChild(box);});
    var head = el('div', 'acc-sub__head');
    head.appendChild(el('h3', 'h3', p.title + (s.kind === 'club' || s.seats > 1 ? ' · ' + s.seats + ' ПК' : '')));
    var remaining=s.paid_until?new Date(s.paid_until).getTime()-Date.now():NaN;
    if(!s.lifetime&&remaining>0&&remaining<=7*86400000){var notice=el('p','acc-error','Подписка заканчивается '+date(s.paid_until)+'. Продлите доступ, чтобы продолжить пользоваться VELIQ.');notice.setAttribute('role','status');card.appendChild(notice);}
    var status = 'Не оплачена';
    if (s.lifetime) status = 'Бессрочно';
    else if (s.paid_until) status = (s.active ? 'Оплачено до ' : 'Закончилась ') + date(s.paid_until);
    else if (s.trial_until) status = s.active ? 'Пробный доступ до ' + dateTime(s.trial_until) : 'Пробный доступ завершён';
    head.appendChild(el('span', 'acc-badge' + (s.active ? ' acc-badge--ok' : ''), status));
    card.appendChild(head);
    card.appendChild(el('p', 'muted', 'Занято компьютеров: ' + s.used_seats + ' из ' + s.seats));

    var actions = el('div', 'acc-actions');
    var err = el('p', 'acc-error'); err.hidden = true;
    var payLabel = 'Оплатить';
    if (s.paid_until) payLabel = 'Продлить';
    else if (s.trial_until && !s.active) payLabel = 'Выбрать срок и оплатить';
    var pay = el('button', 'btn', payLabel);
    var duration=el('select','input');duration.setAttribute('aria-label','Срок продления');
    var policy=window.veliqPricing; var terms=state.terms || []; terms.forEach(function(t){var o=el('option',null,t.months+' мес. ('+t.days+' дней)'+(t.discount?' · скидка '+t.discount+'%':''));o.value=t.months;duration.appendChild(o);});
    var durationLabel=el('label','field');durationLabel.appendChild(el('span',null,'Срок подписки'));durationLabel.appendChild(duration);
    var quote=el('p','muted');quote.setAttribute('aria-live','polite');
    var appliedCode='', appliedQuote=null, quoteVersion=0, checking=false;
    function quotedAmount(){var term=terms.find(function(t){return t.months===Number(duration.value);});var base=paymentsOn?p.price_per_seat_rub:policy&&policy.prices[s.kind];return appliedQuote?appliedQuote.amount_kopecks:term&&base?base*s.seats*term.months*(100-term.discount):0;}
    function showQuote(){var term=terms.find(function(t){return t.months===Number(duration.value);});if(!term)return;var base=(paymentsOn?p.price_per_seat_rub:policy&&policy.prices[s.kind])*s.seats*term.months*100;var reduction=appliedQuote?appliedQuote.base_amount_kopecks-appliedQuote.amount_kopecks:base-quotedAmount();quote.textContent='За '+term.days+' дней. Базовая сумма: '+rub(base/100)+'. Скидка: '+rub(reduction/100)+'. К оплате: '+rub(quotedAmount()/100)+'. Комиссия для вас: 0 ₽. Разовая оплата без автосписаний.';}

    var promo=el('details','acc-promo'), summary=el('summary',null,'У меня есть промокод');promo.appendChild(summary);
    var promoForm=el('form','acc-promo__form'), promoLabel=el('label','field'), promoInput=el('input','input');
    promoLabel.appendChild(el('span',null,'Промокод'));promoInput.type='text';promoInput.maxLength=64;promoInput.autocomplete='off';promoInput.spellcheck=false;promoInput.required=true;promoLabel.appendChild(promoInput);promoForm.appendChild(promoLabel);
    var apply=el('button','btn btn--sm','Применить');apply.type='submit';promoForm.appendChild(apply);
    var remove=el('button','btn btn--sm btn--quiet','Убрать промокод');remove.type='button';remove.hidden=true;promoForm.appendChild(remove);
    var promoNote=el('p','acc-small');promoNote.setAttribute('role','status');promoNote.hidden=true;promo.appendChild(promoForm);promo.appendChild(promoNote);
    function clearPromo(){quoteVersion++;appliedCode='';appliedQuote=null;remove.hidden=true;checking=false;busy(apply,false);busy(pay,false);say(promoNote,'');showQuote();}
    duration.addEventListener('change',clearPromo);promoInput.addEventListener('input',clearPromo);
    remove.addEventListener('click',function(){clearPromo();promoInput.value='';promoInput.focus();});
    promoForm.addEventListener('submit',function(e){
      e.preventDefault();if(checking||pay.getAttribute('aria-busy')==='true')return;
      var code=promoInput.value.trim();if(!code)return;clearPromo();var version=quoteVersion;
      checking=true;busy(apply,true);busy(pay,true);say(promoNote,'Проверяем промокод…');
      call('POST','/subscriptions/'+s.id+'/quote',{months:Number(duration.value),promo_code:code}).then(function(result){
        if(version!==quoteVersion)return;
        if(!Number.isSafeInteger(result.amount_kopecks)||result.amount_kopecks<1)throw new Error('PAYMENT_UNAVAILABLE');
        appliedCode=code;appliedQuote=result;remove.hidden=false;showQuote();say(promoNote,'Расчёт получен. Льгота: '+rub((result.base_amount_kopecks-result.amount_kopecks)/100)+(result.eligible_seconds!=null?' на '+result.eligible_seats+' первоначальных мест, '+(result.eligible_seconds/86400).toLocaleString('ru-RU',{maximumFractionDigits:6})+' дней.':'.'));
      }).catch(function(x){if(version===quoteVersion)say(promoNote,message(x.message));}).then(function(){if(version===quoteVersion){checking=false;busy(apply,false);busy(pay,false);}});
    });
    showQuote();
    if(!s.lifetime){card.appendChild(durationLabel);card.appendChild(quote);if(paymentsOn)card.appendChild(promo);}
    function showPaymentConfirmation(refreshed) {
      if(checking||pay.disabled)return;
      if(!paymentsOn){say(err,'Онлайн-оплата пока не подключена. Для оформления или продления обратитесь в поддержку.');return;}
      var expected=window.veliqPricing&&window.veliqPricing.prices[s.kind];if(expected&&p.price_per_seat_rub!==expected){say(err,'Для оформления по актуальному тарифу обратитесь в поддержку. Онлайн-оплата пока недоступна.');return;}
      if(!terms.length || p.period_days!==30 || !quotedAmount()){say(err,'Тариф временно недоступен для онлайн-оплаты. Обратитесь в поддержку.');return;}
      busy(pay, true); say(err, ''); duration.disabled=true;promoInput.disabled=true;apply.disabled=true;remove.disabled=true;
      function unlock(){busy(pay,false);duration.disabled=false;promoInput.disabled=false;apply.disabled=false;remove.disabled=false;}
      var request={auto_renew:false,months:Number(duration.value)};if(appliedCode)request.promo_code=appliedCode;
      call('POST','/subscriptions/'+s.id+'/quote',request).then(function(frozen){
        if(!Number.isSafeInteger(frozen.amount_kopecks)||frozen.amount_kopecks<1)throw new Error('PAYMENT_UNAVAILABLE');
        var dialog=el('dialog','card');dialog.style.maxWidth='min(36rem, calc(100vw - 2rem))';dialog.style.maxHeight='85vh';dialog.style.overflow='auto';dialog.style.overflowWrap='anywhere';dialog.setAttribute('aria-label','Подтверждение оплаты подписки');
        dialog.appendChild(el('h2','h3','Проверьте заказ перед оплатой'));
        if(refreshed){var changeNote=el('p','acc-small',message('PAYMENT_PRICE_CHANGED'));changeNote.setAttribute('role','status');dialog.appendChild(changeNote);}
        var operation=(frozen.operation || (s.paid_until?'renewal':'purchase'))==='renewal'?'Продление':'Первая покупка';
        [ (state.name || 'Мой аккаунт')+(frozen.club_reference?' · Клуб '+frozen.club_reference:''), 'Подписка: '+s.id, operation+' · '+p.title, 'Компьютеров: '+s.seats+'. Срок: '+frozen.days+' дней.', 'Базовая сумма: '+rub(frozen.base_amount_kopecks/100), 'Скидка: '+rub((frozen.base_amount_kopecks-frozen.amount_kopecks)/100), 'К оплате: '+rub(frozen.amount_kopecks/100)+'. Комиссия для вас: 0 ₽.' ].forEach(function(line){dialog.appendChild(el('p',null,line));});
        if(frozen.eligible_seconds!=null)dialog.appendChild(el('p',null,'По текущему расчёту скидка 30% действует на '+frozen.eligible_seats+' первоначальных мест и '+(frozen.eligible_seconds/86400).toLocaleString('ru-RU',{maximumFractionDigits:6})+' дней льготного периода. Остальной срок — по полной цене.'));
        if(frozen.window_end)dialog.appendChild(el('p',null,'Льготное окно заканчивается '+new Date(frozen.window_end).toLocaleString('ru-RU')+'. Оно не начинается заново при продлении.'));
        dialog.appendChild(el('p',null,'После подтверждения оплаты эта подписка получит '+frozen.days+' дней'+(frozen.expected_start?' (ожидаемо с '+new Date(frozen.expected_start).toLocaleString('ru-RU')+' до '+new Date(frozen.expected_end).toLocaleString('ru-RU')+')':'')+'. При поздней оплате полный срок сохраняется; новая льгота не возникает. Автосписаний нет.'));
        var confirm=el('button','btn','Подтвердить и перейти к оплате'),cancel=el('button','btn btn--quiet','Вернуться к выбору');confirm.type=cancel.type='button';dialog.appendChild(confirm);dialog.appendChild(cancel);root.appendChild(dialog);
        function close(){dialog.close();dialog.remove();unlock();pay.focus();}
        cancel.addEventListener('click',close);dialog.addEventListener('cancel',function(e){e.preventDefault();close();});
        confirm.addEventListener('click',function(){
          busy(confirm,true);cancel.disabled=true;
          request.expected_amount_kopecks=frozen.amount_kopecks;
          if(s.kind==='club'){request.quote_version=frozen.quote_version;request.idempotency_key=crypto.randomUUID();}
          // Keep the same request/key on an uncertain browser response. The server
          // returns its original order or reconciliation, never another provider POST.
          function send(){
            call('POST','/subscriptions/'+s.id+'/pay',request).then(function(result){
              if(!result.redirect)throw new Error('PROMO_RECONCILIATION_REQUIRED');
              location.href=result.redirect;
            }).catch(function(x){
              if(!dialog.open)return;
              if(s.kind==='club'&&x.message==='PAYMENT_PRICE_CHANGED'){
                close();
                showPaymentConfirmation(true);
                return;
              }
              var note=dialog.querySelector('[data-confirm-error]');
              if(!note){note=el('p','acc-error');note.setAttribute('data-confirm-error','');note.setAttribute('role','alert');dialog.appendChild(note);}
              say(note,message(x.message));
              busy(confirm,false);cancel.disabled=false;
            });
          }
          send();
          // Subsequent clicks retain the same immutable request, including its key.
          confirm.onclick=function(e){e.stopImmediatePropagation();busy(confirm,true);send();};
        },{once:true});
        dialog.showModal();cancel.focus();
      }).catch(function(x){say(err,message(x.message));unlock();});
    }
    pay.addEventListener('click',function(){showPaymentConfirmation(false);});
    if (!s.lifetime) actions.appendChild(pay);
    card.appendChild(actions);
    if (s.club_verification === 'verified') {
      var requestCode = el('button', 'btn btn--sm', 'Получить код активации');
      requestCode.type = 'button';
      var issuedCode = el('p', 'acc-small');
      issuedCode.setAttribute('role', 'status');
      requestCode.addEventListener('click', function () {
        if (issuedCode.textContent && !confirm('Выпустить новый код? Уже подключённые ПК сохранят доступ.')) return;
        busy(requestCode, true);
        say(err, '');
        call('POST', '/subscriptions/' + s.id + '/code').then(function (result) {
          issuedCode.textContent = 'Код для ' + s.seats + ' ПК: ' + result.code;
        }).catch(function (x) { say(err, message(x.message)); }).then(function () { busy(requestCode, false); });
      });
      actions.appendChild(requestCode);
      card.appendChild(issuedCode);
    } else if (s.club_verification) {
      var reviewNotice = s.club_verification === 'pending' ? MESSAGES.CLUB_VERIFICATION_PENDING :
        s.club_verification === 'expired' ? MESSAGES.SUBSCRIPTION_EXPIRED : MESSAGES.CLUB_PAYMENT_REQUIRED;
      var review = el('p', 'muted acc-small', reviewNotice);
      review.setAttribute('role', 'status');
      card.appendChild(review);
    } else {
      card.appendChild(el('p', 'muted acc-small', 'Чтобы подключить компьютер, откройте VELIQ на нём и нажмите «Войти или зарегистрироваться». Копировать код активации не нужно.'));
    }
    if (!paymentsOn && !s.lifetime) card.appendChild(el('p', 'muted acc-small', 'Онлайн-оплата пока не подключена. Для подключения или продления обратитесь в поддержку.'));
    if (paymentsOn && autoRenewAvailable && !s.lifetime) {
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

  function renderPayment(p, primary) {
    var row = el('li');
    row.style.overflowWrap='anywhere';
    row.appendChild(el('span', null, 'Заказ '+p.id+' · Подписка '+p.subscription_id+' · '+date(p.created_at)+' · '+rub(p.amount_kopecks/100)+' · '+p.period_days+' дней'));
    var status = p.review_required ? 'Возврат или спор · требуется проверка' :
      p.status==='succeeded' ? 'оплачено' : p.status==='pending' ? 'ожидает оплаты' : 'отменено';
    row.appendChild(el('span','muted',status));
    if(p.provider==='platega' && (p.status!=='succeeded' || p.review_required)){
      var check=el('button','btn btn--sm btn--quiet','Проверить оплату');
      var note=el('span','muted');note.setAttribute('role','status');
      check.addEventListener('click',function(){
        busy(check,true);say(note,'Проверяем подтверждение…');
        call('POST','/payments/'+p.id+'/refresh',{}).then(function(result){
          return load().then(function(){
            var text = result.review_required ? 'По платежу отмечен возврат или спор. Текущий срок доступа указан в подписке.' :
              result.status==='succeeded' ? 'Оплата подтверждена. Срок доступа обновлён.' :
              result.status==='canceled' ? 'Оплата отменена. Срок доступа не изменён.' :
              'Подтверждение ещё не получено. Повторите проверку позже; не оплачивайте повторно, если деньги списаны.';
            var resultNote=el('li','muted',text);
            resultNote.setAttribute('role','status');
            $('[data-payments]').prepend(resultNote);
          });
        }).catch(function(error){say(note,message(error.message));busy(check,false);});
      });
      row.appendChild(check);row.appendChild(note);
    }
    if(primary && state.subscriptions.some(function(s){return s.id===p.subscription_id;})){
      var select=el('button','btn btn--sm btn--quiet','Показать подписку');
      select.addEventListener('click',function(){
        state.selectedSubscription=p.subscription_id;
        var target=document.getElementById('subscription-'+p.subscription_id);
        if(target){target.scrollIntoView({block:'center'});target.focus();}
      });
      row.appendChild(select);
    }
    return row;
  }

  function renderPayments(payments, params) {
    var list=$('[data-payments]');
    var previousHistory=list.querySelector('details');
    list.textContent='';
    $('[data-payments-empty]').hidden=payments.length>0;
    var returnID=params.get('order');
    var returnedPayment=payments.find(function(p){return p.id===returnID;});
    var primary=returnedPayment ||
      payments.find(function(p){return p.status==='pending'&&!p.review_required;}) || payments[0];
    if(params.get('payment')==='return'){
      var knownPayment=returnID ? returnedPayment : primary;
      var notice=el('li','muted',knownPayment ? 'Вы вернулись с формы оплаты. Статус платежа указан ниже.' :
        'Вы вернулись с формы оплаты. Сведения об этом платеже пока недоступны.');
      notice.setAttribute('role','status');
      list.appendChild(notice);
    }
    if(!primary)return;
    list.appendChild(renderPayment(primary,true));
    if(payments.length>1){
      var history=el('details','acc-small');
      history.style.width='100%';
      history.open=!!previousHistory&&previousHistory.open;
      history.appendChild(el('summary',null,'История платежей ('+(payments.length-1)+')'));
      var older=el('ul','acc-pays');
      payments.forEach(function(p){if(p!==primary)older.appendChild(renderPayment(p,false));});
      history.appendChild(older);
      var historyRow=el('li');historyRow.appendChild(history);list.appendChild(historyRow);
    }
  }

  function load() {
    return call('GET', '').then(function (data) {
      state.name=data.name||'';state.orders=data.club_orders||[];state.plans = data.plans || []; state.terms=data.payment_terms || (!data.payments_enabled && window.veliqPricing ? (data.kind==='club'?window.veliqPricing.club_terms:window.veliqPricing.terms).map(function(t){return {months:t.months,discount:t.discount,days:t.months*30};}):[]); state.paymentsOn=!!data.payments_enabled; state.kind=data.kind || ''; state.subscriptions=data.subscriptions || []; state.enforced=!!data.subscription_enforced;
      if(!state.kind){ updateProfileFields(); show('profile'); return; }
      trialCode.textContent = state.kind === 'player' ? (data.trial_code || '') : '';
      $('[data-trial-panel]').hidden = !trialCode.textContent;
      say(trialError, '');
      $('[data-account-email]').textContent = data.email;
      $('[data-account-kind]').textContent = (data.kind === 'club' ? 'Клуб' : 'Пользователь') + (data.name ? ' · ' + data.name : '');
      $('#account-subscriptions-title').textContent=state.kind==='player' ? 'Личный доступ' : 'Мои подписки';
      var subs = $('[data-subs]'); subs.textContent = '';
      (data.subscriptions || []).forEach(function (s) { subs.appendChild(renderSubscription(s, data.payments_enabled, data.auto_renew_available)); });
      $('[data-subs-empty]').hidden = (data.subscriptions || []).length > 0;
      renderPlans($('[data-plans]'));
      var params=new URLSearchParams(location.search);
      renderPayments(data.payments || [],params);
      show('cabinet'); renderLink(); renderImages();
      var selected=state.selectedSubscription || params.get('subscription');
      if(selected && state.subscriptions.some(function(s){return s.id===selected;})){var target=document.getElementById('subscription-'+selected);if(target){target.scrollIntoView({block:'center'});target.focus();}}
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
      if (!info.approved && !select.options.length && trialCode.textContent) {
        $('[data-link-message]').textContent = 'Можно активировать пробный день ниже и подключить компьютер.';
        return;
      }
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
