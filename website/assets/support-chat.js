/* VELIQ support. No message content or access credentials in browser storage. */
(function () {
  'use strict';
  if (document.getElementById('veliq-support')) return;
  var root = document.createElement('div'); root.id = 'veliq-support';
  root.innerHTML = '<button class="vs-launch" type="button" aria-expanded="false" aria-controls="vs-panel">Поддержка<span class="vs-badge" hidden> · новый ответ</span></button>' +
    '<section id="vs-panel" class="vs-panel" role="dialog" aria-modal="false" aria-labelledby="vs-title" hidden>' +
    '<header class="vs-head"><div><strong id="vs-title">Поддержка VELIQ</strong><p class="vs-status" role="status">Подключаемся…</p></div><div class="vs-head-actions"><button class="vs-info-toggle" type="button" aria-label="О чате" aria-expanded="false" aria-controls="vs-info">i</button><button class="vs-close" type="button" aria-label="Закрыть диалог">×</button></div></header>' +
    '<div id="vs-info" class="vs-info" hidden><p>Ответим здесь. Не отправляйте пароли и коды. Переписка передаётся команде через Telegram. <a href="/privacy">Конфиденциальность</a></p><p>После входа переписка доступна только вашему аккаунту. Гостевой диалог остаётся в этом браузере. На общем ПК завершите сессию после разговора.</p><button type="button" class="vs-forget">Завершить сессию поддержки</button></div>' +
    '<button class="vs-older" type="button" hidden>Предыдущие сообщения</button><div class="vs-messages" role="log" aria-label="Переписка" aria-live="polite" aria-relevant="additions"></div>' +
    '<p class="vs-error" role="alert" hidden></p>' +
    '<div class="vs-confirm" hidden><strong>Вопрос решён?</strong><p>Если нет — продолжим разбираться.</p><button type="button" data-answer="yes">Да, решён</button><button type="button" data-answer="no">Нет, нужна помощь</button><button type="button" data-answer="later">Свернуть, ответ прочитаю позже</button></div>' +
    '<form class="vs-form"><label class="vs-sr-only" for="vs-input">Ваше сообщение</label><textarea id="vs-input" maxlength="2000" rows="1" placeholder="Напишите сообщение…" required></textarea><div class="vs-form-bottom"><span class="vs-compose-hint">Enter — отправить · Shift+Enter — новая строка</span><span class="vs-count" hidden>0 / 2000</span><button type="submit">Отправить</button></div></form>' +
    '<div class="vs-resolved" hidden><p>Вопрос решён. Спасибо за обращение!</p><button type="button" class="vs-new">Новый вопрос</button></div>' +
    '<div class="vs-forget-confirm" role="alertdialog" aria-labelledby="vs-forget-title" hidden><strong id="vs-forget-title">Завершить сессию на этом ПК?</strong><p>Переписка исчезнет из этого браузера. У поддержки она сохранится, обращение останется открытым.</p><div><button type="button" class="vs-forget-cancel">Продолжить диалог</button><button type="button" class="vs-forget-yes">Завершить сессию</button></div></div></section>';
  document.body.appendChild(root);
  var q = function (s) { return root.querySelector(s); };
  var panel=q('.vs-panel'), launcher=q('.vs-launch'), input=q('textarea'), form=q('form'), list=q('.vs-messages');
  var state=null, busy=false, opened=false, pending=null, seen=0, timer=null, refreshing=false, creating=false, generation=0, identity='', authPending=false, heldDraft=null;
  input.disabled=true;q('[type=submit]').disabled=true;
  try { opened=sessionStorage.getItem('veliq-support-open')==='1'; seen=Number(sessionStorage.getItem('veliq-support-seen')||0); } catch (_) {}
  function remember() { try { sessionStorage.setItem('veliq-support-open',opened?'1':'0'); sessionStorage.setItem('veliq-support-seen',String(seen)); } catch (_) {} }
  function error(message) { q('.vs-error').textContent=message||'';q('.vs-error').hidden=!message; }
  function key() { return Array.from(crypto.getRandomValues(new Uint8Array(32))).map(function(v){return v.toString(16).padStart(2,'0');}).join(''); }
  async function api(path, body) {
    var ctl=new AbortController(), timeout=setTimeout(function(){ctl.abort();},10000);
    try {
      var res=await fetch('/api/v1/account/support/'+path,{method:body?'POST':'GET',credentials:'same-origin',cache:'no-store',headers:body?{'Content-Type':'application/json','X-Support-Context':identity}:{},body:body?JSON.stringify(body):undefined,signal:ctl.signal});
      var data=await res.json();
      if (!res.ok) { var e=new Error(data.error||'unavailable');e.status=res.status;throw e; } return data;
    } finally { clearTimeout(timeout); }
  }
  function describe(e) {
    if(e.message==='identity_changed')return 'Аккаунт изменился. Переписка обновлена; напишите сообщение заново.';
    if(e.status===409)return 'Диалог изменился. Прочитайте новые сообщения и повторите действие.';
    if(e.status===401)return 'Сессия закончилась. Новое обращение можно начать после обновления страницы.';
    if(e.status===429)return 'Слишком много сообщений. Подождите минуту и попробуйте снова.';
    if(e.message==='support_not_connected')return 'Чат пока не подключён. Попробуйте позже.';
    return 'Связь прервалась. Сообщение не подтверждено: повторите отправку, текст сохранён в поле.';
  }
  function show(open) { opened=open;panel.hidden=!open;launcher.setAttribute('aria-expanded',String(open));remember();if(open){q('.vs-badge').hidden=true;refresh();input.focus();}else launcher.focus(); }
  function append(messages,prepend) {
    var fragment=document.createDocumentFragment();
    messages.forEach(function(m){if(list.querySelector('[data-message="'+m.id+'"]'))return;
      var el=document.createElement('div');el.className='vs-message vs-message--'+m.role;el.dataset.message=m.id;
      var name=document.createElement('strong');name.textContent=m.role==='visitor'?'Вы':m.role==='operator'?'Специалист VELIQ':'VELIQ';
      var text=document.createElement('p');text.textContent=m.body;
      var date=document.createElement('time');date.dateTime=m.created_at;date.textContent=new Date(m.created_at).toLocaleTimeString('ru',{hour:'2-digit',minute:'2-digit'});
      el.append(name,text,date);fragment.appendChild(el);
    });
    var height=list.scrollHeight,nearBottom=list.scrollHeight-list.scrollTop-list.clientHeight<70;
    if(prepend){list.prepend(fragment);list.scrollTop+=list.scrollHeight-height;}else{list.appendChild(fragment);if(nearBottom)list.scrollTop=list.scrollHeight;}
  }
  function clearPrivate() {
    generation++;state=null;identity='';pending=null;heldDraft=null;creating=false;busy=false;refreshing=false;seen=0;
    input.value='';input.disabled=true;q('[type=submit]').disabled=true;list.replaceChildren();
    q('.vs-count').hidden=true;q('.vs-badge').hidden=true;q('.vs-older').hidden=true;
    q('.vs-confirm').hidden=true;q('.vs-forget-confirm').hidden=true;q('.vs-resolved').hidden=true;
    form.hidden=false;error('');remember();
    q('.vs-status').textContent='Проверяем сессию…';
  }
  function recheckPrivate() {
    var saved=heldDraft||(identity?{context:identity,body:input.value,pending:pending}:null);
    clearPrivate();if(!authPending)heldDraft=saved;refresh();
  }
  window.addEventListener('veliq:account-transition',function(e){
    clearPrivate();authPending=!!(e.detail&&e.detail.pending);if(!authPending)refresh();
  });
  window.addEventListener('pagehide',clearPrivate);
  window.addEventListener('pageshow',function(){clearPrivate();refresh();});
  function render(next) {
    if(!next.context) { clearPrivate();return; }
    if(identity&&identity!==next.context)clearPrivate();
    identity=next.context;
    if(heldDraft){if(heldDraft.context===identity){input.value=heldDraft.body;pending=heldDraft.pending;fitInput();}heldDraft=null;}
    q('.vs-forget').textContent=next.identity==='account'?'Выйти из аккаунта на этом ПК':'Завершить сессию поддержки';
    q('#vs-forget-title').textContent=next.identity==='account'?'Выйти из аккаунта на этом ПК?':'Завершить сессию на этом ПК?';
    if(!state||!state.ticket||!next.ticket||state.ticket.id!==next.ticket.id){list.replaceChildren();creating=false;}
    state=next;
    var t=state.ticket;
    q('.vs-status').textContent=!state.available?'Чат пока не подключён':!t?'Напишите нам':t.status==='queued'?'Обращение в очереди':t.status==='assigned'?'Обращение у специалиста':'Вопрос решён';
    append(state.messages||[],false);q('.vs-older').hidden=!state.has_more;
    var resolved=t&&t.status==='resolved'&&!creating;
    q('.vs-resolved').hidden=!resolved;form.hidden=!!resolved;input.disabled=!state.available||busy;q('[type=submit]').disabled=!state.available||busy;
    var last=0;(state.messages||[]).forEach(function(m){if(m.role==='operator')last=Math.max(last,m.id);});
    if(opened){seen=Math.max(seen,last);remember();}else if(last>seen){q('.vs-badge').hidden=false;}
  }
  async function refresh() {
    if(refreshing||busy||authPending)return;refreshing=true;var epoch=generation;
    try {var next=await api('state');if(epoch===generation&&!busy&&!authPending)render(next);}
    catch(e){if(epoch===generation){clearPrivate();q('.vs-status').textContent=e.status===401?'Войдите в аккаунт, чтобы продолжить':'Не удалось проверить сессию. Попробуйте позже.';}}
    finally{if(epoch===generation)refreshing=false;clearTimeout(timer);timer=setTimeout(refresh,document.hidden?30000:opened?4000:15000);}
  }
  launcher.addEventListener('click',function(){if(opened)close();else show(true);});
  function close(){if(busy)return;if(state&&state.ticket&&state.ticket.status!=='resolved'){q('.vs-confirm').hidden=false;q('[data-answer="no"]').focus();}else show(false);}
  q('.vs-close').addEventListener('click',close);
  q('.vs-info-toggle').addEventListener('click',function(){var info=q('.vs-info');info.hidden=!info.hidden;this.setAttribute('aria-expanded',String(!info.hidden));});
  root.addEventListener('keydown',function(e){if(e.key==='Escape'&&opened){e.preventDefault();close();}});
  q('[data-answer="no"]').addEventListener('click',function(){q('.vs-confirm').hidden=true;input.placeholder='Расскажите подробнее: что осталось нерешённым?';input.focus();});
  q('[data-answer="later"]').addEventListener('click',function(){q('.vs-confirm').hidden=true;show(false);});
  q('[data-answer="yes"]').addEventListener('click',async function(){
    if(busy||authPending||!state||!state.ticket)return;busy=true;var epoch=++generation;error('');
    var revision=state.ticket.revision,id=state.ticket.id;
    try{await api('resolve',{key:key(),ticket:id,revision:revision});if(epoch!==generation)return;q('.vs-confirm').hidden=true;busy=false;await refresh();if(epoch===generation)show(false);}
    catch(e){if(epoch!==generation)return;if(e.message==='identity_changed'||e.status===401)clearPrivate();else {error(describe(e));busy=false;}await refresh();}
  });
  function fitInput(){input.style.height='auto';input.style.height=Math.min(input.scrollHeight,130)+'px';var n=Array.from(input.value).length;q('.vs-count').textContent=n+' / 2000';q('.vs-count').hidden=n<1700;}
  input.addEventListener('input',fitInput);
  input.addEventListener('keydown',function(e){if(e.key==='Enter'&&!e.shiftKey&&!e.isComposing&&e.keyCode!==229){e.preventDefault();if(!busy&&input.value.trim())form.requestSubmit();}});
  form.addEventListener('submit',async function(e){
    e.preventDefault();if(busy||authPending||!input.value.trim()||!state||!state.available||!identity)return;
    var body=input.value.trim(),ticket=state.ticket&&!creating?state.ticket.id:'';
    if(!pending||pending.body!==body)pending={key:key(),ticket:ticket,body:body};
    busy=true;var epoch=++generation;input.disabled=true;q('[type=submit]').disabled=true;error('');
    try{
      if(!state.session){var session=await api('session',{});if(epoch!==generation)return;identity=session.context;state.context=identity;state.session=true;}
      await api('message',pending);if(epoch!==generation)return;
      pending=null;input.value='';q('.vs-count').textContent='0 / 2000';fitInput();creating=false;
    } catch(ex){
      if(epoch!==generation)return;
      if(ex.message==='identity_changed'||ex.status===401){clearPrivate();await refresh();return;}
      error(describe(ex));if(ex.status===409)pending=null;
    } finally{if(epoch===generation){busy=false;await refresh();input.focus();}}
  });
  q('.vs-new').addEventListener('click',function(){creating=true;q('.vs-resolved').hidden=true;form.hidden=false;input.focus();});
  q('.vs-older').addEventListener('click',async function(){
    var first=list.firstElementChild;if(!first||!state||!state.ticket||authPending)return;
    var epoch=generation,owner=identity,id=state.ticket.id;
    try {var old=await api('state?ticket='+id+'&before='+first.dataset.message);
      if(epoch!==generation)return;
      if(old.context!==owner){clearPrivate();await refresh();return;}
      append(old.messages,true);q('.vs-older').hidden=!old.has_more;
    }catch(e){if(epoch===generation)error(describe(e));}
  });
  q('.vs-forget').addEventListener('click',function(){if(busy)return;q('.vs-forget-confirm').hidden=false;q('.vs-forget-cancel').focus();});
  q('.vs-forget-cancel').addEventListener('click',function(){q('.vs-forget-confirm').hidden=true;q('.vs-forget').focus();});
  q('.vs-forget-yes').addEventListener('click',async function(){
    if(busy||authPending||!state)return;
    q('.vs-forget-confirm').hidden=true;q('.vs-info').hidden=true;q('.vs-info-toggle').setAttribute('aria-expanded','false');
    var account=state.identity==='account';
    try {
      if(account){
        var res=await fetch('/api/v1/account/logout',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:'{}'});
        if(!res.ok)throw new Error('logout_failed');
        clearPrivate();location.assign('/account');
      } else {
        await api('forget',{});clearPrivate();
        if(window.veliqSupportAuthChanged)window.veliqSupportAuthChanged();
        await refresh();
      }
    }catch(e){clearPrivate();error('Сессию завершить не удалось. Попробуйте ещё раз.');await refresh();}
  });
  document.addEventListener('visibilitychange',recheckPrivate);
  window.addEventListener('focus',recheckPrivate);
  /* Explicit user action opens the existing conversation without creating a ticket. */
  var mobileDraftRequested=false, renderBeforeLink=render;
  function prepareMobileDraft(){
    if(!mobileDraftRequested||!state)return;
    mobileDraftRequested=false;
    if(state.ticket&&state.ticket.status==='resolved'){
      creating=true;q('.vs-resolved').hidden=true;form.hidden=false;
      q('.vs-status').textContent='Новый вопрос';
      if(opened)input.focus();
    }
  }
  render=function(next){renderBeforeLink(next);prepareMobileDraft();};
  function openFromLink(topic) {
    if(topic==='mobile')mobileDraftRequested=true;
    q('.vs-confirm').hidden=true;
    show(true);prepareMobileDraft();
    if(topic==='mobile'&&!input.value.trim()){
      input.value='Хочу узнать о выходе VELIQ для телефона. Мой контакт для уведомления: ';
      fitInput();
    }
  }
  document.addEventListener('click',function(e){
    var a=e.target.closest&&e.target.closest('a[data-support-open]');
    if(!a||e.defaultPrevented||e.button!==0||e.ctrlKey||e.metaKey||e.shiftKey||e.altKey)return;
    e.preventDefault();openFromLink(a.getAttribute('data-support-topic'));
  });
  function openFromHash(){if(location.hash==='#chat'||location.hash==='#chat-mobile')openFromLink(location.hash==='#chat-mobile'?'mobile':'');}
  window.addEventListener('hashchange',openFromHash);
  if(location.hash==='#chat'||location.hash==='#chat-mobile'){
    opened=true;mobileDraftRequested=location.hash==='#chat-mobile';
    if(location.hash==='#chat-mobile'&&!input.value.trim()){
      input.value='Хочу узнать о выходе VELIQ для телефона. Мой контакт для уведомления: ';fitInput();
    }
  }

  panel.hidden=!opened;launcher.setAttribute('aria-expanded',String(opened));refresh();
})();
