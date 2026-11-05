/* VELIQ support. No message content or access credentials in browser storage. */
(function () {
  'use strict';
  if (document.getElementById('veliq-support')) return;
  var root = document.createElement('div'); root.id = 'veliq-support';
  root.innerHTML = '<button class="vs-launch" type="button" aria-expanded="false" aria-controls="vs-panel">Поддержка<span class="vs-badge" hidden> · новый ответ</span></button>' +
    '<section id="vs-panel" class="vs-panel" role="dialog" aria-modal="false" aria-labelledby="vs-title" hidden>' +
    '<header class="vs-head"><div><strong id="vs-title">Поддержка VELIQ</strong><p class="vs-status" role="status">Подключаемся…</p></div><button class="vs-close" type="button" aria-label="Закрыть диалог">×</button></header>' +
    '<div class="vs-intro">Опишите проблему — специалист ответит здесь. Не отправляйте пароли и коды входа. Переписка передаётся поддержке через Telegram. <a href="/privacy">Конфиденциальность</a></div>' +
    '<button class="vs-older" type="button" hidden>Предыдущие сообщения</button><div class="vs-messages" role="log" aria-label="Переписка" aria-live="polite" aria-relevant="additions"></div>' +
    '<p class="vs-error" role="alert" hidden></p>' +
    '<div class="vs-confirm" hidden><strong>Вопрос решён?</strong><p>Если нет — продолжим разбираться.</p><button type="button" data-answer="yes">Да, решён</button><button type="button" data-answer="no">Нет, нужна помощь</button><button type="button" data-answer="later">Свернуть, ответ прочитаю позже</button></div>' +
    '<form class="vs-form"><label for="vs-input">Ваше сообщение</label><textarea id="vs-input" maxlength="2000" rows="3" placeholder="Что произошло и что вы уже пробовали?" required></textarea><div class="vs-form-bottom"><span class="vs-count">0 / 2000</span><button type="submit">Отправить</button></div></form>' +
    '<div class="vs-resolved" hidden><p>Вопрос решён. Спасибо за обращение!</p><button type="button" class="vs-new">Новый вопрос</button></div>' +
    '<p class="vs-session">Диалог сохраняется в этом браузере на 30 дней. На общем ПК после окончания разговора нажмите «Завершить сессию».</p><button type="button" class="vs-forget">Завершить сессию поддержки</button></section>';
  document.body.appendChild(root);
  var q = function (s) { return root.querySelector(s); };
  var panel=q('.vs-panel'), launcher=q('.vs-launch'), input=q('textarea'), form=q('form'), list=q('.vs-messages');
  var state=null, busy=false, opened=false, pending=null, seen=0, timer=null, refreshing=false, creating=false, generation=0;
  try { opened=sessionStorage.getItem('veliq-support-open')==='1'; seen=Number(sessionStorage.getItem('veliq-support-seen')||0); } catch (_) {}
  function remember() { try { sessionStorage.setItem('veliq-support-open',opened?'1':'0'); sessionStorage.setItem('veliq-support-seen',String(seen)); } catch (_) {} }
  function error(message) { q('.vs-error').textContent=message||'';q('.vs-error').hidden=!message; }
  function key() { return Array.from(crypto.getRandomValues(new Uint8Array(32))).map(function(v){return v.toString(16).padStart(2,'0');}).join(''); }
  async function api(path, body) {
    var ctl=new AbortController(), timeout=setTimeout(function(){ctl.abort();},10000);
    try {
      var res=await fetch('/api/v1/support/'+path,{method:body?'POST':'GET',credentials:'same-origin',cache:'no-store',headers:body?{'Content-Type':'application/json'}:{},body:body?JSON.stringify(body):undefined,signal:ctl.signal});
      var data=await res.json();
      if (!res.ok) { var e=new Error(data.error||'unavailable');e.status=res.status;throw e; } return data;
    } finally { clearTimeout(timeout); }
  }
  function describe(e) {
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
  function render(next) {
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
    if(refreshing||busy)return;refreshing=true;var epoch=generation;
    try {var next=await api('state');if(epoch===generation&&!busy)render(next);}catch(_){q('.vs-status').textContent='Нет связи. Переписка сохранена на сервере.';}
    finally{refreshing=false;clearTimeout(timer);timer=setTimeout(refresh,document.hidden?30000:opened?4000:15000);}
  }
  launcher.addEventListener('click',function(){if(opened)close();else show(true);});
  function close(){if(busy)return;if(state&&state.ticket&&state.ticket.status!=='resolved'){q('.vs-confirm').hidden=false;q('[data-answer="no"]').focus();}else show(false);}
  q('.vs-close').addEventListener('click',close);
  root.addEventListener('keydown',function(e){if(e.key==='Escape'&&opened){e.preventDefault();close();}});
  q('[data-answer="no"]').addEventListener('click',function(){q('.vs-confirm').hidden=true;input.placeholder='Расскажите подробнее: что осталось нерешённым?';input.focus();});
  q('[data-answer="later"]').addEventListener('click',function(){q('.vs-confirm').hidden=true;show(false);});
  q('[data-answer="yes"]').addEventListener('click',async function(){
    if(busy||!state||!state.ticket)return;busy=true;generation++;error('');
    var revision=state.ticket.revision,id=state.ticket.id;
    try{await api('resolve',{key:key(),ticket:id,revision:revision});q('.vs-confirm').hidden=true;busy=false;await refresh();show(false);}
    catch(e){error(describe(e));busy=false;await refresh();}
  });
  input.addEventListener('input',function(){q('.vs-count').textContent=Array.from(input.value).length+' / 2000';});
  form.addEventListener('submit',async function(e){
    e.preventDefault();if(busy||!input.value.trim()||!state||!state.available)return;
    var body=input.value.trim(),ticket=state.ticket&&!creating?state.ticket.id:'';
    if(!pending||pending.body!==body)pending={key:key(),ticket:ticket,body:body};
    busy=true;generation++;input.disabled=true;q('[type=submit]').disabled=true;error('');
    try{if(!state.session){await api('session',{});state.session=true;}await api('message',pending);pending=null;input.value='';q('.vs-count').textContent='0 / 2000';creating=false;}
    catch(ex){error(describe(ex));if(ex.status===409)pending=null;}
    finally{busy=false;input.disabled=false;q('[type=submit]').disabled=false;await refresh();input.focus();}
  });
  q('.vs-new').addEventListener('click',function(){creating=true;q('.vs-resolved').hidden=true;form.hidden=false;input.focus();});
  q('.vs-older').addEventListener('click',async function(){
    var first=list.firstElementChild;if(!first||!state.ticket)return;
    try {var old=await api('state?ticket='+state.ticket.id+'&before='+first.dataset.message);append(old.messages,true);q('.vs-older').hidden=!old.has_more;}catch(e){error(describe(e));}
  });
  q('.vs-forget').addEventListener('click',async function(){
    if(busy)return;
    if(!window.confirm('Скрыть переписку на этом компьютере? Доступ к ней из этого браузера будет утрачен. Это не помечает вопрос решённым.'))return;
    try{generation++;await api('forget',{});state=null;pending=null;input.value='';list.replaceChildren();seen=0;remember();await refresh();}catch(e){error(describe(e));}
  });
  document.addEventListener('visibilitychange',function(){if(!document.hidden)refresh();});
  panel.hidden=!opened;launcher.setAttribute('aria-expanded',String(opened));refresh();
})();
