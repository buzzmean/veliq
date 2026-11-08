/* Club applications use the existing durable support queue. No contact data in browser storage. */
(function (scope) {
  'use strict';
  var channels={telegram:'Telegram',phone:'Телефон',email:'Email'};
  function text(value,max,required,multiline){
    var s=String(value||'').trim().replace(multiline?/\r\n?/g:/[\r\n\t]+/g,multiline?'\n':' ');
    if((required&&!s)||Array.from(s).length>max||/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(s))throw new Error('Проверьте обязательные поля и длину текста.');return s;
  }
  function build(data,key){
    var club=text(data.club,80,true),city=text(data.city,80,true),name=text(data.name,80,true),contact=text(data.contact,120,true),management=text(data.management,100,true);
    if(!/^[1-9]\d{0,3}$/.test(String(data.pcs))||Number(data.pcs)>2000)throw new Error('Укажите количество ПК от 1 до 2000.');
    if(!channels[data.channel])throw new Error('Выберите способ связи.');
    if(data.channel==='telegram'&&!/^@?[a-zA-Z][a-zA-Z0-9_]{4,31}$/.test(contact))throw new Error('Укажите Telegram в формате @username, от 5 до 32 символов.');
    if(data.channel==='email'&&!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contact))throw new Error('Проверьте адрес электронной почты.');
    if(data.channel==='phone'&&(!/^\+?[\d ()-]+$/.test(contact)||contact.replace(/\D/g,'').length<7||contact.replace(/\D/g,'').length>15))throw new Error('Укажите телефон с кодом страны или города.');
    if(!data.consent)throw new Error('Подтвердите согласие на обработку заявки.');
    var reference='CL-'+key.slice(0,12).toUpperCase();
    var body=['НОВАЯ ЗАЯВКА НА ПОДКЛЮЧЕНИЕ КЛУБА',reference,'','Клуб: '+club,'Город: '+city,'Количество ПК: '+data.pcs,'Система управления: '+management,'Windows: '+text(data.installation,60,false),'Контактное лицо: '+name,'Роль: '+text(data.role,60,false),channels[data.channel]+': '+contact,'Удобное время: '+(text(data.time,100,false)||'не указано'),'','Задача: '+(text(data.comment,600,false,true)||'не указана'),'','Источник: veliqapp.ru/clubs#apply','Согласие на обработку заявки: подтверждено'].join('\n');
    if(Array.from(body).length>2000)throw new Error('Сократите описание заявки.');return {body:body,reference:reference};
  }
  function client(fetcher){
    var pending=null,sessionReady=false;
    async function api(path,body){
      var ctl=new AbortController(),timeout=setTimeout(function(){ctl.abort();},12000);
      try{var r=await fetcher('/api/v1/support/'+path,{method:body?'POST':'GET',credentials:'same-origin',cache:'no-store',headers:body?{'Content-Type':'application/json'}:{},body:body?JSON.stringify(body):undefined,signal:ctl.signal});var d=await r.json();if(!r.ok){var e=new Error(d.error||'unavailable');e.status=r.status;throw e;}return d;}finally{clearTimeout(timeout);}
    }
    return {send:async function(application,key){
      if(pending&&pending.body!==application.body)throw new Error('Повторите неподтверждённую отправку перед изменением заявки.');
      if(!sessionReady){await api('session',{});sessionReady=true;}
      if(!pending){var state=await api('state');if(!state.available)throw new Error('support_not_connected');pending={key:key,body:application.body,ticket:state.ticket&&state.ticket.status!=='resolved'?state.ticket.id:''};}
      try{var result=await api('message',pending);if(!/^[a-f0-9]{64}$/.test(result.ticket||''))throw new Error('invalid_receipt');pending=null;return result;}catch(e){if(e.status===409)pending=null;throw e;}
    }};
  }
  if(typeof module!=='undefined'&&module.exports)module.exports={build:build,client:client};
  if(!scope.document)return;
  var form=document.getElementById('club-application');if(!form)return;
  var error=document.getElementById('club-application-error'),success=document.getElementById('club-application-success'),button=form.querySelector('[type=submit]'),busy=false,pending=null,transport=client(scope.fetch.bind(scope));
  function contactUI(){var channel=form.elements.channel.value,input=form.elements.contact,label=document.getElementById('club-contact-label');input.type=channel==='email'?'email':channel==='phone'?'tel':'text';input.autocomplete=channel==='email'?'email':channel==='phone'?'tel':'off';input.placeholder=channel==='email'?'name@company.ru':channel==='phone'?'+7 999 123-45-67':'@username';label.textContent=(channel==='telegram'?'Имя в Telegram':channel==='phone'?'Телефон':'Электронная почта')+' *';document.getElementById('club-contact-hint').textContent=channel==='telegram'?'Проверьте, что вам можно написать.':'Используем только для связи по заявке.';}
  form.elements.channel.addEventListener('change',contactUI);contactUI();
  function lock(value){Array.from(form.elements).forEach(function(el){if(el!==button)el.disabled=value;});}
  form.addEventListener('submit',async function(e){
    e.preventDefault();if(busy)return;error.hidden=true;
    if(!pending){try{var data=Object.fromEntries(new FormData(form));var key=Array.from(crypto.getRandomValues(new Uint8Array(32))).map(function(n){return n.toString(16).padStart(2,'0');}).join('');pending={application:build(data,key),key:key};}catch(ex){error.textContent=ex.message;error.hidden=false;return;}}
    busy=true;lock(true);button.disabled=true;button.textContent='Отправляем…';form.setAttribute('aria-busy','true');
    try{await transport.send(pending.application,pending.key);success.querySelector('[data-application-reference]').textContent=pending.application.reference;form.reset();form.hidden=true;success.hidden=false;success.focus();pending=null;}
    catch(ex){error.hidden=false;error.textContent=ex.status===429?'Слишком много запросов. Подождите минуту и повторите отправку.':ex.status===401?'Сессия завершилась. Откройте поддержку для проверки отправки, затем обновите страницу.':ex.status===409?'Диалог изменился. Нажмите «Повторить отправку» — заявку направим в актуальный диалог.':ex.message==='support_not_connected'?'Поддержка временно недоступна. Данные остались в форме, попробуйте позже.':'Не удалось подтвердить отправку. Данные остались в форме. Нажмите «Повторить отправку»: повтор не создаст дубль. Не обновляйте страницу до подтверждения.';button.textContent='Повторить отправку';}
    finally{busy=false;button.disabled=false;form.removeAttribute('aria-busy');}
  });
  success.querySelector('[data-application-chat]').addEventListener('click',function(){var launch=document.querySelector('#veliq-support .vs-launch');if(launch){if(launch.getAttribute('aria-expanded')!=='true')launch.click();}else{var msg=success.querySelector('[data-chat-error]');msg.textContent='Чат ещё загружается. Повторите через несколько секунд или откройте страницу помощи.';msg.hidden=false;}});
})(typeof window==='undefined'?{}:window);
