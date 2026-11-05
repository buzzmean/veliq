/* Coordinate account transitions before any old chat or draft can be reused.
   Account authority remains exclusively in the support HTTP service. */
(function () {
  'use strict';
  if(window.veliqSupportAuthChanged)return;
  var nativeFetch=window.fetch.bind(window), channel=null, active=0, sender=String(Math.random()), sequence=0, received={};
  try{channel=new BroadcastChannel('veliq-account-transition');}catch(_){}
  function notify(pending,remote){
    window.dispatchEvent(new CustomEvent('veliq:account-transition',{detail:{pending:pending}}));
    if(!remote){
      var event={pending:pending,sender:sender,sequence:++sequence};
      if(channel)channel.postMessage(event);
      try{localStorage.setItem('veliq-account-transition',JSON.stringify(event));localStorage.removeItem('veliq-account-transition');}catch(_){}
    }
  }
  function receive(data){
    if(!data||typeof data.sender!=='string'||!Number.isSafeInteger(data.sequence)||data.sequence<=(received[data.sender]||0))return;
    received[data.sender]=data.sequence;notify(!!data.pending,true);
  }
  if(channel)channel.onmessage=function(e){receive(e.data);};
  window.addEventListener('storage',function(e){
    if(e.key!=='veliq-account-transition'||!e.newValue)return;
    try{receive(JSON.parse(e.newValue));}catch(_){}
  });
  window.veliqSupportAuthChanged=function(){notify(false,false);};
  window.fetch=async function(input,init){
    var url,method;
    try{url=new URL(typeof input==='string'||input instanceof URL?input:input.url,location.href);method=String(init&&init.method||input.method||'GET').toUpperCase();}catch(_){return nativeFetch(input,init);}
    var transition=url.origin===location.origin&&method==='POST'&&
      (url.pathname==='/api/v1/account/logout'||url.pathname==='/api/v1/account/login/verify');
    if(!transition)return nativeFetch(input,init);
    active++;notify(true,false);
    try{
      // A guest conversation has no proven account owner. End guest access
      // before login; never attach it to the newly authenticated account.
      if(url.pathname.endsWith('/login/verify')){
        try {
        var st=await nativeFetch('/api/v1/account/support/state',{credentials:'same-origin',cache:'no-store'});
        if(st.ok){
          var data=await st.json();
          if(data.identity==='guest'&&data.session){
            var forgotten=await nativeFetch('/api/v1/account/support/forget',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-Support-Context':data.context},body:'{}'});
            if(!forgotten.ok)throw new Error('support_session_not_detached');
          }
        }
        } catch(_) { /* Account nginx also expires the guest cookie; login stays independent of support availability. */ }
      }
      return await nativeFetch(input,init);
    }finally{active--;notify(active>0,false);}
  };
})();
