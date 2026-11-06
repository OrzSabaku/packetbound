import {network,route,ipValid,normalizeCommand} from './engine.mjs';
const escape=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const P={pc:[120,270],switch:[345,270],dns:[345,100],router:[570,270],archive:[800,150],neighbor:[800,350]};
const path=(...ids)=>ids.map(id=>P[id]);
const step=(title,detail,points,node,kind='normal')=>({title,detail,points,node,kind});
// These stages illustrate the training model; they are not packet captures.
export function journey(s,command,r){
 const c=normalizeCommand(command), stages=[];const local=(title,detail,kind='normal')=>stages.push(step(title,detail,path('pc'),'pc',kind));
 const changeNode=c.startsWith('service')?'archive':'pc';
 if(r.changed&&!c.startsWith('dhcp'))return [step('設定を変更',r.text,path(changeNode),changeNode,'changed')];
 if(c==='dhcp renew'){
  if(r.kind==='error')return[step('リンクを確認',r.text,path('pc'),'pc','error')];
  return [step('DISCOVER','端末が同一LANへDHCPサーバーを探索。ブロードキャストを代表経路で表示。',path('pc','switch','dns'),'dns'),step('OFFER','サーバーがIP・出口・DNSの候補を提示。',path('dns','switch','pc'),'pc'),step('REQUEST','提示された設定の利用を要求。',path('pc','switch','dns'),'dns'),step('ACK','貸与が確定。PCのIP・出口・DNS設定が更新されました。',path('dns','switch','pc'),'pc','success')];
 }
 const m=c.match(/^(ping(?: -t \d+)?|dig|traceroute|nc -vz|curl) (\S+)/);
 if(!m)return [step('状態を観測',r.text,path(changeNode),changeNode,r.kind==='error'?'error':'normal')];
 let host=m[2].replace(/^https?:\/\//,'').split('/')[0];
 const direct=m[1]==='dig';
 if(!s.link)return[step('端末で停止','eth0 が DOWN。信号はPCから出ていません。',path('pc'),'pc','error')];
 local('端末が送信を準備','旅人の端末が通信を開始します。');
 if(!ipValid(host)){
  if(!direct&&host==='archive.net'&&s.cache){local('キャッシュを参照',`PC内の古い記録: archive.net → ${s.cache}。DNSへ問い合わせません。`);host=s.cache;}
  else {
   if(s.dns!=='192.168.10.53'){local('DNS設定で停止','PCに正しいDNSサーバーが設定されていません。','error');return stages;}
   const dn=network(s,s.dns);
   if(dn.error){local('DNSへの通信で停止',dn.error,'error');return stages;}
   stages.push(step('DNS問い合わせ',`${host} のAレコードをDNSサーバーへ問い合わせ。スイッチはフレームを中継します。`,path('pc','switch','dns'),'dns'));
   if(!['archive.net','relay.net'].includes(host)){stages.push(step('DNS: NXDOMAIN','DNSサーバーが「登録なし」と応答。Webサーバーへはまだ接続していません。',path('dns','switch','pc'),'pc','error'));return stages;}
   host=host==='archive.net'?'10.20.0.80':'10.30.0.80';
   stages.push(step('DNS応答',`DNSが ${host} を返しました。${direct?'dig はこの応答を表示して終了。':'次はこのIPへ接続します。'}`,path('dns','switch','pc'),'pc',direct?'success':'normal'));
   if(direct)return stages;
  }
 }
 const n=network(s,host),chosen=route(s,host);
 if(!s.ip||!chosen){local('経路選択で停止',n.error||'送信元IPまたは経路がありません。','error');return stages;}
 local('宛先と経路を選択',`${host} → ${chosen.prefix}${chosen.via?' via '+chosen.via:'（同じLANと判断）'}`);
 if(s.arpBad){local('近隣表で停止','PCの固定ARPエントリーが誤っています。スイッチの故障ではありません。','error');return stages;}
 if(n.error){
  if(n.error.includes('ARP timeout'))stages.push(step('LANでARP応答待ち','遠隔ホストをLAN内に探しています。誰も返答せずタイムアウト。マスクを確認。',path('pc','switch'),'switch','error'));
  else if(chosen.via&&chosen.via!=='192.168.10.1')stages.push(step('誤った次ホップ','選ばれた '+chosen.via+' はこの構成のルーターではありません。LAN内で応答なし。',path('pc','switch'),'switch','error'));
  else if(host==='10.20.0.99')stages.push(step('古い宛先へ送信','ルーターの先の旧住所 10.20.0.99 には応答するホストがいません。図の書庫の住所と比べよう。',path('pc','switch','router'),'router','error'));
  else local('通信できない',n.error,'error');
  return stages;
 }
 const port=c.startsWith('curl')?(c.includes('https://')?443:80):c.startsWith('nc ')?Number(c.split(' ').at(-1)):null;
 if(port&&((port===443&&s.firewall)||s.blocked.includes(port))){local('端末の送信フィルターが遮断',`OUTBOUND TCP ${port}: DENY。DNS問い合わせが成功しても、このTCP接続はPCの外へ出ません。`,'error');return stages;}
 const dest=host==='192.168.10.1'?'router':host==='192.168.10.53'?'dns':host==='192.168.10.20'?'pc':host==='192.168.20.80'?'neighbor':'archive';
 const outbound=dest==='pc'?path('pc'):dest==='dns'?path('pc','switch','dns'):dest==='router'?path('pc','switch','router'):path('pc','switch','router',dest);
 if(r.events.includes('ttl-expired')){stages.push(step('TTLが0になり破棄','PCがTTL=1で送信。最初のルーターが減算し、転送を止めます。',path('pc','switch','router'),'router','error'));stages.push(step('ICMP Time Exceeded','ルーターから理由が返ります。ルーター自体の故障ではありません。',path('router','switch','pc'),'pc','error'));return stages;}
 if(c.startsWith('traceroute')){stages.push(step('ホップを調査','TTLを段階的に増やした問い合わせを、一つの代表経路にまとめて表示。',outbound,dest));stages.push(step('経路を表示',r.text,[...outbound].reverse(),'pc','success'));return stages;}
 stages.push(step(port?'TCP接続を要求':'ICMP Echo Request',port?`宛先 ${host}:${port} へ接続を要求。ルーターはIPに従って転送。`:`${host} へ到達性確認を送信。`,outbound,dest));
 if(port&&(port!==443||!s.service)){stages.push(step('接続を拒否','ホストまで届きましたが、対象ポートでサービスが待受していません。',outbound.slice(-1),dest,'error'));stages.push(step('TCP RST','宛先から拒否が返りました。パケットを破棄するタイムアウトとは異なります。',[...outbound].reverse(),'pc','error'));return stages;}
 if(port){stages.push(step('TCP接続が成立','SYN → SYN/ACK → ACK を代表往復で表示。TLS内部の処理は省略します。',[...outbound].reverse(),'pc'));if(c.startsWith('curl')){stages.push(step('HTTPSリクエスト',`書庫に ${c.split(host)[1]||'/'} の資源を要求。`,outbound,dest));}}
 const bad=r.events.includes('http404');stages.push(step(bad?'HTTP 404 応答':port?(c.startsWith('curl')?'HTTP 200 応答':'TCPポートの応答'):'ICMP Echo Reply',bad?'書庫は応答しました。存在しないパスが原因で、通信路は正常です。':r.text,[...outbound].reverse(),'pc',bad?'error':'success'));
 return stages;
}
const deviceNames={pc:'旅人の端末',switch:'LAN スイッチ',dns:'DNS / DHCP サーバー',router:'ゲートウェイ',archive:'書庫サーバー',neighbor:'隣国の端末'};
const monitor=`<path d="M-56-47h106v65H-56z" fill="#283e37" stroke="#8ea896" stroke-width="2"/><rect x="-48" y="-39" width="90" height="48" rx="2" fill="#102a25"/><path d="M-7 18v16m-20 0h40M-56 44l9-9h88l14 9z" stroke="#7b9583" fill="#2a3e33"/><path d="M-38-23l9 7-9 7m17 0h20" stroke="#c4e68d" stroke-width="3" fill="none"/><circle class="deviceLed" cx="40" cy="13" r="3"/>`;
const switchIcon=`<path d="M-58-12l15-16h97l10 16v37H-58z" fill="#2c4137" stroke="#89a68b" stroke-width="2"/><path d="M-58-12H64M48-12v37" fill="none" stroke="#657f6b"/>${Array.from({length:6},(_,i)=>`<rect x="${-48+i*15}" y="0" width="10" height="12" rx="1" fill="#101e18" stroke="#607b60"/><circle class="deviceLed" cx="${-43+i*15}" cy="-6" r="2"/>`).join('')}`;
const routerIcon=`<path d="M-52-22l15-13h75l16 13v51H-52z" fill="#334331" stroke="#a5b28a" stroke-width="2"/><path d="M-52-22H54M40-22v51" fill="none" stroke="#6f8158"/><path d="M-29 3h45m-12-8l12 8-12 8m-13-24h-25m9-6l-9 6 9 6" stroke="#c6d79a" fill="none" stroke-width="2"/><circle class="deviceLed" cx="-40" cy="21" r="3"/><rect x="23" y="14" width="11" height="7" fill="#111d12"/>`;
const rack=`<path d="M-39-58l16-12h58l10 12v112H-39z" fill="#283e3d" stroke="#87a8a1" stroke-width="2"/><path d="M-39-58H45M32-58v112" stroke="#547771" fill="none"/>${[-43,-14,15].map(y=>`<rect x="-30" y="${y}" width="54" height="22" rx="2" fill="#172b28" stroke="#5a7a6e"/><path d="M-22 ${y+7}h24m-24 7h24" stroke="#4c685e"/><circle class="deviceLed" cx="14" cy="${y+11}" r="3"/>`).join('')}`;
export function mountNetwork(container,{onCommand}){
 let support=false;
 let state=null,selected='pc',stages=[],index=0,progress=0,playing=false,raf=0,last=0,speed=1;
 const reduced=matchMedia('(prefers-reduced-motion: reduce)').matches;
 container.innerHTML=`<div class="liveHeading"><div><div class="eyebrow">LIVE NETWORK / 通信工房</div><h2>コマンドの向こうに、機器がある。</h2></div><span class="liveBadge">● 状態に連動</span></div><div class="sceneWrap"><svg class="networkScene" viewBox="0 0 920 470" aria-label="操作に連動するネットワーク機器の図"><defs><pattern id="workGrid" width="25" height="25" patternUnits="userSpaceOnUse"><path d="M25 0H0V25" stroke="#9cbf9b" stroke-opacity=".06" fill="none"/></pattern><radialGradient id="workLight"><stop stop-color="#344b39" stop-opacity=".5"/><stop offset="1" stop-color="#102019" stop-opacity="0"/></radialGradient></defs><rect width="920" height="470" fill="#111e19"/><rect width="920" height="470" fill="url(#workGrid)"/><ellipse cx="390" cy="245" rx="450" ry="260" fill="url(#workLight)"/><rect x="32" y="30" width="600" height="408" rx="18" fill="none" stroke="#4a6650" stroke-dasharray="5 8"/><text class="zoneLabel" x="50" y="53">LOCAL NETWORK · 192.168.10.0/24</text><text class="zoneLabel" x="686" y="38">REMOTE NETWORKS</text><path class="wire" data-wire="pc" d="M120 270H345"/><path class="wire" d="M345 270V100"/><path class="wire" d="M345 270H570"/><path class="wire" d="M570 270H675V150H800"/><path class="wire" d="M570 270H675V350H800"/><text class="wireLabel" x="213" y="253">Ethernet</text><text class="wireLabel" x="402" y="253">LAN</text><text class="wireLabel" x="678" y="261">ルーターの先</text><g id="liveDevices">${Object.entries(P).map(([id,[x,y]])=>`<g class="physicalDevice" data-device="${id}" role="button" tabindex="0" aria-label="${deviceNames[id]}の詳細" transform="translate(${x} ${y})"><title>${deviceNames[id]}：クリックして状態と調査コマンドを表示</title><ellipse cx="0" cy="46" rx="73" ry="19" fill="#07120e" opacity=".65"/><ellipse class="selectionHalo" cx="0" cy="15" rx="77" ry="62" fill="none" stroke="#c4e68d" stroke-width="1.5"/>${id==='pc'||id==='neighbor'?monitor:id==='switch'?switchIcon:id==='router'?routerIcon:rack}<rect class="deviceTag" x="-92" y="62" width="184" height="43" rx="5" fill="#14251d" stroke="#3d5b42"/><text x="0" y="79" text-anchor="middle" class="deviceName">${deviceNames[id]}</text><text x="0" y="96" text-anchor="middle" class="deviceAddress" data-address="${id}"></text></g>`).join('')}</g><g class="packetMarker" style="display:none"><circle r="14" fill="#c4e68d" opacity=".13"/><rect x="-6" y="-6" width="12" height="12" rx="3" fill="#d8f6ac" stroke="#f0ffdf"/><path d="M-4-3l4 4 4-4" fill="none" stroke="#304b23"/></g><g class="stopMarker" style="display:none"><circle r="13" fill="#492923" stroke="#efab8b"/><path d="M-4-4l8 8m0-8l-8 8" stroke="#efc3a7" stroke-width="2"/></g></svg><div class="sceneLegend"><span><i></i>機器の稼働状態</span><span>✉ 移動する通信</span><span>× 今回止まった処理</span><span>図解用モデル・実パケットではありません</span></div></div><div class="transport"><button data-control="play" aria-label="通信アニメーションを再生・一時停止">▶ 再生</button><button data-control="next" aria-label="通信の次の段階へ">1段階進む →</button><button data-control="replay" aria-label="直近の通信をもう一度見る">↺ 最初から</button><label>速度 <select aria-label="通信アニメーションの速度"><option value="0.6">ゆっくり</option><option value="1" selected>標準</option><option value="2">速い</option></select></label><span class="stageCounter"></span></div><div class="liveNarration" role="status"><strong>まず機器を選んでみよう。</strong><p>PCの画面、サーバーのランプ、配線は設定に連動します。端末から ping や curl を実行すると通信が動きます。</p></div><div class="stageRail" aria-label="通信の各段階"></div><div class="inspector"></div>`;
 const find=s=>container.querySelector(s);
 const commandForm=document.querySelector('#commandForm');find('.liveHeading').after(commandForm);
 function inspector(){if(!state)return;const s=state;const content={
 pc:{tag:'CLIENT / 操作している機器',role:'コマンドを実行しているPC。IP・経路表・DNSキャッシュ・送信規則はこの機器の設定です。',values:[['eth0',s.link?'UP / 有効':'DOWN / 停止'],['IPv4',s.ip||'未設定'],['出口',s.gateway||'未設定'],['DNS',s.dns||'未設定'],['ARP',s.arpBad?'誤った固定MACあり':'正しい近隣を解決'],['TCP 443',s.firewall?'送信を拒否':'送信を許可']],commands:['ip link','ip addr','ip route','resolvectl show-cache','sudo iptables -S OUTPUT']},
 switch:{tag:'LAYER 2 / フレームを中継',role:'同じLANの機器を有線でつなぎます。MACアドレスに基づいて中継する機器で、デフォルトゲートウェイとは別の役割です。この演習では正常稼働・設定変更対象外です。',values:[['電源','ON'],['PC側ポート',s.link?'リンクあり':'リンクなし'],['接続先','PC・DNS/DHCP・ルーター']],commands:['ip link','ip neigh']},
 dns:{tag:'SERVER / 名前と設定を配る',role:'DNSは名前からIPを返し、DHCPは端末設定を配布します。この機体で両サービスが動く構成です。Webデータを代理取得する機器ではありません。',values:[['IP','192.168.10.53'],['DNSの登録','archive.net → 10.20.0.80'],['DHCPの配布','192.168.10.20/24'],['電源','ON / サービス稼働']],commands:['dig archive.net','resolvectl status eth0','sudo dhclient -v eth0']},
 router:{tag:'LAYER 3 / ネットワークの境界',role:'別のネットワークへIPパケットを転送する機器。端末のデフォルトゲートウェイは、このルーターのLAN側IPです。上流と戻り経路は設定済みです。',values:[['LAN側IP','192.168.10.1'],['正しいMAC','02:00:00:00:10:01'],['端末の出口設定',s.gateway||'未設定'],['電源','ON / 転送可能']],commands:['ip route','ip route get 10.20.0.80','traceroute 10.20.0.80']},
 archive:{tag:'REMOTE SERVER / 書庫の実体',role:'ルーターの先にあるWebサーバー。機体の電源はONでも、HTTPSのプログラムが停止するとTCP 443を受け付けられません。service操作はこのサーバーが対象です。',values:[['IP','10.20.0.80'],['ホスト名','archive.net'],['電源','ON'],['HTTPS',s.service?'RUNNING / TCP 443':'STOPPED / 待受なし'],['稼働確認パス','/health']],commands:['service status','nc -vz archive.net 443','curl https://archive.net/health']},
 neighbor:{tag:'REMOTE HOST / 隣国の端末',role:'192.168.20.0/24にある別ネットワークの端末。192.168で始まっていても、旅人のLAN内とは限りません。CIDRのクエストで調べる相手です。',values:[['IP','192.168.20.80'],['経路','ゲートウェイの先'],['電源','ON']],commands:['ip route get 192.168.20.80','ping 192.168.20.80']}
 }[selected];find('.inspector').innerHTML=`<div class="inspectorTitle"><div class="eyebrow">${content.tag}</div><h3>${deviceNames[selected]}</h3></div><p>${support?content.role:'機器と配線は設計台帳です。稼働状態は端末で観測してください。機構の解説は右側のボタンで開けます。'}</p><dl>${(support?content.values:[]).map(([k,v])=>`<div><dt>${escape(k)}</dt><dd>${escape(v)}</dd></div>`).join('')}</dl><div class="inspectCommands"><small>この機器を調べる・操作する（クリックで端末に入力）</small>${(support?content.commands:[]).map(c=>`<button data-live-command="${escape(c)}">${escape(c)}</button>`).join('')}</div>`;
 container.querySelectorAll('[data-live-command]').forEach(b=>b.onclick=()=>onCommand(b.dataset.liveCommand));container.querySelectorAll('[data-device]').forEach(el=>el.classList.toggle('selected',el.dataset.device===selected));
 }
 function paint(){if(!state)return;const s=state;const addr={pc:support?(s.ip||'IP未設定'):'旅人の端末 / 状態未表示',switch:'6 PORTS / L2',dns:'192.168.10.53',router:'192.168.10.1',archive:support?(s.service?'10.20.0.80 :443':'10.20.0.80 / HTTPS停止'):'設計IP 10.20.0.80',neighbor:'192.168.20.80'};for(const id of Object.keys(P)){find(`[data-address="${id}"]`).textContent=addr[id];const el=find(`[data-device="${id}"]`);el.classList.toggle('offline',support&&id==='pc'&&!s.link);el.classList.toggle('serviceStopped',support&&id==='archive'&&!s.service)}find('[data-wire="pc"]').classList.toggle('disconnected',support&&!s.link);inspector()}
 function choose(id){selected=id;inspector()}
 container.querySelectorAll('[data-device]').forEach(el=>{el.onclick=()=>choose(el.dataset.device);el.onkeydown=e=>{if(['Enter',' '].includes(e.key)){e.preventDefault();choose(el.dataset.device)}}});
 function stop(){playing=false;cancelAnimationFrame(raf);find('[data-control="play"]').textContent='▶ 再生'}
 function pointAt(points,t){if(points.length===1)return points[0];const segments=points.slice(1).map((p,i)=>Math.hypot(p[0]-points[i][0],p[1]-points[i][1]));const total=segments.reduce((a,b)=>a+b,0);let distance=total*t;for(let i=0;i<segments.length;i++){if(distance<=segments[i]||i===segments.length-1){const f=segments[i]?distance/segments[i]:0;return [points[i][0]+(points[i+1][0]-points[i][0])*f,points[i][1]+(points[i+1][1]-points[i][1])*f]}distance-=segments[i]}return points.at(-1)}
 // Match the bent remote wires rather than flying diagonally between devices.
 function bent(points){let p=[];for(let i=0;i<points.length;i++){p.push(points[i]);const a=points[i],b=points[i+1];if(!b)continue;if(a===P.router&&(b===P.archive||b===P.neighbor))p.push([675,a[1]],[675,b[1]]);if((a===P.archive||a===P.neighbor)&&b===P.router)p.push([675,a[1]],[675,b[1]])}return p}
 function drawMarker(){const st=stages[index];if(!st)return;const [x,y]=pointAt(bent(st.points),progress);const marker=find('.packetMarker');marker.style.display='';marker.setAttribute('transform',`translate(${x} ${y})`);marker.classList.toggle('error',st.kind==='error');const cross=find('.stopMarker');cross.style.display=st.kind==='error'&&progress>=1?'':'none';cross.setAttribute('transform',`translate(${x} ${y})`)}
 function announce(){const st=stages[index];if(!st)return;find('.liveNarration').className='liveNarration '+st.kind;find('.liveNarration strong').textContent=st.title;find('.liveNarration p').textContent=st.detail;find('.stageCounter').textContent=`${index+1} / ${stages.length}`;container.querySelectorAll('[data-stage]').forEach(b=>b.classList.toggle('current',+b.dataset.stage===index));container.querySelectorAll('[data-device]').forEach(el=>el.classList.toggle('receiving',el.dataset.device===st.node));drawMarker()}
 function tick(now){if(!playing)return;if(!last)last=now;progress=Math.min(1,progress+(now-last)*speed/1800);last=now;drawMarker();if(progress>=1){if(index<stages.length-1){index++;progress=0;announce()}else{stop();return}}raf=requestAnimationFrame(tick)}
 function play(){if(!stages.length)return;if(index===stages.length-1&&progress>=1){index=0;progress=0;announce()}playing=true;last=0;find('[data-control="play"]').textContent='Ⅱ 一時停止';raf=requestAnimationFrame(tick)}
 function show(st){stop();stages=st;index=0;progress=0;find('.stageRail').innerHTML=stages.map((v,i)=>`<button data-stage="${i}">${i+1}. ${escape(v.title)}</button>`).join('');container.querySelectorAll('[data-stage]').forEach(b=>b.onclick=()=>{stop();index=+b.dataset.stage;progress=1;announce()});announce();if(!reduced)play();else{progress=1;drawMarker()}}
 find('[data-control="play"]').onclick=()=>playing?stop():play();find('[data-control="replay"]').onclick=()=>{stop();index=0;progress=0;announce();play()};find('[data-control="next"]').onclick=()=>{stop();if(!stages.length)return;index=Math.min(index+1,stages.length-1);progress=1;announce()};find('select').onchange=e=>speed=Number(e.target.value);
 return {setSupport(value){support=value;container.classList.toggle('investigating',!value);find('.liveBadge').textContent=value?'● 状態に連動':'設計台帳 / 内部状態は未表示';find('.sceneLegend').textContent=value?'機器の稼働状態 · 移動する通信 · 図解用モデル（実パケットではありません）':'配線と設計情報のみ表示。コマンドの結果は端末で確認できます。';if(!value)stop();paint()},update(s){state=cloneState(s);paint()},command(s,c,r){state=cloneState(s);paint();show(journey(s,c,r))},reset(s){stop();state=cloneState(s);stages=[];index=0;progress=0;paint();find('.packetMarker').style.display='none';find('.stopMarker').style.display='none';find('.stageRail').innerHTML='';find('.stageCounter').textContent='';find('.liveNarration').className='liveNarration';find('.liveNarration strong').textContent='機器を選んで、調査を始めよう。';find('.liveNarration p').textContent='PCやサーバーをクリックすると、その役割・現在の設定・使えるコマンドが表示されます。';container.querySelectorAll('.receiving').forEach(el=>el.classList.remove('receiving'))},pause:stop};
}
function cloneState(s){return JSON.parse(JSON.stringify(s))}
