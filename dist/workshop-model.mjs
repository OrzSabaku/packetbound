// Explicit teaching models: no shell, packets, network or cloud I/O.
export const clone = value => JSON.parse(JSON.stringify(value));
export const NODES = [
  {id:'client',name:'旅人の端末',type:'client',x:70,y:200},
  {id:'swA',name:'西のスイッチ',type:'switch',x:250,y:100},
  {id:'swB',name:'東のスイッチ',type:'switch',x:250,y:300},
  {id:'gwA',name:'関所 A',type:'router',x:450,y:100},
  {id:'gwB',name:'関所 B',type:'router',x:450,y:300},
  {id:'srvA',name:'書庫 A',type:'server',x:650,y:100},
  {id:'srvB',name:'書庫 B',type:'server',x:650,y:300}
];
export const PAIRS = [['client','swA'],['client','swB'],['swA','gwA'],['swA','gwB'],['swB','gwA'],['swB','gwB'],['gwA','srvA'],['gwA','srvB'],['gwB','srvA'],['gwB','srvB']];
export function newDesign(){return {links:PAIRS.map(([a,b],i)=>({a,b,on:[0,2,6].includes(i),capacity:100})),domains:{swA:'west',gwA:'west',srvA:'west',swB:'west',gwB:'west',srvB:'west'},servers:1,serverCapacity:100,https:true,ssh:true,db:true,vpn:false,privateRoute:false};}
// Undirected link capacities, aggregate service capacity. No transport latency model.
export function capacity(d,failed=[]){
 const active=new Set(NODES.filter(n=>!failed.includes(n.id)&&(n.id!=='srvB'||d.servers===2)).map(n=>n.id));
 if(!active.has('client'))return 0;
 const residual={};const edge=(a,b,c)=>{residual[a]??={};residual[b]??={};residual[a][b]=(residual[a][b]||0)+c;residual[b][a]??=0;};
 d.links.filter(l=>l.on&&active.has(l.a)&&active.has(l.b)).forEach(l=>{edge(l.a,l.b,l.capacity);edge(l.b,l.a,l.capacity)});
 for(const id of ['srvA','srvB'])if(active.has(id))edge(id,'sink',d.serverCapacity);
 let flow=0;
 while(true){const prev={client:null},queue=['client'];while(queue.length&&!Object.hasOwn(prev,'sink')){const a=queue.shift();for(const [b,c] of Object.entries(residual[a]||{}))if(c>0&&!Object.hasOwn(prev,b)){prev[b]=a;queue.push(b)}}if(!Object.hasOwn(prev,'sink'))break;
 let amount=Infinity;for(let b='sink';prev[b]!==null;b=prev[b])amount=Math.min(amount,residual[prev[b]][b]);for(let b='sink';prev[b]!==null;b=prev[b]){residual[prev[b]][b]-=amount;residual[b][prev[b]]+=amount}flow+=amount;}
 return flow;
}
export const cost=d=>d.links.filter(l=>l.on).reduce((n,l)=>n+l.capacity/100,0)+d.servers*(d.serverCapacity/100+2);
export function designTests(d,kind){
 if(kind==='ha')return [{label:'通常時に書庫へ到達',pass:capacity(d)>0},...NODES.filter(n=>n.id!=='client'&&(n.id!=='srvB'||d.servers===2)).map(n=>({label:n.name+' 停止中も到達',pass:capacity(d,[n.id])>0})),...['west','east'].map(zone=>({label:(zone==='west'?'西':'東')+'電源系統の停止中も到達',pass:capacity(d,Object.keys(d.domains).filter(id=>d.domains[id]===zone))>0}))];
 if(kind==='security')return [{label:'外部 → HTTPS を許可',pass:d.https&&capacity(d)>0},{label:'外部 → SSH を拒否',pass:!d.ssh},{label:'外部 → DB を拒否',pass:!d.db},{label:'支店 → 私設網をVPN経由で接続',pass:d.vpn&&d.privateRoute&&capacity(d)>0}];
 return [{label:'通常負荷 100 Mbps を処理',pass:capacity(d)>=100},{label:'増加負荷 300 Mbps を処理',pass:capacity(d)>=300},{label:'書庫 A 停止時も 150 Mbps を処理',pass:capacity(d,['srvA'])>=150},{label:'予算 28 単位以下',pass:cost(d)<=28}];
}
export function capture(variant='drop'){
 const p=(no,time,src,dst,protocol,info,port)=>({no,time,src,dst,protocol,info,port});
 const rows=[p(1,0,'192.168.10.20','192.168.10.53','DNS','A? archive.net',53),p(2,.004,'192.168.10.53','192.168.10.20','DNS','A 10.20.0.80',53),p(3,.009,'192.168.10.20','10.20.0.80','TCP','49152 → 443 [SYN] Seq=0',443)];
 if(variant==='drop')rows.push(p(4,1.009,'192.168.10.20','10.20.0.80','TCP','49152 → 443 [SYN] Seq=0 retransmission',443),p(5,3.009,'192.168.10.20','10.20.0.80','TCP','49152 → 443 [SYN] Seq=0 retransmission',443));
 if(variant==='refuse')rows.push(p(4,.015,'10.20.0.80','192.168.10.20','TCP','443 → 49152 [RST, ACK] Ack=1',443));
 if(variant==='ok')rows.push(p(4,.015,'10.20.0.80','192.168.10.20','TCP','443 → 49152 [SYN, ACK] Seq=0 Ack=1',443),p(5,.016,'192.168.10.20','10.20.0.80','TCP','49152 → 443 [ACK] Seq=1 Ack=1',443),p(6,.02,'192.168.10.20','10.20.0.80','TLS','Application Data (encrypted)',443));
 return rows;
}
export function filterCapture(command,rows){
 const match=command.trim().match(/^tcpdump -nn -r incident\.pcap(?: (.+))?$/);
 if(!match)throw Error('対応構文: tcpdump -nn -r incident.pcap [tcp | port 443 | host 10.20.0.80 | tcp and port 443]');
 const filter=(match[1]||'').replace(/^['"]|['"]$/g,'');
 const predicates={'':()=>true,tcp:r=>r.protocol==='TCP'||r.protocol==='TLS','port 443':r=>r.port===443,'port 53':r=>r.port===53,'host 10.20.0.80':r=>r.src==='10.20.0.80'||r.dst==='10.20.0.80','tcp and port 443':r=>r.port===443&&(r.protocol==='TCP'||r.protocol==='TLS')};
 if(!predicates[filter])throw Error('この演習で未対応のフィルターです。対応構文を参照してください。');
 return rows.filter(predicates[filter]);
}
export const TEMPLATES={
 netplan:`network:
  version: 2
  ethernets:
    eth0:
      addresses: [192.168.99.20/24]
      routes:
        - to: default
          via: 192.168.10.254
      nameservers:
        addresses: [192.168.10.53]
`,
 ansible:`- hosts: web
  become: true
  tasks:
    - name: Keep HTTPS service running
      ansible.builtin.service:
        name: nginx
        state: stopped
        enabled: false
`,
 terraform:`resource "aws_subnet" "west" {
  vpc_id = "vpc-training"
  cidr_block = "10.20.1.0/24"
  availability_zone = "ap-northeast-1a"
}
resource "aws_subnet" "east" {
  vpc_id = "vpc-training"
  cidr_block = "10.20.2.0/24"
  availability_zone = "ap-northeast-1a"
}
`};
// Deliberately strict grammars: never silently accept unsupported YAML/HCL.
export function parseConfig(kind,text){
 const clean=text.replace(/\r/g,'').replace(/^\s*#.*\n/gm,'').trim();
 if(kind==='netplan'){
 const m=clean.match(/^network:\s*\n  version: 2\s*\n  ethernets:\s*\n    eth0:\s*\n      addresses: \[([\d.]+\/\d+)\]\s*\n      routes:\s*\n        - to: default\s*\n          via: ([\d.]+)\s*\n      nameservers:\s*\n        addresses: \[([\d.]+)\]$/);
 if(!m)throw Error('対応するNetplanテンプレートの構造・インデントを確認してください。addresses、via、DNSのみ編集できます。');
 const ip=s=>s.split('.').length===4&&s.split('.').every(v=>/^\d{1,3}$/.test(v)&&+v<=255);
 if(!ip(m[1].split('/')[0])||+m[1].split('/')[1]>32||!ip(m[2])||!ip(m[3]))throw Error('不正なIPv4アドレスまたはプレフィックスです。');
 return {address:m[1],gateway:m[2],dns:m[3]};
 }
 if(kind==='ansible'){
 const m=clean.match(/^- hosts: web\s*\n  become: true\s*\n  tasks:\s*\n    - name: [^\n]+\n      ansible\.builtin\.service:\s*\n        name: nginx\s*\n        state: (started|stopped)\s*\n        enabled: (true|false)$/);
 if(!m)throw Error('対応範囲: webグループのnginxサービス、state: started/stopped、enabled: true/false。テンプレート構造を保ってください。');
 return {running:m[1]==='started',enabled:m[2]==='true'};
 }
 const matches=[...clean.matchAll(/resource "aws_subnet" "(\w+)" \{\s*vpc_id = "vpc-training"\s*cidr_block = "(10\.20\.\d+\.0\/24)"\s*availability_zone = "(ap-northeast-1[acd])"\s*\}/g)];
 if(matches.length!==2||clean.replace(/resource "aws_subnet" "(\w+)" \{\s*vpc_id = "vpc-training"\s*cidr_block = "(10\.20\.\d+\.0\/24)"\s*availability_zone = "(ap-northeast-1[acd])"\s*\}/g,'').trim())throw Error('対応範囲: テンプレートと同じ形式のaws_subnetを2個。CIDRとAZを編集できます。');
 if(new Set(matches.map(m=>m[1])).size!==2||new Set(matches.map(m=>m[2])).size!==2||matches.some(m=>+m[2].split('.')[2]>255))throw Error('リソース名・CIDRは重複できません。CIDRを確認してください。');
 return Object.fromEntries(matches.map(m=>[m[1],{cidr:m[2],zone:m[3]}]));
}
export function newIac(kind){return {kind,text:TEMPLATES[kind],actual:kind==='ansible'?{a:{running:false,enabled:false},b:{running:false,enabled:false}}:{},revision:0,plan:null,trial:null,checked:false,applies:0,idempotent:false,driftSeen:false,repaired:false,verified:false};}
export function iacRun(s,command){
 const c=command.trim().replace(/^sudo /,'');
 const readOnlyOrSaved=['terraform apply tfplan','terraform state list','netplan status'].includes(c);
 const desired=readOnlyOrSaved?null:parseConfig(s.kind,s.text);
 const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);const diff=()=>JSON.stringify({before:s.actual,after:s.kind==='ansible'?{a:desired,b:desired}:desired},null,2);
 if(s.kind==='netplan'){
  if(c==='netplan generate'){s.checked=true;s.checkedText=s.text;return '構文検証成功。設定はまだ変更していません。'}
  if(c==='netplan try'){if(s.trial===null)s.trial=clone(s.actual);s.actual=desired;s.revision++;s.verified=false;return '試験適用。接続を検証し「確定」または「取消」を選んでください。実機の120秒タイムアウトは手動取消で模擬します。'}
  if(c==='netplan status')return JSON.stringify(s.actual,null,2);
 }
 if(s.kind==='ansible'){
  if(c==='ansible-playbook -i inventory.ini site.yml --check --diff'){s.checked=true;s.checkedText=s.text;return diff()+'\nCHECK MODE: 実際の設定は未変更';}
  if(c==='ansible-playbook -i inventory.ini site.yml'){
   const changed=Object.values(s.actual).filter(a=>!same(a,desired)).length;s.actual={a:clone(desired),b:clone(desired)};s.applies++;s.idempotent=changed===0&&s.applies>=2;s.verified=false;s.revision++;return `PLAY RECAP — web-a, web-b\nhosts=2 changed=${changed} failed=0`;
  }
 }
 if(s.kind==='terraform'){
  if(c==='terraform plan -out=tfplan'){s.plan={desired:clone(desired),revision:s.revision};if(s.driftInjected&&!same(s.actual,desired)&&s.applies>0)s.driftSeen=true;return diff()+'\nPlan saved: tfplan';}
  if(c==='terraform apply tfplan'){
   if(!s.plan)throw Error('先に terraform plan -out=tfplan を実行してください。');
   if(s.plan.revision!==s.revision)throw Error('計画後に環境が変わりました。再計画してください。');
   s.actual=clone(s.plan.desired);s.plan=null;s.applies++;s.revision++;s.repaired=s.driftSeen;s.verified=false;return 'Apply complete. 模擬サブネットの状態を更新しました。';
  }
  if(c==='terraform state list')return Object.keys(s.actual).map(k=>'aws_subnet.'+k).join('\n')||'(empty)';
 }
 throw Error('未対応のコマンドです。「構文リファレンス」を確認してください。');
}
export function iacValid(s){
 let desired;try{desired=parseConfig(s.kind,s.text)}catch{return false}
 const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 if(s.kind!=='ansible'&&!same(s.actual,desired))return false;
 if(s.kind==='ansible'&&!Object.values(s.actual).every(a=>same(a,desired)))return false;
 if(s.kind==='netplan')return s.actual.address==='192.168.10.20/24'&&s.actual.gateway==='192.168.10.1'&&s.actual.dns==='192.168.10.53'&&s.trial===null&&s.checked&&s.checkedText===s.text;
 if(s.kind==='ansible')return Object.values(s.actual).length===2&&Object.values(s.actual).every(v=>v.running&&v.enabled)&&s.checked&&s.checkedText===s.text&&s.idempotent;
 const resources=Object.values(s.actual);return resources.length===2&&new Set(resources.map(v=>v.zone)).size===2&&s.repaired;
}
export const CONCEPTS=[
 {question:'digは成功、TCPのSYNには応答がない。観測だけから言えることは？',choices:['Webアプリは正常','名前解決に成功したが、TCP接続成立は確認できない','必ずDNSキャッシュが壊れている'],answer:1,explain:'DNSとTCPは異なる段階。無応答だけで破棄した機器を断定することはできません。'},
 {question:'IP宛てのpingは成功した。次にHTTPSが使えると予測できる？',choices:['できる。ICMPは全ポートを検証する','できない。TCP・TLS・HTTPは別途検証する','DNSだけ調べれば十分'],answer:1,explain:'ICMP到達性の証拠はTCPの待受やアプリの稼働を保証しません。'},
 {question:'別の支店でHTTPSの404が返った。何を確認できた？',choices:['要求した資源が存在する','応答したHTTPサーバーまで処理が進んだ','通信経路が存在しない'],answer:1,explain:'404はHTTP層の応答。資源の不存在と経路の障害を分けます。応答元はプロキシの可能性もあります。'}
];

export function injectDrift(s){
 const key=Object.keys(s.actual)[0];
 if(s.kind!=='terraform'||!key)throw Error('まずplanとapplyで構築してください。');
 delete s.actual[key];s.revision++;s.verified=false;s.repaired=false;s.driftInjected=true;
}
export function endTrial(s,confirm=false){
 if(s.kind!=='netplan'||s.trial===null)throw Error('試験適用中ではありません。');
 if(confirm&&!s.verified)throw Error('確定前に接続を検証してください。');
 if(!confirm)s.actual=clone(s.trial);
 s.trial=null;s.verified=false;s.revision++;
}
