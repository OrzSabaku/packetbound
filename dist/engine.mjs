// Deterministic, browser-local training model. No packets leave this process.
export const DEFAULT={link:true,ip:'192.168.10.20/24',gateway:'192.168.10.1',dns:'192.168.10.53',firewall:false,arpBad:false,lease:false,cache:null,routes:[],service:true,blocked:[],ttl:64};
export const clone=x=>JSON.parse(JSON.stringify(x));
export function initial(overrides={}){return {...clone(DEFAULT),...clone(overrides)}}
export function ipValid(ip){return typeof ip==='string'&&/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)&&ip.split('.').every(n=>+n<=255)}
const toInt=ip=>ip.split('.').reduce((a,b)=>(a*256+Number(b))>>>0,0);
const toIP=n=>[24,16,8,0].map(b=>(n>>>b)&255).join('.');
export function cidr(value){if(typeof value!=='string')return null;const [ip,p,...extra]=value.split('/');if(extra.length||!ipValid(ip)||!/^\d{1,2}$/.test(p)||+p>32)return null;const bits=+p,mask=bits===0?0:(0xffffffff<<(32-bits))>>>0;const network=(toInt(ip)&mask)>>>0;const broadcast=(network|(~mask>>>0))>>>0;return{ip,bits,mask,network,broadcast,text:toIP(network)+'/'+bits}}
export const inside=(ip,range)=>{const net=cidr(range);return ipValid(ip)&&net&&((toInt(ip)&net.mask)>>>0)===net.network};
const names={'archive.net':'10.20.0.80','relay.net':'10.30.0.80'};
const hosts=['192.168.10.1','192.168.10.53','192.168.10.20','10.20.0.80','10.30.0.80','192.168.20.80'];
export function route(s,ip){const entries=[];if(s.ip)entries.push({prefix:cidr(s.ip).text,via:null});for(const r of s.routes)entries.push(r);if(s.gateway)entries.push({prefix:'0.0.0.0/0',via:s.gateway});return entries.filter(r=>inside(ip,r.prefix)).sort((a,b)=>cidr(b.prefix).bits-cidr(a.prefix).bits)[0]||null}
export function network(s,ip){const steps=[];if(!s.link)return{error:'Network is down — eth0 は DOWN。',steps:['eth0: DOWN']};steps.push('eth0: UP');if(!s.ip)return{error:'IPv4 アドレスがありません。',steps};const r=route(s,ip);if(!r)return{error:'Network is unreachable — 該当する経路がありません。',steps:[...steps,'経路表: 該当なし']};steps.push(`経路選択: ${r.prefix}${r.via?' via '+r.via:' dev eth0'}`);
// The simulated Ethernet segment is fixed at 192.168.10.0/24.
if(!inside(cidr(s.ip).ip,'192.168.10.0/24')||!inside('192.168.10.1',s.ip))return{error:'宛先到達不能 — 端末のIP / プレフィックスと実際のLANを確認。',steps};
if(s.arpBad)return{error:'ARP 解決失敗 — 次ホップの近隣エントリーが誤っています。',steps:[...steps,'ARP: 誤った固定MACへ送信']};
const next=r.via||ip;steps.push(`ARP: ${next} のMACを解決`);
if(r.via&&(!inside(r.via,s.ip)||r.via!=='192.168.10.1'))return{error:'次ホップから応答がありません。選択された経路を調べよう。',steps};
if(!r.via&&!inside(ip,'192.168.10.0/24'))return{error:'ARP timeout — 遠隔ホストを同じLAN上に探しています。プレフィックスを確認。',steps};
if(!hosts.includes(ip))return{error:'Request timeout — この演習に応答するホストはありません。',steps};
if(r.via)steps.push('ルーター: 転送 → 目的ネットワーク');return{error:null,steps:[...steps,'宛先IP: 到達'],hops:r.via?2:1}}
function lookup(s,name,direct=false){if(ipValid(name))return{ip:name,steps:[]};if(!direct&&name==='archive.net'&&s.cache)return{ip:s.cache,steps:[`ローカルDNSキャッシュ: ${name} → ${s.cache}`]};if(s.dns!=='192.168.10.53')return{error:'名前解決失敗 — DNSサーバーが未設定または不正です。',steps:['DNS: サーバー設定エラー']};const n=network(s,s.dns);if(n.error)return{error:'DNS query failed: '+n.error,steps:n.steps};if(!names[name])return{error:'NXDOMAIN — 登録されていない名前です。',steps:['DNS: 該当するレコードなし']};return{ip:names[name],steps:[`DNS応答: ${name} → ${names[name]}`]}}
export function ready(s,name='archive.net',port=443){const l=lookup(s,name);if(l.error)return false;return !network(s,l.ip).error&&!(port===443&&s.firewall)&&!s.blocked.includes(port)&&s.service}
export const COMMANDS=[
['ip link','リンク状態を表示'],['ip addr','IPv4とプレフィックスを表示'],['ip route','経路表を表示'],['ip route get 10.20.0.80','最長一致で選ばれる経路'],['ip neigh','近隣キャッシュを表示'],['ping 192.168.10.1','ICMP到達性確認'],['dig archive.net','DNSサーバーへ直接問い合わせ'],['traceroute 10.20.0.80','通るルーターを調査'],['curl https://archive.net','HTTPSリクエスト'],['ip link set eth0 up','リンクを有効にする'],['ip addr replace 192.168.10.20/24 dev eth0','IPv4を置換（本演習は単一アドレス）'],['ip route add default via 192.168.10.1','デフォルト経路を設定'],['ip route del 10.20.0.0/24','特定経路を削除'],['sudo ip neigh del 192.168.10.1 dev eth0','ゲートウェイの固定近隣エントリーを削除'],['sudo dhclient -v eth0','DHCPクライアントで設定を取得'],['ipcalc 192.168.10.20/24','ネットワーク範囲を計算'],['resolvectl status eth0','DNS設定を表示'],['sudo resolvectl dns eth0 192.168.10.53','DNSサーバーを設定'],['resolvectl show-cache','クライアントのキャッシュを表示'],['sudo resolvectl flush-caches','systemd-resolved のキャッシュを削除'],['sudo iptables -S OUTPUT','送信フィルターを表示'],['sudo iptables -I OUTPUT -p tcp --dport 443 -j ACCEPT','TCPポートを許可'],['sudo iptables -I OUTPUT -p tcp --dport 23 -j DROP','TCPポートを拒否'],['nc -vz archive.net 443','TCPポートを調査'],['service status','管理対象の書庫サーバーのサービス状態 ※'],['service start https','書庫サーバーのHTTPSを起動 ※'],['ping -t 1 10.20.0.80','送信TTLを1に制限'],['curl https://archive.net/health','HTTPパスを指定'],['help','一覧を表示'],['mission','現在の目標'],['clear','端末表示を消去']];
// Normalize supported Linux syntax to the existing simulator operations.
export function normalizeCommand(input) {
  const command = input.trim().replace(/\s+/g, ' ').replace(/^sudo /, '');
  const aliases = {
    'ip neigh del 192.168.10.1 dev eth0': 'ip neigh flush dev eth0',
    'dhclient -v eth0': 'dhcp renew',
    'resolvectl status eth0': 'dns status',
    'resolvectl show-cache': 'dns cache',
    'resolvectl flush-caches': 'dns flush',
    'iptables -S OUTPUT': 'fw status',
  };
  if (Object.hasOwn(aliases, command)) return aliases[command];
  const dns = command.match(/^resolvectl dns eth0 (\S+)$/);
  if (dns) return 'dns set ' + dns[1];
  const rule = command.match(/^iptables -I OUTPUT -p tcp --dport (\d+) -j (ACCEPT|DROP)$/);
  if (rule) return 'fw ' + (rule[2] === 'ACCEPT' ? 'allow' : 'deny') + ' tcp ' + rule[1];
  return command.replace(/^ipcalc /, 'subnet ');
}
export function run(s,input){const c=normalizeCommand(input);let m;let result={text:'',kind:'log',steps:[],events:[],changed:false};const out=(text,kind='log')=>({...result,text,kind});const fail=text=>out(text,'error');const mutate=text=>{result.changed=true;return out(text,'success')};
if(c==='help')return out(COMMANDS.map(([cmd,note])=>cmd.padEnd(48)+' '+note).join('\n')+'\n※ service status / service start https は書庫管理用のゲーム操作。Linuxコマンドは演習に必要な構文を再現しています。');
if(['ip link','ip link show'].includes(c))return out(`2: eth0: <${s.link?'UP,LOWER_UP':'BROADCAST'}> mtu 1500 state ${s.link?'UP':'DOWN'}\n    link/ether 02:00:00:00:10:20`);
if(['ip addr','ip a','ip addr show'].includes(c))return out(`eth0: state ${s.link?'UP':'DOWN'}\n    inet ${s.ip||'未設定'}`);
if(c==='ip route'||c==='ip route show')return out([s.ip?cidr(s.ip).text+' dev eth0':null,...s.routes.map(r=>r.prefix+' via '+r.via),s.gateway?'default via '+s.gateway+' dev eth0':null].filter(Boolean).join('\n')||'経路なし');
if((m=c.match(/^ip route get (\S+)$/))){if(!ipValid(m[1]))return fail('IPv4アドレスを指定してください。');const r=route(s,m[1]);result.events=['route-inspected'];return out(r?`${m[1]} ${r.via?'via '+r.via:'dev eth0'}\n    matched ${r.prefix}（最長一致）`:'Network is unreachable')}
if(c==='ip neigh'){result.events=['arp-inspected'];return out(s.arpBad?'192.168.10.1 dev eth0 lladdr de:ad:be:ef:00:01 PERMANENT\n管理記録の正しいMAC: 02:00:00:00:10:01':'192.168.10.1 dev eth0 lladdr 02:00:00:00:10:01 REACHABLE')}
if((m=c.match(/^ip link set eth0 (up|down)$/))){s.link=m[1]==='up';return mutate('eth0 → '+m[1].toUpperCase())}
if((m=c.match(/^ip addr replace (\S+) dev eth0$/))){const n=cidr(m[1]);if(!n||n.bits<1||n.bits>30||toInt(n.ip)===n.network||toInt(n.ip)===n.broadcast)return fail('有効なホストIPv4/1〜30を指定してください（ネットワーク・ブロードキャストアドレスを除く）。');s.ip=m[1];s.lease=false;return mutate('IPv4 → '+s.ip)}
if((m=c.match(/^ip route (add|replace) (default|\S+) via (\S+)$/))){if(!ipValid(m[3])||!s.ip||!inside(m[3],s.ip))return fail('Invalid gateway — eth0 の直接接続範囲のIPv4を指定。');if(m[2]==='default')s.gateway=m[3];else{const n=cidr(m[2]);if(!n)return fail('有効な宛先プレフィックスを指定。');s.routes=s.routes.filter(r=>r.prefix!==n.text);s.routes.push({prefix:n.text,via:m[3]})}return mutate('経路を設定しました。')}
if((m=c.match(/^ip route del (\S+)$/))){if(m[1]==='default')s.gateway=null;else{const n=cidr(m[1]);if(!n)return fail('有効な宛先プレフィックスを指定。');if(!s.routes.some(r=>r.prefix===n.text))return fail('No such process — 指定した静的経路はありません。');s.routes=s.routes.filter(r=>r.prefix!==n.text)}return mutate('経路を削除しました。')}
if(c==='ip neigh flush dev eth0'){s.arpBad=false;return mutate('近隣キャッシュを消去。次の通信でARPを再解決します。')}
if(c==='dhcp renew'){if(!s.link)return fail('DHCP timeout — まずリンクを有効にしてください。');s.ip='192.168.10.20/24';s.gateway='192.168.10.1';s.dns='192.168.10.53';s.lease=true;result.events=['dhcp'];result.steps=['DISCOVER: ブロードキャストで探索','OFFER: サーバーが候補を提示','REQUEST: 候補を要求','ACK: 貸与を確定'];return mutate('DHCPDISCOVER → DHCPOFFER → DHCPREQUEST → DHCPACK\nLEASE: 192.168.10.20/24  /  3600s（固定演出値）\nRouter: 192.168.10.1  DNS: 192.168.10.53')}
if((m=c.match(/^subnet (\S+)$/))){const n=cidr(m[1]);if(!n)return fail('IPv4/プレフィックス長を指定してください。');result.events=['subnet'];return out(`network: ${n.text}\nnetmask: ${toIP(n.mask)}\nbroadcast: ${toIP(n.broadcast)}\n${n.bits<=30?'hosts: '+toIP(n.network+1)+'〜'+toIP(n.broadcast-1)+' ('+(2**(32-n.bits)-2)+' hosts)':'/31・/32は用途に応じた扱いが必要です。'}`)}
if(c==='dns status')return out('DNS server: '+(s.dns||'未設定'));if(c==='dns cache'){result.events=['cache-inspected'];return out(s.cache?'archive.net → '+s.cache+' (local cache; expiry not simulated)':'ローカルキャッシュは空です。')}
if(c==='dns flush'){s.cache=null;return mutate('ローカルDNSキャッシュを削除。次回はサーバーへ問い合わせます。')}
if((m=c.match(/^dns set (\S+)$/))){if(!ipValid(m[1]))return fail('有効なIPv4を指定。');s.dns=m[1];return mutate('DNS server → '+s.dns)}
if(c==='fw status' && /iptables/.test(input)){
 const rules = ['-P OUTPUT ACCEPT'];
 if (s.firewall) rules.push('-A OUTPUT -p tcp -m tcp --dport 443 -j DROP');
 for (const port of s.blocked) rules.push(`-A OUTPUT -p tcp -m tcp --dport ${port} -j DROP`);
 result.events=['fw-inspected'];
 return out(rules.join('\n'));
}
if(c==='fw status'){result.events=['fw-inspected'];return out('OUTBOUND TCP 443: '+(s.firewall?'DENY':'ALLOW')+'\nOUTBOUND TCP 23: '+(s.blocked.includes(23)?'DENY':'ALLOW')+'\nOther blocked TCP: '+(s.blocked.filter(p=>p!==23).join(', ')||'none')+'\nICMP / DNS: ALLOW')}
if((m=c.match(/^fw (allow|deny) tcp (\d+)$/))){const p=+m[2];if(p<1||p>65535)return fail('ポート番号は1〜65535。');if(p===443)s.firewall=m[1]==='deny';else if(m[1]==='deny')s.blocked=[...new Set([...s.blocked,p])];else s.blocked=s.blocked.filter(n=>n!==p);return mutate(`OUTBOUND TCP ${p} → ${m[1].toUpperCase()}`)}
if(c==='service status'){result.events=['service-inspected'];return out('管理対象: archive.net（許可された演習サーバー）\nhttps: '+(s.service?'RUNNING — listen tcp/443':'STOPPED — no listener'))}
if(c==='service start https'){s.service=true;return mutate('archive.net のHTTPSサービスを起動。TCP 443で待受を開始。')}
if((m=c.match(/^dig (\S+)$/))){if(ipValid(m[1]))return fail('この演習の dig はホスト名のAレコードを調べます。');const l=lookup(s,m[1],true);result.steps=l.steps;if(l.error)return fail(l.error);result.events=['dig:'+m[1]];return out(`;; status: NOERROR\n${m[1]}. 300 IN A ${l.ip}\n;; SERVER: ${s.dns}\n（ローカルキャッシュを経由せずDNSへ問い合わせ）`,'success')}
if((m=c.match(/^ping(?: -t (\d+))? (\S+)$/))){const ttl=m[1]?+m[1]:64;if(ttl<1||ttl>255)return fail('TTLは1〜255。');const l=lookup(s,m[2]);if(l.error){result.steps=l.steps;return fail(l.error)}const n=network(s,l.ip);result.steps=[...l.steps,...n.steps];if(n.error)return fail(n.error);if(ttl<n.hops){result.steps=[...l.steps,...n.steps.slice(0,3),'ルーター: TTLが0 → 破棄','ICMP Time Exceeded: 受信'];result.events=['ttl-expired'];return fail('From 192.168.10.1: Time to live exceeded\n送信TTLがルーターで0になりました。')}result.events=['ping:'+m[2]];result.steps.push('ICMP Echo Reply: 受信');return out(`PING ${m[2]} (${l.ip})\n64 bytes from ${l.ip}: icmp_seq=1 ttl=${64-(n.hops-1)} time=1.2 ms\n2 packets transmitted, 2 received, 0% packet loss`,'success')}
if((m=c.match(/^traceroute (\S+)$/))){const l=lookup(s,m[1]);if(l.error)return fail(l.error);const n=network(s,l.ip);result.steps=[...l.steps,...n.steps];if(n.error)return fail(n.error);result.events=['trace'];return out(n.hops===1?`1 ${l.ip} 0.5 ms`:`1 192.168.10.1 0.5 ms\n2 ${l.ip} 1.2 ms`,'success')}
if((m=c.match(/^nc -vz (\S+) (\d+)$/))){const p=+m[2];if(p<1||p>65535)return fail('ポート番号は1〜65535。');const l=lookup(s,m[1]);if(l.error)return fail(l.error);const n=network(s,l.ip);result.steps=[...l.steps,...n.steps];if(n.error)return fail(n.error);if((p===443&&s.firewall)||s.blocked.includes(p)){result.events=['port-filtered:'+p];return fail('Connection timed out — フィルターがパケットを破棄。')}if(p!==443||!s.service){result.events=['port-refused:'+p];return fail('Connection refused — 到達したが、このポートで待受していない。')}result.events=['port-open:'+p];result.steps.push('TCP: SYN → SYN/ACK → ACK');return out('Connection to '+m[1]+' '+p+' port [tcp/https] succeeded!','success')}
if((m=c.match(/^curl (https?:\/\/)([a-zA-Z0-9.-]+)(\/\S*)?$/))){const port=m[1]==='https://'?443:80;const l=lookup(s,m[2]);if(l.error){result.steps=l.steps;return fail(l.error)}const n=network(s,l.ip);result.steps=[...l.steps,...n.steps];if(n.error)return fail(n.error);if((port===443&&s.firewall)||s.blocked.includes(port))return fail('curl: (28) Connection timed out — 送信フィルターが破棄。');if(port!==443||!s.service)return fail('curl: (7) Connection refused — サービスが待受していません。');result.steps.push('TCP: 接続確立','TLS: 成功（内部処理は省略）');const path=m[3]||'/';if(!['/','/health'].includes(path)){result.events=['http404'];result.steps.push('HTTP: 404 Not Found');return out('HTTP/1.1 404 Not Found\n{"error":"path not found"}\nネットワーク接続は成功。指定したパスが見つかりません。','error')}result.events=['curl',path==='/health'?'health':'root'];result.steps.push('HTTP: 200 OK');return out('HTTP/1.1 200 OK\nContent-Type: application/json\n\n'+(path==='/health'?'{"status":"healthy","signal":"RESTORE"}':'{"signal":"RESTORE","message":"世界は再び、つながり始めた。"}'),'success')}
return fail('未対応のコマンド / 構文です。help またはコマンド帳を確認してください。')}
