import test from 'node:test';
import assert from 'node:assert/strict';
import {journey} from '../dist/network-view.mjs';
import {initial,run} from '../dist/engine.mjs';
function simulate(s,c){return journey(s,c,run(s,c))}
test('link down never sends a packet to another device',()=>{const steps=simulate(initial({link:false}),'ping 192.168.10.1');assert.equal(steps.length,1);assert.equal(steps[0].node,'pc');assert.equal(steps[0].kind,'error')});
test('DNS direct query ends at PC without reaching archive',()=>{const steps=simulate(initial(),'dig archive.net');assert.ok(steps.some(x=>x.node==='dns'));assert.ok(!steps.some(x=>x.node==='archive'));assert.equal(steps.at(-1).kind,'success')});
test('outbound firewall is shown at PC after DNS',()=>{const steps=simulate(initial({firewall:true}),'curl https://archive.net');assert.equal(steps.at(-1).node,'pc');assert.match(steps.at(-1).title,/送信フィルター/);assert.ok(!steps.some(x=>x.node==='archive'))});
test('stopped service receives request and returns refusal',()=>{const steps=simulate(initial({service:false}),'curl https://archive.net');assert.ok(steps.some(x=>x.node==='archive'&&x.kind==='error'));assert.equal(steps.at(-1).title,'TCP RST')});
test('404 is an application reply from a reached server',()=>{const steps=simulate(initial(),'curl https://archive.net/old');assert.ok(steps.some(x=>x.node==='archive'));assert.equal(steps.at(-1).title,'HTTP 404 応答')});
test('TTL expiration reaches router but not server',()=>{const steps=simulate(initial(),'ping -t 1 10.20.0.80');assert.ok(steps.some(x=>x.node==='router'));assert.ok(!steps.some(x=>x.node==='archive'));assert.equal(steps.at(-1).kind,'error')});
test('DHCP has four alternating stages',()=>{const steps=simulate(initial({ip:null}),'dhcp renew');assert.deepEqual(steps.map(x=>x.title),['DISCOVER','OFFER','REQUEST','ACK']);assert.deepEqual(steps.map(x=>x.node),['dns','pc','dns','pc'])});
test('stale cache does not query DNS or reach current archive',()=>{const steps=simulate(initial({cache:'10.20.0.99'}),'curl https://archive.net');assert.ok(!steps.some(x=>['dns','archive'].includes(x.node)));assert.equal(steps.at(-1).kind,'error')});
test('ARP issue remains a client neighbor table issue',()=>{const steps=simulate(initial({arpBad:true}),'ping 192.168.10.1');assert.equal(steps.at(-1).node,'pc');assert.match(steps.at(-1).detail,/スイッチの故障ではありません/) });
test('server start animation targets server not client',()=>{const steps=simulate(initial({service:false}),'service start https');assert.equal(steps[0].node,'archive');assert.equal(steps[0].kind,'changed')});
