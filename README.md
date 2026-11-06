# PACKETBOUND — ネットワーク復興譚

Browser-local network training RPG. Three chapters, eighteen quests, a randomized incident lab, field notes and command reference. Japanese UI. No build or external runtime dependencies; serve `dist` as static files with JavaScript module MIME types.

## Structure

- `dist/engine.mjs`: deterministic network state and supported command evaluator; no I/O.
- `dist/quests.mjs`: mission narratives, state presets, objective predicates, walkthroughs and random incident generation.
- `dist/app.js`: campaign progression, scoped evidence, browser saves, map, terminal, journal and lab.
- `tests/engine.test.mjs`: eighteen mission walkthroughs and nine model regression cases.

Run `node --test tests/engine.test.mjs` to validate mission completion, routing and CIDR, DNS caching, port outcomes, TTL, input validation and random incident recoverability.

## Scope and limitations

This is an explicit teaching model, not a Linux emulator. The LAN is fixed at 192.168.10.0/24, with gateway .1 and DNS/DHCP .53. Upstream and return routes are assumed configured. The command book uses Linux syntax for resolvectl, iptables, dhclient, ipcalc and deleting a specific neighbor entry. Availability depends on the Linux setup. The simulator models effective port policy instead of an ordered ruleset, and ip addr replace updates a single IPv4 address. The old training command spellings are accepted for compatibility. The game-specific service commands control the authorized remote training host. Metrics, policy routing, real packets, TCP retransmission, DHCP lease expiry, DNS cache ageing and TLS handshake internals are omitted. Displayed times are illustrative.

## Saves

`packetbound-v2` stores per-quest state, evidence, terminal logs (100 entries maximum per quest), progression and lab records. A first v2 launch migrates `packetbound-v1` campaign completions and valid current settings without removing the original save. Saves are local to the browser and origin. Replays do not award duplicate campaign XP or lab completion counts. Connectivity evidence is tied to the settings at the time of the observation; configuration changes require another probe.

## Living network view

`dist/network-view.mjs` draws interactive SVG equipment, maintains a device inspector, and plays educational request/response stages generated from the command result and model state. It includes a client PC, Ethernet switch, gateway, DNS/DHCP server, HTTPS server and the neighboring network's host. Device power/service indicators are distinct from end-to-end reachability. Client outbound filtering stops at the client; a stopped HTTPS service produces a server-side refusal; HTTP404 remains a received application reply. Playback supports pause, replay, stage selection, speed, keyboard-accessible devices, and reduced-motion preferences. Broadcast and multi-packet exchanges are intentionally represented by a single illustrative path. The scenario does not simulate failures or configuration changes of the switch itself.

Run `node --test tests/*.test.mjs` for all 37 mission, model and animation-path tests.

## 設計・自動構築工房

`dist/academy.html` に独立した8課題を追加。基礎18課題から移動できる。

- プロトコルの成功範囲を3場面で判断
- tcpdumpの限定構文による教材キャプチャの絞り込み、SYN再送/RST/TLSの比較
- 配線・台数・故障ドメインを編集するHA設計（全単一機器/電源系統故障の受入試験）
- FWの正負テストとVPN/私設経路
- 最大フローによる容量上限、障害時余力、増設費用の評価
- Netplanの検証・試験適用・取消・確定
- Ansibleのcheck/diff、2ホストへの適用と冪等性
- Terraformの保存plan、apply、状態ドリフト、古い計画の拒否と再計画

`dist/workshop-model.mjs` は純粋なモデルと限定構文パーサー、`dist/workshop.mjs` は画面と学習進行。`docs/IMPLEMENTATION_PLAN.md` に学習目標・採点・モデルの境界を記載。

`node --test tests/*.test.mjs` で全49テスト。ブラウザのセーブは `packetbound-workshop-v1` で基礎課題と分離。構成図は各設計課題で引き継ぎ、達成履歴と現在の構成の合否は別に扱う。

### 観測と解説を分離
基礎課題の既定は調査モード。機器の形と設計台帳を表示し、内部状態の色・値・自動解説を隠す。機構解説は明示的な操作で開く。調査ノートを保存し、クリア直後の強制解説モーダルを廃止。達成条件は常に確認できる。

### 発展モデルの境界
実pcap採取、Linux、Ansible、Terraform、AWS API、VPN暗号処理は実行しない。IaCは画面のテンプレート構文に限り、不明な構文はエラーにする。Netplanの試験適用タイムアウトは手動取消。Terraformの既存VPC IDは教材値であり実環境に適用できる完成構成ではない。容量は無向リンクの最大フロー上限で、実測値ではない。L2ループ回避・ルーティング収束・セッション同期・TCP輻輳を省略する。学習効果の実証は今後の評価が必要。

## ローカル起動

Node.jsでテストを実行し、任意の静的HTTPサーバーで `dist/` を配信してください。例：`python3 -m http.server 8000 --directory dist`。ブラウザで http://localhost:8000 を開きます。HTTPサーバーが必要なのはES modulesを読み込むためです。ビルドやパッケージインストールは不要です。
