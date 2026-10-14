# nethergate

**作者 / Author: Michitaka Kurahashi** · ライセンス: [MIT](LICENSE)

Claude Code や Codex のような AI エージェントに、**サーバーの防御だけを安全に任せる**ための「門」です。
AIにはシェルも生ログも渡しません。決められた狭い道具（MCPツール）だけを渡し、
AIがどう判断しても、ポリシーを超える操作は物理的にできない構造にしています。

```
                    管理用PC / 別ホスト（AIはここで動く）
              ┌──────────────────────────────────────────┐
              │ Claude Code / Codex  (サブスクリプション) │
              └───────────────┬──────────────────────────┘
                              │ SSH（鍵は "nethergate mcp" しか起動できない）
════════════════ 防御対象サーバー ═══════════════╪═══════════════════════
                              ▼
  ┌── ng-mcp（権限なし）──────────────┐  ┌── ng-watch（権限なし）──────────────┐
  │ nethergate mcp … AI用ツールのみ    │  │ nethergate watch … ログ監視 →        │
  │ ログは無害化して渡す               │  │ ルール/記録書で即ブロック・AIに調査依頼 │
  └───────────────┬────────────────────┘  └──────────────┬──────────────────────┘
                  │ Unixソケット：送り手は接続元UIDで決まる（ai / rules・playbook / human）
  ┌───────────────▼──── ng-enforcer（CAP_NET_ADMIN だけ）─────────────────────┐
  │ nethergate enforcer … ログから自分でインシデントを再計算 → ポリシー・上限で検査 │
  │ → 監査ログに先に記録（書けなければ中止）→ nftables に単一IPを時限追加         │
  └──────────────────────────────────────────────────────────────────────┘
  すべての判断・操作 → ハッシュチェーン付きの監査ログ → 件数とハッシュを定期的に外部へ（アンカー）
```

## AIができること / できないこと

| AIに渡すツール | 内容 |
|---|---|
| `status` | 深刻度ごとの件数、上位の送信元、現在のブロック |
| `list_incidents` / `get_incident` | 送信元IPごとの攻撃の種類、狙われた入口、攻撃者の種別の推定、無害化したサンプル |
| `enrich_ip` | **公開情報のみ**の照会：逆引き、ASN、RDAP（abuse連絡先）、Shodan InternetDB、Torの出口ノード一覧、AbuseIPDB |
| `block_ip` / `unblock_ip` | 単一IPの一時的なブロック（期限つき）とその解除 |
| `save_report` | 管理者向けのMarkdownレポートを保存（ファイル名はサーバーが決める） |
| `request_human_review` | 判断に自信がないとき、**ブロックせずに**ユーザーに相談する（Webhookで通知される） |
| `list_playbook` / `propose_rule` | 記録書（プレイブック）を見る / 新しい攻撃パターンをルールとして**提案**する（ユーザーが承認するまでは何の効果もない） |

**できないこと**：コマンドの実行、ファイルの読み書き、IP範囲（CIDR）のブロック、許可リストやプライベートIPのブロック、
**このサーバーを攻撃していないIPのブロック**（スコアが `ai_min_score` 未満なら拒否）、TTL上限や1時間あたりの件数上限を超える操作。

## 攻撃してくるAIへの対策

| 脅威 | 対策 |
|---|---|
| **プロンプトインジェクション**（User-Agentやパスに「指示を無視して〜」を仕込む） | 制御文字やbidi文字を除去し、秘密情報をマスクし、160文字で切り詰める。`untrusted_*` ラベルを付けて渡す。調査依頼のプロンプトには自分たちが生成した値（IPとスコア）しか入れない |
| **AIをだましてサービスを止めさせる**（顧客やCDNのIPをブロックさせる） | このサーバーに攻撃したIPしか対象にしない。許可リスト、単一IPのみ、TTL上限、件数上限で縛る。ポリシーは特権側のプロセスで再検査する |
| **nethergate自体の乗っ取り** | 権限を分離（ファイアウォールを触るのは小さなenforcerだけ）。外部依存は0（Go標準ライブラリのみ）。待ち受けるネットワークポートなし。systemdで厳しくサンドボックス化。nftはシェルを経由せず引数で実行 |
| **MCPやwatchが乗っ取られ、enforcerに直接リクエストを送る** | enforcerは呼び出し側を信用しない。① 送り手（ai / rules / playbook / human）は**接続元のUID**から決める（リクエストで名乗れない）② 自動のブロックは、enforcer自身がログを読み直してインシデントを再計算し、条件（AIは `ai_min_score`、ルールは `auto_block_score`、記録書は承認済みルールの発動）を満たすときだけ実行する。ログを読めなければ拒否する ③ AIが解除できるのは**AI自身がかけたブロックだけ**。延長しても所有者は強いほう（human > playbook > rules > ai）のまま ④ 件数上限は送り手ごと（初期値：ai 20 / rules 60 / playbook 60 件/時）なので、AIが上限を使い切ってもルールエンジンは止まらない。人間（ユーザー）の操作は上限の対象外 ⑤ `mcp` や `watch` を別の役割のUID（rootなど）で起動しようとすると、起動を拒否する |
| **痕跡の消去** | 監査ログはハッシュチェーンで、`nethergate verify` で改ざんを検出できる。enforcerは**監査ログに書けなければファイアウォールを変更しない**（先に「これから実行する」記録を書く）。ログの末尾を丸ごと消されるとチェーンだけでは検出できないため、各ログの「件数とハッシュ」を `NETHERGATE-ANCHOR` 行として journald へ定期的に出し、必要なら `audit_anchor.url` へも送る（**外部アンカー**）。journald を別のサーバー（syslog/SIEM）に転送しておけば、`journalctl -u 'nethergate-*' > anchors.txt` → `nethergate verify -anchors anchors.txt` で、末尾の削除や作り直しも検出できる |
| **大量のログでの攻撃** | 読み込む量の上限、1行の長さの上限、保持するサンプル数の上限、調査は同時に1件まで（クールダウンあり） |

## AIが乗っ取られても被害を最小限にする

AIは、ログ（攻撃者が書いた文字列）を読む以上、**いつでもプロンプトインジェクションで乗っ取られうる**ものとして設計しています。乗っ取られたAIにも、次の範囲のことしかできません。

| 乗っ取られたAIが狙うこと | どう防ぐか（AIの判断に頼らない） |
|---|---|
| 無関係な人や顧客をブロックする | enforcer がログから再計算し、**このサーバーを攻撃したIP**（スコア `ai_min_score` 以上）しか受け付けない。許可リスト、単一IPのみ、AIの1時間あたりの件数上限（初期値20件）あり |
| 攻撃者と同じIPを使う利用者（会社のNAT、携帯回線、プロキシ）をまとめて止める | 成功した通信が多い、またはUser-Agentの種類が多いIPは「共有アドレス」とみなし、AIには許さず人間に回す |
| 長期間のブロックでサービスを止める | AIのブロックは最長 `ai.max_ttl`（初期値6時間）。延長しても、より強い所有者のブロックを乗っ取れない |
| ルールや人間がかけたブロックを外して、攻撃者を通す | AIが解除できるのは、AI自身がかけたブロックだけ |
| 拒否されても何度も試す | **自動隔離**：10分間に5回拒否されると、AIのすべての書き込み操作（ブロック、解除、提案、相談、レポート）を止め、すぐにWebhookで通知する。停止状態は enforcer が持ち、再起動しても残る。解除できるのは管理者だけ（`nethergate ai resume`。監査ログに記録できなければ解除しない） |
| 自分の言葉で、次回以降のAIを乗っ取る | AIが書いた文章（提案ルールの説明文、相談文）は、次のAIに渡すとき `untrusted_ai_written` として明示的に区別する。人間が書いた教訓と承認済みルールだけを信頼できる情報として渡す |
| 人間をだます（偽の手順、危険なリンク、広い許可） | レポートの先頭に警告を付け、リンクを無効化（`hxxps://`）し、HTMLを無害化する。AIが提案できる許可の範囲は /24（IPv6は /48）まで。提案は必ず人間が承認する |
| ツールを大量に使う（通知の大量送信、外部照会サービスの利用枠の使い切り、ディスクを埋める） | ツールごとに、セッションをまたいだ回数の上限を設ける（相談 30件/時、照会 120件/時、提案 20件/日、レポート 50件/日・合計100MB） |
| 権限の外に出る | AIに渡すのは MCP のツールだけ（シェル、ファイル、ネットワークは渡さない）。AI用のプロセスは専用ユーザー（ng-mcp）で動き、enforcer はUIDでAIと判断する |

**人間が使う停止スイッチ**：`nethergate ai pause -reason "..."` でAIを即座に止め、`nethergate ai status` で状態を確認できます。

**助言モード**：`"policy": {"ai": {"mode": "advise"}}` にすると、AIは**ブロックを提案するだけ**になります（`block_ip` は人間への相談になり、enforcer もAIによるブロックを拒否します）。まず助言モードで運用し、AIの判断を信頼できるようになってから `act` に切り替える、という導入の仕方もできます。

## 判断の流れ（タイミングの判断）

1. **確実に悪いもの**（スコア90以上：既知の攻撃ツールで複数種類の攻撃をしている等）→ ルールで即時ブロック。AIのコストも時間もかけない
2. **深刻度が上がった** → Webhook（Slack/Discord）でユーザーに通知
3. **グレーゾーンか重要なもの**（60以上）→ AIを起動。AIが調査・公開情報の照会・ブロックするかの判断・レポート作成まで行う
4. **SSHの総当たりの後にログインが成功** → 重大として通知。自動ブロックはしない（管理者本人の可能性があるので、ユーザーが判断する）

攻撃者の種別の推定：既知のスキャナー / 単一CVEを狙う大量攻撃bot / ディレクトリ総当たり / SSH総当たり /
**複数種類の攻撃を中くらいの速度で次々試す、適応型（AI支援の可能性がある）標的型攻撃**。
※ IPから個人や組織を断定することはできません（VPN、Tor、乗っ取られた機器が多い）。あくまで推定として扱ってください。

## 記録書（プレイブック）：一度対処した攻撃は次から即座に止める

特殊な攻撃に一度対処したら、そのパターンと対処方法をルールとして残します。次に同じ攻撃が来たら、AIに聞かずにその場で止めます。

```
AIが調査・対処 ──propose_rule──▶ 提案ファイル（AIが書ける場所）
                                    │ 自動チェック：正規表現 / 普通の通信に当たらないか / 今のログで再現
                                    ▼
           ユーザー：nethergate playbook show <id> → approve <id>
                                    ▼
           /etc/nethergate/playbook.json（rootだけが書ける。AIは読むだけ）
                                    ▼ 起動時に読み込み。ファイルが変わったら再起動なしで再読み込み
     同じ攻撃が来たら：ルールに一致 → 即ブロック（記録したTTL）。AIへの調査依頼は省略
```

- **ルールの中身**：パス / User-Agent / SSHユーザー名の正規表現、何回当たったら発動するか（`min_hits`）、加算するスコア、自動ブロックするか（`auto_block`）とそのTTL、**そのとき何をしたか（`handling`）**
- 自動ブロックしないルールでも、一致すると「既知のパターン」としてAIに伝わり、AIは前回の対処方法をもとに判断します
- **AIが書いたルールは、必ずユーザーが承認してから有効になります**。攻撃者にだまされたAIが「全員に当たるルール」を仕込んで、サービスを止めるのを防ぐためです。提案の時点でも、次のものは自動で拒否されます：
  - 空文字列にマッチする（＝何にでも当たる）正規表現
  - 普通のページ・ブラウザ・Googlebotに当たるもの
  - 例として挙げたIPに当たらないもの
  - 今のログで普通の利用者に見えるIPに3つ以上当たるもの、当たるIPが多すぎるもの（`max_match_ips`）
- 正規表現はGoのRE2なので、攻撃者が送る文字列で処理が固まる（ReDoS）ことはありません

```bash
nethergate playbook list            # 承認済みと承認待ちの一覧
nethergate playbook show <id>       # 中身と「今のログで誰に当たるか」の再現結果
sudo nethergate playbook approve <id>
nethergate playbook reject <id>
sudo nethergate playbook remove <id>   # 承認済みルールを無効にする
```

ユーザーが `/etc/nethergate/playbook.json` を直接書いても構いません。壊れたルールは読み込み時にスキップされ、ログに警告が出ます（他のルールは動き続けます）。承認・却下・削除はすべて監査ログ（`playbook-audit.jsonl`）に残ります。

## 間違いを覚える：相談・訂正・手動の許可

ブロックは、正しい利用者を締め出すことがあります。そのため、迷ったときと間違えたときの扱いも「記憶」として残します。

| 場面 | すること | 覚えること |
|---|---|---|
| **AIが判断に迷った**（顧客？取引先？監視サービス？） | AIはブロックせず `request_human_review` で相談 → Webhookで通知 → `nethergate review answer <id> malicious\|benign -note "..."` | ユーザーの答えが**教訓**になる。次に同じIPを調べるとき、AIには `human_lessons_for_this_ip` として届き、**AI自身の判断より優先**される |
| **ブロックが間違いだった** | `nethergate correct <ip> benign -note "..."` | すぐにブロックを解除し、そのIPの許可ルールを作り、**どのルールが原因だったか**を記録する。`-remove-rules` を付けると、原因になったルールも削除する |
| **見逃していた攻撃だった** | `nethergate correct <ip> malicious -note "..." [-path-regex ...] [-auto-block]` | ブロックし、パターンを指定すれば攻撃ルールとして登録する。そのIPを許可していたルールがあれば、記録に残す |
| **よく分からないが許可したい**（委託先の診断、社内監視など） | `correct <ip> benign -allow-prefix 198.51.100.0/24 -note "..."`、またはパターンで絞る（`-path-regex '^/healthz$'`） | 許可ルール（`verdict: allow`）として登録する |

- **許可ルールの効き方**：一致した通信は攻撃として数えません。IP範囲の許可は**enforcerでも強制**され、そのIPはどの経路からもブロックできなくなり、すでにかかっているブロックも自動で解除されます。範囲は /8（IPv6は /16）より広くは指定できません
- AIも許可ルールを**提案**できます（`verdict: "allow"`）。その場合の検証結果には「この許可で見逃すことになる、現在は疑わしいIP」の一覧が付くので、ユーザーはその影響を見たうえで承認できます
- 教訓（`/etc/nethergate/lessons.json`）と承認済みルールは root だけが書けます。そのためAIが「偽の教訓」を作って攻撃者を許可させることはできません。記録はすべて監査ログに残ります
- 一覧：`nethergate playbook list`（ルール＋最近の教訓）、`nethergate review list`（相談待ち）

## セットアップ（Debian/Ubuntu系の例）

```bash
go build -trimpath -ldflags=-s -o nethergate ./cmd/nethergate
sudo install -m 0755 nethergate /usr/local/bin/
sudo install -D -m 0644 deploy/sysusers-nethergate.conf /etc/sysusers.d/nethergate.conf && sudo systemd-sysusers
#   AIはSSHで ng-mcp としてつなぐ：ホームと authorized_keys を用意する（鍵ファイルは root 所有）
sudo install -d -m 0750 -o ng-mcp -g nethergate /home/ng-mcp && sudo install -d -m 0755 /home/ng-mcp/.ssh
sudo install -D -m 0640 -g nethergate deploy/config.example.json /etc/nethergate/config.json
echo '[]' | sudo install -m 0644 /dev/stdin /etc/nethergate/playbook.json   # 承認済みの記録書（root所有）
echo '[]' | sudo install -m 0644 /dev/stdin /etc/nethergate/lessons.json    # ユーザーの判断の記録（root所有）
#   → config.json の enforcer_clients に各UIDを入れる（役割ごとに必ず別のユーザー）：
#        "watch_uids": [`id -u ng-watch`], "mcp_uids": [`id -u ng-mcp`], "admin_uids": []（rootは常に管理者）
#     allowlist に管理元のIPを入れる
nethergate nft-setup | sudo tee /etc/nftables.d/nethergate.nft && sudo nft -f /etc/nftables.d/nethergate.nft
sudo install -m 0644 deploy/nethergate-*.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now nethergate-enforcer nethergate-watch
#   ↑ watch を先に一度起動しておくと /var/lib/nethergate が作られ（1770, group nethergate）、SSH経由の mcp も監査ログを書ける
#   外部アンカー：journald をリモートの syslog/SIEM へ転送する（推奨）か、config の audit_anchor.url に収集先を設定する
```

最初は `"dry_run": true` のまま数日動かし、`nethergate scan` と監査ログで誤検知がないかを確認してください。問題なければ `false` にします。

### AIをつなぐ

- **推奨：AIは別のホストで動かし、SSHでつなぐ**。防御対象のサーバーにAIの認証情報を置かずに済みます
  - `deploy/authorized_keys.example`：この鍵では `nethergate mcp` しか起動できません（`restrict` と `from=`）
  - Claude Code：`deploy/claude-mcp.ssh.example.json` を `--mcp-config` で読み込む
  - Codex：`deploy/codex-config.example.toml`
- 自動で調査させる場合は、`deploy/triage-command.example.json` の内容を config の `triage.command` に入れます（nethergateのツール以外は使えないようにしてあります）
  - 同じサーバー上で調査させる場合も、MCPサーバーは必ず **ng-mcp** として動かします（`deploy/claude-mcp.local.example.json`：localhost へのSSHでユーザーを切り替える）。watch のユーザーのまま `nethergate mcp` を起動しようとすると、起動を拒否します

## 証拠を外に出す・状態を見る（SIEM連携とメトリクス）

### SIEM / syslog への転送
`config.json` の `forward` を設定すると、watch が**すべての監査ログ（enforcer の分を含む）を1件ずつ外部へ転送**します。サーバーが乗っ取られても、証拠は別の場所に残ります。

- 送り先：**syslog**（RFC5424、TLS、ポート6514。`ca_file` で社内CAも指定できる）と **HTTP**（`ndjson`：Elastic・Loki・Vector・Fluent Bit など ／ `splunk_hec`）。トークンは `/etc/nethergate/env` に置き、`token_env` で変数名を指定する
- **送れない間も失われない**：監査ログ自体を送信待ちの記録として使い、送信に成功したときだけ「どこまで送ったか」を進める（同じ記録が二重に届くことはあるので、受信側は `file` と `n` で重複を除く）
- 一定量ずつまとめて送り、その都度「その時点の件数とハッシュ」（`anchor`）も送るので、SIEM 側だけで改ざんを検証できる
- **監査ログのファイルが縮んだ、差し替えられた、消えた**ときは、その場で `tamper` イベント（syslog の重大度は alert）を送る
- 暗号化なしの syslog は、同じサーバー上の中継（127.0.0.1）宛てにしか送れない
- journald（`NETHERGATE-ANCHOR` 行を含む）の転送例：`deploy/rsyslog-journal-forward.conf.example`

### メトリクス（Prometheus / OpenTelemetry）
`"metrics": {"listen": "127.0.0.1:9464"}` で `/metrics` を公開します。初期設定では、このサーバー自身（ループバック）からしか読めません。enforcer は新たに待ち受けポートを開かず、数値は今あるソケット経由で watch に渡し、watch がまとめて公開します。

| 主なメトリクス | 意味 |
|---|---|
| `nethergate_enforcer_requests_total{op,actor,result}` | enforcer の処理件数（ok / rejected / error） |
| `nethergate_enforcer_audit_write_failures_total` | 監査ログに書けずファイアウォールの変更を中止した回数。**常に0であるべき** |
| `nethergate_enforcer_quota_remaining{actor}` / `nethergate_enforcer_active_blocks{owner}` | 送り手ごとの件数上限の残り / 現在のブロック数 |
| `nethergate_forward_tamper_events_total` / `nethergate_forward_lag_bytes` | 改ざんの疑いを検知した回数 / SIEM にまだ送っていない量 |
| `nethergate_incidents{severity}` / `nethergate_reviews_pending` / `nethergate_playbook_proposals_pending` | 直近のインシデント数 / 相談待ち / 承認待ちの提案 |
| `nethergate_triage_runs_total` / `nethergate_triage_duration_seconds` | AIによる調査の回数と所要時間 |

- 警告ルールの例：`deploy/prometheus-alerts.yml`（監査ログの書き込み失敗、改ざん、enforcer の停止、AIの拒否の急増、件数上限の使い切り、承認待ちの放置、dry-run のまま1週間など）
- OpenTelemetry：`deploy/otel-collector.example.yaml`（Collector の prometheus receiver で読み取り、OTLP で送る）

## サーバー構成のアドバイス

**ネットワークの境界**
- **オリジンを隠す**：Cloudflareなどのリバースプロキシ/WAFを前段に置き、オリジンの80/443はCDNのIPからだけ受け付ける。こうするとAIによる大量スキャンの大半がオリジンまで届かない
  - この場合、nginxは `real_ip_header CF-Connecting-IP` と `set_real_ip_from <CloudflareのIP範囲>` で本当の送信元IPを記録する（設定しないと、全員がCDNのIPに見えてしまう）
- **SSH**：パスワード認証を無効にして鍵のみにする。可能ならSSHはTailscale/WireGuardのVPN内からだけ受け付ける
- **nftablesの基本方針はdrop**にして、必要なポートだけ開ける。外向き通信も制限すると、侵入された後の外部への持ち出しを防げる

**ホスト**
- 自動セキュリティ更新（`unattended-upgrades`）を有効にし、不要なサービスを止める。各サービスにsystemdのサンドボックス（このリポジトリの `.service` を参考に）を付ける
- アプリは権限のないOSアカウントで動かし、DBはlocalhostかプライベートネットワークだけで待ち受ける
- **ログと監査ログは別のサーバーに転送する**（journaldのリモート転送、rsyslog、Lokiなど）。侵入されても証拠が残るようにするため
- バックアップは**オフライン（または変更不可）の場所に**保存し、定期的に復元テストもする（ランサムウェア対策）

**運用**
- 公的機関や有名企業がAIによる攻撃に狙われているのは、主に「公開されている脆弱性を、修正されるまでの間に突く」攻撃です。nethergateは時間稼ぎにはなりますが、**パッチを早く当てるのが一番効きます**
- AIが作ったレポートは必ずユーザーが確認してから、abuse窓口への連絡や警察・JPCERT/CCへの届け出を判断してください

## 法的な範囲について
- `enrich_ip` は公開されているレジストリや公開データベースを照会するだけで、**攻撃者の機器への接続・スキャン・反撃は一切しません**。この方針を変える拡張（ポートスキャンやハックバック）は、不正アクセス禁止法などに触れるおそれがあるので入れないでください
- 自分が管理しているサーバーにだけ導入してください

## 開発

```bash
go test -race -short ./...                       # 単体テスト
go test ./e2e                                    # 結合テスト：実際のバイナリを偽の nft で動かす
./scripts/fuzz.sh 30s                            # 全ファジング対象を各30秒
go run ./cmd/nethergate -config cfg.json scan    # 現在のインシデントをJSONで表示
go run ./cmd/nethergate -config cfg.json verify  # 監査ログの改ざんチェック
```

- **結合テスト**（`e2e/`）：enforcer・watch・mcp・CLI を本物のソケットでつなぎ、次を確認する
  - ルールによる自動ブロック
  - 乗っ取られたAIを想定した直接リクエストが、enforcer で拒否される
  - 監査ログが書けないときはファイアウォールを変更しない
  - 記録書の提案 → 承認 → 即ブロック
  - ユーザーによる誤ブロックの訂正
  - SIEM への転送とメトリクスの公開
  - アンカーと改ざん通知による、ログ切り詰めの検出
- **ファジング**：ログの読み取り（送信元IPが攻撃者の書いた部分に左右されないこと）、無害化、記録書・教訓・設定・監査ログ・MCP・enforcer のリクエスト。問題が見つかった入力は `testdata/fuzz/` に保存され、以後のテストで毎回確認される
- **CI**（GitHub Actions）：push のたびに gofmt・vet・race・結合テスト・短時間のファジング。毎晩、全ファジング対象を各5分

## 作者・ライセンス

- 作者：**Michitaka Kurahashi**
- ライセンス：[MIT License](LICENSE) © 2026 Michitaka Kurahashi
  - 自由に利用・改変・再配布できますが、著作権表示（作者名）とライセンス文は残してください
