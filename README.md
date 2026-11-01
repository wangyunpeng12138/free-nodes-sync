# free-nodes-sync

把 [Hidashimora/free-vpn-anti-rkn](https://github.com/Hidashimora/free-vpn-anti-rkn) 的**明文 txt 节点列表**转换成 **Clash / mihomo 订阅配置**，并在上游更新时自动重新生成。

上游只提供 `vless://`、`vmess://` 这类明文链接，Clash 系客户端不能直接导入；本项目负责解析、清洗、去重，产出可直接被 mihomo 加载的 YAML 订阅。

- 纯 Python 3 标准库，零第三方依赖，Windows / macOS / Linux 直接跑
- 支持 vless / vmess / trojan / ss / hysteria2 / hysteria / tuic
- 输出完整配置：`proxies` + `proxy-groups` + `rules` + `dns`
- 内容没变化就不写盘，适合挂定时任务和 CI

---

## 目录

- [数据源：源仓库结构](#数据源源仓库结构)
- [转换方法](#转换方法)
- [快速开始](#快速开始)
- [自动同步](#自动同步)
- [订阅地址](#订阅地址)
- [参数](#参数)
- [项目结构](#项目结构)
- [已知限制](#已知限制)

---

## 数据源：源仓库结构

**源仓库**：`git@github.com:Hidashimora/free-vpn-anti-rkn.git`（分支 `main`）

```
free-vpn-anti-rkn/
├── configs/                  # ← 本项目的数据来源
│   ├── 1.txt                 # 单文件订阅
│   ├── 1.1.txt … 1.26.txt    # 来源 1 的 26 个分片
│   ├── 2.1.txt / 2.2.txt     # N.1 = 短订阅，N.2 = 全量
│   ├── 27.txt … 34.txt       # 另一批来源
│   └── vpn.txt
├── index.html                # 订阅导航页
└── README.md
```

### 文件命名规则

| 文件 | 含义 |
|---|---|
| `N.txt` | 单个来源的订阅（部分来源只有这一种） |
| `N.1.txt` | 该来源的**短订阅**：节点超过 300 时按每 4 行取 1 行采样，最多 300 条 |
| `N.2.txt` | 该来源的**全量列表**：所有节点，可能有上万条，客户端容易卡顿 |

短订阅是为了让手机端不至于加载上万个节点而做的采样，本项目默认只转换 `N.txt` 和 `N.1.txt`，跳过 `N.2.txt`（可通过 `config/sources.json` 的 `select.exclude` 调整）。

### 上游的上游

源仓库本身是聚合器，数据来自两个原始项目：

| 编号 | 原始来源 | 说明 |
|---|---|---|
| 1–26 | [AvenCores/goida-vpn-configs](https://github.com/AvenCores/goida-vpn-configs) | 按协议/地区拆成 26 个列表 |
| 27–34 | [igareck/vpn-configs-for-russia](https://github.com/igareck/vpn-configs-for-russia) | 面向俄罗斯网络的列表，含 `BLACK_VLESS_RUS`、`WHITE-CIDR-RU-*` 等 |

源仓库每分钟检查一次上游变化，所以本项目用 30 分钟一次的定时任务跟进即可。

### 原始数据长什么样

`configs/1.1.txt` 的真实内容（每行一个节点，第一行是注释）：

```
# Подписка 1.1.txt | OpenRay (короткий)
vless://e5cc16a6-ea42-46b2-82ae-ad2157e1641b@188.114.97.6:8080?security=none&type=ws&host=hhlfy.twiladaphne.ndjp.net&path=/&fm={#%5BOpenRay%5D%20%F0%9F%87%A8%F0%9F%87%A6%20CA-28717
trojan://humanity@104.17.148.22:443?security=tls&sni=www.calmlunch.com&type=ws&host=www.calmlunch.com&path=%2Fassignment&allowInsecure=0#%5BOpenRay%5D%20CA-29153
vmess://eyJhZGQiOiIxNTguMTYwLjE4MC4xNjUiLCJhaWQiOiIwIiwiaWQiOiJjNThjMTIwNS1i...
ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTprMWRCT21PQjRvcWk3VW1wMzdhMWJR@82.38.31.184:8080#NL
```

节点名在 `#` 之后，是 URL 编码的，解码后带 emoji 和地区信息。

---

## 转换方法

### 整体流程

```
上游 configs/*.txt
      │  ① 多镜像下载（raw → jsDelivr → ghproxy 依次回退）
      ▼
   cache/*.txt            # 原始文本落地，便于离线重跑
      │  ② 逐行扫描 → 拆分粘连行 → 协议嗅探 → 按协议解析
      ▼
  Python dict（mihomo proxy 结构）
      │  ③ 字段校验 + 清洗 + 按指纹去重 + 节点名唯一化
      ▼
  ④ 生成配置：proxies + proxy-groups + rules + dns
      │  ⑤ 自写 YAML 序列化（不依赖 PyYAML），内容未变则不落盘
      ▼
  output/all.yaml  +  output/sources/<源名>.yaml
```

核心逻辑都在 [`src/txt2clash.py`](src/txt2clash.py) 一个文件里，可以直接拷走单独使用。

### 协议解析与字段映射

各协议的 URI 参数映射到 mihomo 字段的规则：

**vless**（占比最高）

| 链接参数 | mihomo 字段 | 说明 |
|---|---|---|
| `uuid@host:port` | `uuid` / `server` / `port` | — |
| `security=tls` / `reality` / `none` | `tls: true/false` | reality 额外写 `reality-opts` |
| `sni` | `servername` | — |
| `fp` | `client-fingerprint` | 白名单校验，`unsafe` 等 Xray 专有值会被丢弃 |
| `pbk` | `reality-opts.public-key` | 必须是 43 位 base64url，否则丢节点 |
| `sid` | `reality-opts.short-id` | 必须是偶数长度 hex（≤16） |
| `flow` | `flow` | 只接受 `xtls-rprx-vision` |
| `type=ws/grpc/tcp/h2/http/xhttp` | `network` + `*-opts` | `httpupgrade` 映射为 `ws` + `v2ray-http-upgrade: true` |
| `host` | `ws-opts.headers.Host` / `h2-opts.host` | — |
| `path` | `ws-opts.path` 等 | 自动 URL 解码 |
| `serviceName` | `grpc-opts.grpc-service-name` | — |
| `allowInsecure` / `insecure` | `skip-cert-verify: true` | — |
| `alpn` | `alpn` 数组 | 逗号分隔拆分 |

**vmess**：`vmess://` 后是 base64 的 JSON，取 `add/port/id/aid/scy/net/host/path/tls/sni/fp/alpn` 映射；`scy` 不在 `auto|aes-128-gcm|chacha20-poly1305|none|zero` 里时回落为 `auto`。

**trojan**：`password@host:port`，TLS 强制开启，`sni` / `type` / `path` / `host` 规则同 vless。

**ss**：兼容三种写法 —— `ss://base64(method:pass)@host:port`、`ss://base64(method:pass@host:port)`、明文 `ss://method:pass@host:port`；`plugin` 支持 `obfs` 和 `v2ray-plugin`。加密方式走白名单，`chacha20-poly1305` 这类常见误写会自动纠正为 `chacha20-ietf-poly1305`。

**hysteria2 / hysteria / tuic**：`auth`→`password`、`peer`→`servername`、`upmbps/downmbps`→`up/down`、`congestion_control`→`congestion-controller`。

### 数据清洗与容错

上游数据相当脏，下面这些情况都做了处理，否则会让**整份配置**被内核拒绝加载：

| 问题 | 处理方式 |
|---|---|
| `ss://` 前缀实际是 vless / vmess 内容 | 按内容嗅探纠正协议（裸 UUID → vless，base64 JSON → vmess） |
| 链接用 `&amp;` 而不是 `&`（从 HTML 页面抓取） | 解析前统一还原，否则所有 query 参数会被吞进第一个参数 |
| 多个链接粘在同一行 | 用 `(?=(?:vless\|vmess\|…):\/\/)` 前瞻切分 |
| 链接尾部带 `/`（`:443/?type=ws`） | host:port 用正则提取，不受影响 |
| ss 加密方式非法（`null`、`TelegramChannel`、UUID） | 白名单校验，不合法直接跳过该节点 |
| reality 公钥/short-id 格式非法 | 校验长度和字符集，非法跳过 |
| `flow` 值被截断（`xtls-rprx-visi…`） | 只认完整值，其余忽略该字段但保留节点 |
| 节点名含控制字符 | 过滤 `\x00-\x1f`，否则 YAML 报 `control characters are not allowed` |
| 节点重名 | 追加序号，Clash 要求 proxy 名唯一 |
| 截断/残缺的行 | 跳过并计入 `counts.json` 的 `skipped` |

跳过的条目都会在 `counts.json` 里按原因计数，方便判断是上游数据问题还是解析器问题。

### 去重与命名

- 去重指纹：`type|server|port|凭据|network|servername`，同一节点在多个文件里只保留一份
- 分源订阅的节点名保持上游原样（含 emoji）
- 合并订阅会给节点加来源前缀：`[1.1] 🇨🇦 CA-28717`，方便判断出处

### 生成的配置结构

```yaml
mixed-port: 7890
mode: rule
dns: { ... }              # fake-ip + 国内 DoH，避免 DNS 泄漏
proxies: [ ... ]          # 解析后的节点
proxy-groups:
  - 🚀 节点选择            # select，含「自动选择 / DIRECT / 各来源分组 / 所有节点」
  - ♻️ 自动选择            # url-test，按延迟自动切换
  - 📡 <源名>              # 合并订阅里每个来源一个 url-test 分组
rules:
  - GEOIP,LAN,DIRECT,no-resolve
  - GEOIP,CN,DIRECT
  - MATCH,🚀 节点选择
```

---

## 快速开始

```bash
# 全量：拉取上游所有短订阅并转换
python src/txt2clash.py

# 只转某几个源
python src/txt2clash.py --only 1.1,5.1,27

# 离线：用本地已下载的 txt
python src/txt2clash.py --local cache

# 只要合并订阅，不出分源
python src/txt2clash.py --no-merged
```

Windows 直接双击 `run.bat`，Linux/macOS 用 `./run.sh`。

产物：

| 文件 | 说明 |
|---|---|
| `output/all.yaml` | 合并订阅（去重后截断到 800 节点，按来源分组） |
| `output/sources/<源名>.yaml` | 单源订阅，如 `output/sources/1.1.yaml` |
| `output/counts.json` | 各订阅节点数、生成时间、跳过统计 |
| `cache/*.txt` | 上游原始文本缓存 |

本地生成的 `output/all.yaml` 可以直接拖进 Clash Verge Rev / ClashX Meta 当本地配置用；想让它自动更新就走下面的方案。

### 镜像与网络

下载默认按 `raw → jsdelivr → jsdelivr-fastly → ghproxy` 顺序尝试，任一成功即用。国内直连 raw 经常不通：

```bash
python src/txt2clash.py --mirror jsdelivr
```

代理默认读系统环境变量（`HTTPS_PROXY` / `HTTP_PROXY`）。如果系统代理本身不稳、报 `Tunnel connection failed: 502`，用 `--proxy no` 强制直连；也可以 `--proxy http://127.0.0.1:7890` 显式指定。

> jsDelivr 对 `@main` 引用有缓存（通常数小时），追求实时性时优先用 raw。

---

## 自动同步

[`.github/workflows/sync-subscriptions.yml`](.github/workflows/sync-subscriptions.yml) 会**每 30 分钟**拉上游、转换、有变化才提交，客户端只要填一个固定地址就能一直拿到最新节点。

本仓库已启用，无需额外操作。fork 或新建仓库时需要开启：

1. 仓库必须是 **public**，否则客户端拉不到订阅
2. **Settings → Actions → General → Workflow permissions** 选 **Read and write**
3. **Actions** 页面点 **Enable workflow**，手动 Run 一次 `sync-subscriptions` 验证
4. 客户端填 [订阅地址](#订阅地址)，Clash 会自动按间隔拉取

### 本地定时（不用 Actions）

Windows 任务计划程序 → 新建任务 → 触发器「每 30 分钟」→ 操作指向 `run.bat`；Linux 用 crontab：

```cron
*/30 * * * * cd /path/to/free-nodes-sync && ./run.sh >> sync.log 2>&1
```

---

## 订阅地址

本项目已部署在 `wangyunpeng12138/free-nodes-sync`，直接复制下面的地址填进客户端：

| 用途 | 地址 |
|---|---|
| **合并订阅（推荐）** | `https://raw.githubusercontent.com/wangyunpeng12138/free-nodes-sync/main/output/all.yaml` |
| 单源订阅 | `https://raw.githubusercontent.com/wangyunpeng12138/free-nodes-sync/main/output/sources/1.1.yaml` |

国内直连 raw 不稳时换镜像：

```
https://cdn.jsdelivr.net/gh/wangyunpeng12138/free-nodes-sync@main/output/all.yaml
https://ghproxy.net/https://raw.githubusercontent.com/wangyunpeng12138/free-nodes-sync/main/output/all.yaml
```

> fork 或改名后，把上面地址里的 `wangyunpeng12138/free-nodes-sync` 换成自己的仓库即可。

---

## 参数

| 参数 | 说明 |
|---|---|
| `--local DIR` | 从本地目录读 txt（离线模式） |
| `--only 1.1,5.1` | 只处理指定源 |
| `--out DIR` | 输出目录，默认 `output` |
| `--no-merged` / `--no-per-source` | 关闭合并订阅 / 关闭分源订阅 |
| `--merged-limit N` | 覆盖合并订阅的节点上限（默认 800） |
| `--jobs N` | 并发下载数，默认 12 |
| `--timeout N` | 单次下载超时秒数，默认 60 |
| `--xhttp drop\|keep` | xhttp 节点丢弃还是保留（默认 keep，需 mihomo v1.19+） |
| `--mirror jsdelivr,raw` | 指定镜像及其顺序 |
| `--proxy URL\|no` | 指定代理，`no` 表示强制直连 |

想改端口、规则、合并上限、要不要包含 `*.2` 全量列表，改 [`config/sources.json`](config/sources.json) 即可。

---

## 项目结构

```
free-nodes-sync/
├── src/txt2clash.py                  # 转换器（单文件，可直接拷走用）
├── config/sources.json               # 上游仓库、镜像、源筛选、合并策略、端口
├── output/                           # 生成物（提交进仓库，供客户端拉取）
│   ├── all.yaml
│   ├── counts.json
│   └── sources/<源名>.yaml
├── cache/                            # 上游 txt 缓存（gitignore）
├── .github/workflows/
│   └── sync-subscriptions.yml        # 定时同步
├── run.bat / run.sh                  # 一键运行
└── README.md
```

---

## 已知限制

- **节点存活率取决于上游**。这些是公开免费节点，失效很快，抽样测延迟大量超时属于正常现象，不代表转换出错。本项目保证的是配置结构合法（每份产物都用 mihomo v1.19 内核 `-t` 校验过）。
- 无法安全转换的条目会被跳过（非法加密方式、缺公钥的 reality、截断行等），数量见 `counts.json`。
- 合并订阅默认截断到 800 个节点，避免客户端卡顿；单源订阅保持上游的 ≤300 条。

### 客户端要求

| 客户端 | 支持情况 |
|---|---|
| mihomo / Clash.Meta（v1.19+） | ✅ 完整支持，含 vless + reality + xhttp |
| Clash Verge Rev / ClashX Meta / FlClash | ✅ |
| Clash for Windows / 原版 Clash Premium | ❌ 不支持 vless |

---

## 免责声明

节点均来自公开渠道，可用性与安全性无保证，本项目只做格式转换，不托管任何节点。仅供学习研究网络协议使用，请遵守当地法律法规。
