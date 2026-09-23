# ssh-hop

**给 AI 用的 SSH / SFTP 代理。** 本机 stdio MCP 服务，AI 只认**别名**，凭据永远留在本机进程里。

局域网自用、单人使用、无端口、无容器、无守护进程。每次工具调用复用（或新建）一条 SSH 连接，
执行完就返回。附带一个功能等价的命令行工具。

```
AI 客户端  ──stdio──►  ssh-hop  ──SSH/SFTP──►  hosts.json 里配置的机器
  (只看得到别名)          (凭据唯一的持有者)
```

支持 Cherry Studio / Claude Code / Codex / Cursor 等任何 MCP 客户端，以及 OMP。

---

## 目录

- [为什么需要它](#为什么需要它)
- [安装](#安装)
- [快速开始](#快速开始)
- [配置 hosts.json](#配置-hostsjson)
- [命令权限（正则）](#命令权限正则)
- [客户端接入](#客户端接入)
- [AI 可用的 8 个工具](#ai-可用的-8-个工具)
- [命令行用法](#命令行用法)
- [安全边界](#安全边界)
- [常见问题](#常见问题)
- [开发](#开发)

---

## 为什么需要它

直接让 AI 连 SSH 有几个现实问题：

| 问题 | ssh-hop 的做法 |
|---|---|
| 把 IP、账号、密码写进提示词 | 写进本机 `hosts.json`，AI 只看到 `ubuntu-01` 这样的别名 |
| AI 可能连错机器 | 别名精确匹配，写错直接报错并列出可用别名，绝不模糊匹配 |
| 每次都要重新握手，很慢 | 连接池复用，空闲 30 秒内不再握手 |
| 不知道 AI 到底执行了什么 | 每次远程操作追加一行 JSON 审计日志，自动脱敏 |
| 有的机器不想让它改 | 每台机器单独配置命令正则白名单/黑名单 |

---

## 安装

需要 **Python 3.10+**。推荐用 [`uv`](https://docs.astral.sh/uv/)（会把依赖装进独立环境，不污染系统 Python）。

### 方式一：从源码装（推荐，可改代码）

```bash
git clone https://github.com/onlineY/ssh-mcp.git
cd ssh-mcp
uv tool install .
```

会生成两个命令：`ssh-hop`（命令行）和 `ssh-hop-mcp`（MCP 服务）。

### 方式二：不装，直接跑

```bash
git clone https://github.com/onlineY/ssh-mcp.git
cd ssh-mcp
uv venv && uv pip install -e .
```

然后用 `.venv/Scripts/python.exe -m ssh_hop`（Windows）或 `.venv/bin/python -m ssh_hop`（Linux/macOS）当 MCP 命令。

### 方式三：从 Release 装

到 [Releases](https://github.com/onlineY/ssh-mcp/releases) 下载 `.whl` 文件：

```bash
uv tool install ./ssh_hop-0.1.0-py3-none-any.whl
```

### 安装后会得到什么

| 项目 | 路径 |
|---|---|
| 命令入口 | `~/.local/bin/ssh-hop`、`~/.local/bin/ssh-hop-mcp` |
| 程序本体 | `%APPDATA%\uv\tools\ssh-hop\`（Windows）/ `~/.local/share/uv/tools/ssh-hop/`（Linux） |

验证：

```bash
ssh-hop --version
```

---

## 快速开始

```bash
# 1. 生成配置文件
ssh-hop init

# 2. 编辑它，填入真实的主机、账号、密码（或密钥路径）
#    Windows:  C:\Users\<你>\.ssh-hop\hosts.json
#    Linux:    ~/.ssh-hop/hosts.json

# 3. 校验格式（不连网）
ssh-hop check

# 4. 校验 + 真实连接测试
ssh-hop check --connect

# 5. 试一条命令
ssh-hop run ubuntu-01 'uname -a'
```

`check --connect` 成功的样子：

```
hosts file OK: C:\Users\me\.ssh-hop\hosts.json (2 host(s))
  ubuntu-01        ok   1197ms  Linux app 6.8.0-1062-azure ... x86_64 GNU/Linux
  nas              ok    120ms  Linux nas 5.10.0 ... aarch64 GNU/Linux
```

---

## 配置 hosts.json

默认位置：**`~/.ssh-hop/hosts.json`**（Windows 是 `C:\Users\<你>\.ssh-hop\hosts.json`）。

查找顺序：`--hosts-file` 参数 → 环境变量 `SSH_HOP_HOSTS` → 当前目录 `./hosts.json` → `~/.ssh-hop/hosts.json`。

### 最小配置

```jsonc
{
  "hosts": {
    "ubuntu-01": {
      "host": "192.168.1.10",
      "user": "deploy",
      "password": "你的密码"
    }
  }
}
```

### 完整示例

```jsonc
{
  "defaults": {
    "port": 22,
    "timeout": 60,
    "connectTimeout": 10,
    "netTimeout": 20,
    "idleReuseSec": 30,
    "knownHosts": "auto-add",
    "allowCommands": ["*"],
    "denyCommands": []
  },

  "hosts": {
    "ubuntu-01": {
      "desc": "Ubuntu 应用服务器，docker compose 在 /opt/app",
      "host": "192.168.1.10",
      "user": "deploy",
      "password": "你的密码",
      "defaultCwd": "/opt/app"
    },

    "nas": {
      "desc": "NAS，用密钥登录",
      "host": "192.168.1.20",
      "user": "admin",
      "keyFile": "C:/Users/me/.ssh/id_ed25519",
      "passphrase": null
    },

    "router": {
      "desc": "路由器，只准看不准改",
      "host": "192.168.1.1",
      "user": "root",
      "password": "你的密码",
      "allowCommands": [
        "^(logread|ubus|uci|ip|iw|df|free|ps|cat|ls|tail|grep|uname)\\b"
      ],
      "denyCommands": ["(sysupgrade|firstboot|mtd)"],
      "allowUpload": false
    }
  }
}
```

### 字段说明

`defaults` 里的每一项都可以被单台主机覆盖。

| 字段 | 默认值 | 说明 |
|---|---|---|
| `host` | — | **必填**。IP 或域名 |
| `user` | — | **必填**。登录用户名 |
| `password` | — | 密码认证。和 `keyFile` 二选一 |
| `keyFile` | — | 私钥路径（**不是 `.pub`**）。两个都写时**密钥优先** |
| `passphrase` | — | 私钥有密码时填 |
| `desc` | `""` | 给 AI 看的说明。想隐藏就不要写 IP/账号 |
| `port` | `22` | SSH 端口 |
| `defaultCwd` | — | 每条命令前自动 `cd` 到这里 |
| `timeout` | `60` | 单条命令超时秒数（上限 1800） |
| `connectTimeout` | `10` | TCP / 认证超时秒数 |
| `netTimeout` | `20` | **整次握手的硬上限**，防止对端卡住导致永久挂起 |
| `idleReuseSec` | `30` | 空闲多久内复用连接；`0` = 每次重连 |
| `allowCommands` | `["*"]` | 命令白名单正则，`*` = 全部允许 |
| `denyCommands` | `[]` | 命令黑名单正则，**优先级高于白名单** |
| `allowUpload` / `allowDownload` | `true` | 是否允许传文件 |
| `uploadRoots` / `downloadRoots` | `[]` | 远端可写/可读目录；**空 = 任意路径** |
| `localRoots` | `[]` | 本地可读写目录；**空 = 任意路径** |
| `knownHosts` | `auto-add` | `auto-add` / `strict` / `ignore` |
| `shell` | `sh` | 执行 `background` 任务和 `cd` 包装用的 shell |
| `env` | `{}` | 每条命令前注入的环境变量 |
| `tags` | `[]` | 自由标签，会返回给 AI |

### 两种认证方式

```jsonc
// 密码
{ "user": "deploy", "password": "hunter2" }

// 密钥（私钥路径，不是 .pub）
{ "user": "deploy", "keyFile": "C:/Users/me/.ssh/id_ed25519" }

// 密钥 + 私钥密码
{ "user": "deploy", "keyFile": "/home/me/.ssh/id_rsa", "passphrase": "xxxx" }
```

> **踩坑提醒**
> - Windows 路径用正斜杠 `/` 或双反斜杠 `\\`；单个 `\` 在 JSON 里是转义符，会解析失败。
> - 程序**拒绝** `REPLACE_ME` / `CHANGE_ME` / `your-password` 这类占位符，防止你忘了改就能连上。
> - `hosts.json` 是明文凭据，**不要提交到 git**（仓库的 `.gitignore` 已经排除）。

---

## 命令权限（正则）

默认 `["*"]`，**什么都不限制**。需要收窄时用正则：

| 写法 | 含义 |
|---|---|
| `"*"` 或 `""` | 全部允许（默认） |
| `"^docker\\b"` | 只允许以 docker 开头的命令 |
| `"^systemctl (start\|stop\|restart\|status) (nginx\|postgresql)$"` | 精确到一条 |
| `"docker"` | **任意位置**含 docker 就放行（`sudo docker ps` 也命中） |

规则细节：

- 用 `re.search` 匹配**整条命令**，开启 `DOTALL`（`.` 能跨行，所以裸 `*` 也能匹配多行的 heredoc）。
- 想钉住整条命令就用 `^` / `$` 锚定。
- **每个列表里第一条命中的规则生效**；**`denyCommands` 先判，永远压过 `allowCommands`**。
- 没命中任何白名单规则就拒绝，报错信息会**列出你配置的规则**，AI 一步就能自查。
- 白名单写成空列表会回退成 `["*"]`，避免把自己锁死。
- 正则写错会在**加载 `hosts.json` 时**报错，不会等到执行才炸。

### 不改配置也能先查

不想真跑，只想问"这条命令会不会被放行"：

```bash
ssh-hop classify router 'reboot'
```

```
host:      router
command:   reboot
verdict:   refused
reason:    refused on 'router': matches denyCommands rule '(sysupgrade|firstboot|mtd)'...
allow:     '^(logread|ubus|uci|ip|iw|df|free|ps|cat|ls|tail|grep|uname)\\b'
deny:      '(sysupgrade|firstboot|mtd)'
```

MCP 里对应 `ssh_run_policy` 工具，同样**不连网、不执行**。

---

## 客户端接入

通用做法：MCP 客户端按 `命令 + 参数 + 环境变量` 拉起一个子进程，用 stdio 说 JSON-RPC。
下面是各客户端的配置位置和写法（把路径换成你自己的）。

### Cherry Studio

设置 → MCP 服务器 → 添加。类型选 `stdio`，命令填 `ssh-hop-mcp.exe` 的完整路径。

> Cherry Studio 把 MCP 配置存在 SQLite 里（`%APPDATA%\CherryStudio\Data\cherrystudio.sqlite` 的 `mcp_server` 表），**没有 JSON 文件可编辑**，所以只能在界面里加。

### Claude Code

```bash
claude mcp add ssh-hop --scope user \
  -e SSH_HOP_HOSTS="C:/Users/你/.ssh-hop/hosts.json" \
  -- "C:/Users/你/.local/bin/ssh-hop-mcp.exe"
```

验证：`claude mcp list` 应显示 `✓ Connected`。

### Codex

编辑 `~/.codex/config.toml`：

```toml
[mcp_servers.ssh-hop]
command = "C:/Users/你/.local/bin/ssh-hop-mcp.exe"
env = { SSH_HOP_HOSTS = "C:/Users/你/.ssh-hop/hosts.json" }
startup_timeout_sec = 30
tool_timeout_sec = 300
```

验证：`codex mcp list`。

### Cursor / Claude Desktop / 其他

```json
{
  "mcpServers": {
    "ssh-hop": {
      "command": "C:/Users/你/.local/bin/ssh-hop-mcp.exe",
      "env": { "SSH_HOP_HOSTS": "C:/Users/你/.ssh-hop/hosts.json" }
    }
  }
}
```

- Cursor：`~/.cursor/mcp.json`
- Claude Desktop：`%APPDATA%\Claude\claude_desktop_config.json`

### OMP

编辑 `~/.omp/agent/mcp.json`：

```json
{
  "mcpServers": {
    "ssh-hop": {
      "type": "stdio",
      "command": "C:/Users/你/.local/bin/ssh-hop-mcp.exe",
      "env": { "SSH_HOP_HOSTS": "C:/Users/你/.ssh-hop/hosts.json" }
    }
  }
}
```

> **路径要点**：`--hosts-file` 之外的路径请用**绝对路径 + 正斜杠**。
> 环境变量 `SSH_HOP_HOSTS` 指定配置文件，`SSH_HOP_HOME` 指定审计日志和 host key 的存放目录。
> 即使一个环境变量都不传，也能自动找到 `~/.ssh-hop/hosts.json`。

改完配置**要重启客户端**，它才会重新读取工具列表。

---

## AI 可用的 8 个工具

| 工具 | 作用 |
|---|---|
| `ssh_list_hosts` | 列出所有别名、说明、命令规则、传输策略。**AI 应先调它** |
| `ssh_probe` | 测试连通性，返回 `uname` / `uptime` / `id` 和延迟。用于排查"连不上" |
| `ssh_run` | 执行 shell 命令，返回 stdout / stderr / 退出码 / 耗时。`background: true` 用于守护类命令 |
| `ssh_run_policy` | 只判断命令会不会被放行、命中哪条规则，**不执行** |
| `ssh_run_many` | 同一命令并行跑多台，逐台返回结果 |
| `sftp_upload` | 上传本地文件/目录到远端 |
| `sftp_download` | 下载远端文件/目录到本地 |
| `sftp_list` | 列远端目录，或 stat 单个文件 |

失败时返回结构化结果，而不是抛异常堆栈，方便 AI 自行纠正：

```json
{ "ok": false, "error": "refused on 'router': matches denyCommands rule ...", "kind": "refused" }
```

`kind` 取值：`refused`（权限拒绝） / `ssh`（连接或远端错误） / `config`（配置问题） / `unknown-host` / `usage` / `internal`。

---

## 命令行用法

不开 MCP 客户端也能用，功能等价：

```bash
# 列主机和它们的策略
ssh-hop ls

# 修命令能不能跑（不连网）
ssh-hop classify router 'reboot'

# 执行命令
ssh-hop run ubuntu-01 'docker compose ps'

# 后台执行长任务，返回 pid 和日志路径
ssh-hop run ubuntu-01 'nohup ./deploy.sh > /tmp/deploy.log 2>&1 & echo started' --background

# 传文件
ssh-hop put ubuntu-01 ./dist/app.tar.gz /opt/app/app.tar.gz
ssh-hop get ubuntu-01 /var/log/syslog ./syslog --json

# 列远端目录
ssh-hop rls ubuntu-01 /opt/app

# 校验配置
ssh-hop check --connect

# 生成配置模板
ssh-hop init
```

退出码：`0` 成功 / 其他为命令退出码 / `1` 连接或配置错误 / `2` 被策略拒绝。

---

## 安全边界

**凭据不外泄**

- AI 的工具返回里**没有** IP、端口、用户名、密码、密钥路径。
- 别名**精确匹配**，写错就报错并列出可用别名，不会连错机器。

**审计**

- 每次远程操作追加一行 JSON 到 `~/.ssh-hop/audit.jsonl`，`password=` / token 自动脱敏。
- 用 `SSH_HOP_HOME` 可改存放位置。

**传输**

- 远端 host key 记入 `~/.ssh-hop/known_hosts`（首次遇到新 key 时创建），同时尊重 `~/.ssh/known_hosts`。
- `auto-add`（默认）会接受没见过的 key 并记下来——新装的路由器必须这样；但记下来之后**密钥变了就会硬失败**并给出处理指引。
- `strict` 模式只接受已知 key。

**这不是沙箱**

命令策略只是一道**正则闸门**——规则只决定这条命令**发不发出去**，发出去之后就是**你账号的完整权限**。
要真正的隔离，请用受限账号、`sudo` 规则或容器。

---

## 常见问题

**Q：为什么都是 npm 的 MCP，Python 怎么让 AI 启动？**

MCP 本质就是"用 stdio 跑一个子进程说 JSON-RPC"，客户端**不关心**是 node 还是 python。
npm 生态多是因为它由 Anthropic 的 TS SDK 起步、`npx -y` 能免安装运行。

Python 的区别只有一个：**依赖要先装好**（`npx` 会自动下载，python 不会）。
所以别用裸 `python`，而是用 `uv tool install` 把依赖固化成一个可执行文件
（`~/.local/bin/ssh-hop-mcp.exe`），客户端直接拉起它，**不需要你手动激活任何虚拟环境**。

**Q：会每条命令都重新建连接吗？**

不会。**一台主机保持一条连接，空闲 30 秒内复用**。实测：

| 场景 | 耗时 |
|---|---|
| 冷启动（新建 SSH） | 1522 ms |
| 复用中 | 287–520 ms |
| 空闲超窗后重连 | 1318 ms |

想更激进地复用，把 `idleReuseSec` 调大即可（比如 `600` 表示 10 分钟）。

**Q：连不上，怎么排查？**

```bash
ssh-hop probe <别名>
```

会返回 `uname` / 延迟 / SSH 服务端版本。如果报 `netTimeout ... exceeded`，说明握手卡住了
（对端没发 SSH banner），可以调大 `netTimeout`。

**Q：为什么 `uuidgen` 这种命令被拒绝了？**

说明那台主机配了 `allowCommands` 白名单，而 `uuidgen` 不在里面。用 `ssh-hop classify <别名> '<命令>'`
看是哪条规则拦的，或者把 `"*"` 加进该主机的 `allowCommands`。

**Q：连接偶尔断，命令会执行两次吗？**

不会。只有当**命令还没送到远端**（连接在网络层就死了）才会自动重连重试一次；
一旦命令已经发出，**绝不重试**，避免重复执行。重试过会在返回里带一条 `warnings` 提示。

**Q：改了 `hosts.json` 要重启客户端吗？**

`ssh-hop` 命令行立即生效；MCP 客户端需要重启（它会缓存工具列表）。若客户端传了环境变量，
改完配置重启即可。

---

## 开发

```bash
git clone https://github.com/onlineY/ssh-mcp.git
cd ssh-mcp
uv venv
uv pip install -e ".[dev]"

# 跑测试
.venv/Scripts/python.exe -m pytest        # Windows
.venv/bin/python -m pytest                # Linux/macOS

# 静态检查
uv pip install pyflakes
.venv/Scripts/python.exe -m pyflakes src/ssh_hop/*.py tests/*.py
```

### 项目结构

```
src/ssh_hop/
  config.py   hosts.json 加载与校验、按主机的策略
  guard.py    命令正则策略、路径收敛、输出截断
  client.py   连接池、执行、SFTP、审计（凭据只存在这里）
  server.py   MCP 服务，8 个工具
  cli.py      命令行
tests/
  fake_ssh.py 进程内 SSH 服务器（真实 paramiko 传输层 + SFTP 子系统）
```

测试用 `tests/fake_ssh.py` —— 一个跑在临时目录里的**真实 SSH 服务器**
（真的 SSH 传输层、真的 SFTP 子系统、一个小型 shell 解释器），
所以 SSH/SFTP/MCP 全链路都能端到端验证，**不需要真机**。

### 发布新版本

改 `pyproject.toml` 里的 `version`，然后：

```bash
git tag v0.1.1
git push origin v0.1.1
```

GitHub Actions 会自动跑测试、构建 wheel、创建 Release 并附上 `.whl` 文件。

---

## 许可证

[MIT](LICENSE)
