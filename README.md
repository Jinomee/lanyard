# LANyard · 后院联机

**Play Minecraft: Java Edition with friends over the internet — no server, no
port forwarding, no account.** Open your world to LAN, click *Host*, send the
code. Your friend pastes it and your world shows up in their Multiplayer → LAN
list.

**和朋友通过互联网一起玩 Minecraft Java 版——不用服务器、不用端口转发、不用注册。**
对局域网开放你的世界，点“开房”，把联机码发给朋友。朋友粘贴联机码后，你的世界就会出现在他的“多人游戏 → 局域网”列表里。

[English](#english) · [中文](#中文)

> Not an official Minecraft product. Not approved by or associated with Mojang or Microsoft.
> 本软件不是 Minecraft 官方产品，与 Mojang 或微软无关。

---

## English

### Download

Get the latest release from the [Releases page](../../releases). If GitHub is
slow or blocked for you, the same files are on the mirror. The mirror has no
file listing, so use the full address, for example
`https://updates.jinome.org/lanyard/0.1.0/LANyard-0.1.0-windows-amd64-setup.exe`
(replace both version numbers with the one on the Releases page):

* `LANyard-x.y.z-windows-amd64-setup.exe` — installer (recommended: adds the
  Windows Firewall rule, Start-menu entry and `lanyard://` links)
* `LANyard-x.y.z-windows-amd64.exe` — portable, just run it
* `lanyard-core-…` — headless core for Windows/macOS/Linux (advanced)

v1 ships for Windows. The code also builds for macOS and Linux.

### "Windows protected your PC" or an antivirus warning

LANyard is new and **not code-signed yet**. Windows code-signing certificates
cost money, and the free option for open-source projects asks for an
established project first. Until then, Windows and some antivirus programs
are suspicious of it, as they are of most new software.

* **SmartScreen** ("Windows protected your PC"): click **More info**, then
  **Run anyway**. Only do this for files downloaded from this repository's
  [Releases page](../../releases).
* **Antivirus** (360, Tencent PC Manager / 腾讯电脑管家, Huorong / 火绒, Windows
  Defender…): a new program that opens network connections is sometimes
  flagged by mistake. Choose "trust" / "allow" for the file, and please use the
  antivirus's *report a false positive* option. Each report helps the next
  player.
* **Check that your download is genuine.** Every release lists the SHA-256 of
  each file in `SHA256SUMS.txt`. In PowerShell:

  ```powershell
  Get-FileHash .\LANyard-1.0.0-windows-amd64-setup.exe   # compare with SHA256SUMS.txt
  ```

  Take `SHA256SUMS.txt` from the GitHub Releases page: a copy from the same
  mirror as the download proves nothing on its own. If you can't reach
  GitHub, download `SHA256SUMS.txt` and its signature `SHA256SUMS.txt.minisig`
  from the same mirror folder as the installer (for example
  `https://updates.jinome.org/lanyard/0.1.0/SHA256SUMS.txt.minisig`), and
  check the signature with [minisign](https://jedisct1.github.io/minisign/)
  and the LANyard release key (also built into the app, which checks update
  notices the same way). The first pre-release, 0.1.0-rc.1, has no such signature.

  ```
  minisign -Vm SHA256SUMS.txt -P RWQHDXQP4qb/hcqaPHhgkXMW0LvO9nKTV/8Ca/Daqp7g7zvRsLHKhxKW
  ```

  Release files are built by [GitHub Actions](.github/workflows/release.yml)
  directly from the public source code, never on someone's PC.

### Host a world

1. In Minecraft, open your world → **Esc → Open to LAN → Start LAN World**.
2. In LANyard, **Host → Start hosting**. Your world is detected automatically
   (even when Minecraft picks a new port). For a dedicated server on your PC,
   choose *A Minecraft server on this computer* and enter its port.
3. **Copy code** and send it to your friends (WeChat, QQ, Discord…). *Copy link*
   gives a `lanyard://join/…` link for apps that allow it.

### Join a world

1. Copy the code your friend sent. LANyard notices a code on the clipboard and
   offers **Join this world?** Or paste it under **Join**.
2. When it says **Connected**, open Minecraft → **Multiplayer**. The world is
   listed under *Scanning for games on your local network*. You can also use
   **Direct Connection** with the `127.0.0.1:port` address LANyard shows.

**"One more step"**: if your friend's network doesn't accept incoming
connections, your app shows a **reply code** (`LY1R-…`). Send it back; your
friend pastes it under *Host → Did a friend send you a reply code?*. Both apps
then connect at the same moment (hole punching).

### How it works

* Two copies of LANyard connect **directly** to each other over encrypted
  QUIC. They try, in parallel: **IPv6** directly → a **router port mapping**
  (UPnP-IGD / NAT-PMP / PCP) → **UDP hole punching** using public STUN servers
  to learn addresses. The first path that works wins.
* The join code contains the host's possible addresses, a random secret, and
  the fingerprint of the host's certificate. The guest only accepts a host
  whose certificate matches; the host only accepts guests that know the secret.
  Codes expire (24 h by default) and *New code* revokes the old one. Optionally
  the host approves every join.
* On the guest's PC, LANyard listens on `127.0.0.1` and announces the world to
  Minecraft's LAN list. Every connection Minecraft makes is forwarded as-is to
  the host's game. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

### Accounts and online mode

LANyard is a transparent pipe: it never reads, changes or bypasses Minecraft
traffic. Account checks work exactly as on a real LAN. With an "Open to LAN"
world, the host's game decides (vanilla checks Microsoft accounts). With a
dedicated server, its `online-mode` setting applies. LANyard has no feature to
turn authentication off and never will.

### Privacy

* **No servers.** The project runs no relay, matchmaking or rendezvous server.
  Codes are exchanged by you, in any chat app.
* **No telemetry, ever.** Nothing is reported anywhere.
* What leaves your PC: traffic to your friends; small STUN requests to public
  STUN servers (Xiaomi, Bilibili, Douyu, CDNBye, Cloudflare, Google, Nextcloud,
  FreeSWITCH by default; editable) when you host or join, to learn your public
  address; and, if enabled, an update check that downloads a signed version
  file from GitHub or the maintainer's mirror. Nothing is installed automatically.
* *Diagnostics → Export logs* writes a zip you can attach to a bug report
  yourself. It contains IP addresses.

### Limits

* Up to 8 players (host + 7 friends).
* If **both** friends are behind strict NAT (symmetric NAT, common on mobile
  networks and some carrier-grade NAT), or one is strict and the other's router
  only allows exact replies, a direct connection may be impossible. LANyard
  says so in plain language and suggests what to try (let the other person
  host, enable UPnP, use a phone hotspot, use IPv6). A **self-hosted relay**
  for these cases is planned for v1.1. There will never be a project-run relay.
* School and office networks that block UDP won't work.
* Both players need LANyard. Minecraft itself needs no mod.

### Troubleshooting

* *Diagnostics → Test my network* shows your NAT type, IPv6, UPnP and CGNAT
  status and which STUN servers answer.
* Windows asks "Allow access?" the first time you host with the portable exe:
  tick both boxes and allow. The installer adds the rule for you. If you
  clicked *Cancel* earlier, LANyard detects the block rule and shows how to
  fix it.

### Building

```sh
go test ./...                               # unit tests (core is pure Go, no cgo)
go build ./cmd/lanyard-core                 # headless core, any OS
cd gui && wails build -platform windows/amd64 -nsis   # app + installer (Wails v2.16, Node 22, NSIS)
sudo go test -tags natlab ./test/natlab     # NAT matrix in network namespaces (Linux, root)
```

The repository uses LF line endings everywhere (`.gitattributes`). A Windows
checkout made before that rule existed still has CRLF files, which makes
gofmt and `brandsync -check` fail; commit or stash your changes, then run
`git rm --cached -r . && git reset --hard` once to check everything out again
with LF.

The product name lives in one file, `internal/brand/brand.json`; run
`go run ./tools/brandsync` after changing it. Contributions welcome — see
[docs/DECISIONS.md](docs/DECISIONS.md) for design choices and
[docs/RELEASING.md](docs/RELEASING.md) for releases.

License: [GPL-3.0](LICENSE).

---

## 中文

### 下载

在 [Releases 页面](../../releases) 下载最新版本。如果 GitHub 访问很慢或打不开，同样的文件也可以从镜像下载。镜像不提供文件列表，请使用完整地址，例如 `https://updates.jinome.org/lanyard/0.1.0/LANyard-0.1.0-windows-amd64-setup.exe`（把两处版本号都换成 Releases 页面上的版本）：

* `LANyard-x.y.z-windows-amd64-setup.exe` —— 安装包（推荐：会自动添加 Windows 防火墙规则、开始菜单快捷方式和 `lanyard://` 链接支持）
* `LANyard-x.y.z-windows-amd64.exe` —— 绿色版，直接运行
* `lanyard-core-…` —— 无界面核心程序，支持 Windows/macOS/Linux（高级用户）

v1 只发布 Windows 版，代码同样可以在 macOS 和 Linux 上编译。

### Windows 提示“已保护你的电脑”或杀毒软件报毒

后院联机是新软件，**暂时还没有代码签名**：Windows 代码签名证书需要付费，而面向开源项目的免费签名要求项目已有一定知名度。在此之前，Windows 和部分杀毒软件会对它有所警惕（大多数新软件都会这样）。

* **SmartScreen**（“Windows 已保护你的电脑”）：点击 **更多信息**，再点 **仍要运行**。只对从本仓库 [Releases 页面](../../releases) 下载的文件这样做。
* **杀毒软件**（360、腾讯电脑管家、火绒、Windows Defender 等）：会联网的新程序有时会被误报。请选择“信任”或“允许”该文件，并使用杀毒软件里的**误报反馈**功能提交，帮助后面的玩家。
* **确认下载的文件是正版**：每个版本的 `SHA256SUMS.txt` 列出了所有文件的 SHA-256。在 PowerShell 中运行：

  ```powershell
  Get-FileHash .\LANyard-1.0.0-windows-amd64-setup.exe   # 与 SHA256SUMS.txt 对比
  ```

  `SHA256SUMS.txt` 请从 GitHub Releases 页面获取：和安装包来自同一个镜像的副本本身证明不了什么。如果打不开 GitHub，请从镜像上安装包所在的同一个文件夹下载 `SHA256SUMS.txt` 和它的签名 `SHA256SUMS.txt.minisig`（例如 `https://updates.jinome.org/lanyard/0.1.0/SHA256SUMS.txt.minisig`），再用 [minisign](https://jedisct1.github.io/minisign/) 和后院联机的发布公钥（软件内置同一个公钥，用来验证更新通知）检查签名。最早的预发布版 0.1.0-rc.1 没有这个签名。

  ```
  minisign -Vm SHA256SUMS.txt -P RWQHDXQP4qb/hcqaPHhgkXMW0LvO9nKTV/8Ca/Daqp7g7zvRsLHKhxKW
  ```

  所有发布文件都由 [GitHub Actions](.github/workflows/release.yml) 直接从公开源代码构建，不经过任何人的电脑。

### 开房（当房主）

1. 在 Minecraft 中打开你的世界 → **Esc → 对局域网开放 → 创建局域网世界**。
2. 在后院联机中点 **开房 → 开始开房**。世界会被自动识别（Minecraft 换了端口也能跟上）。如果是这台电脑上的独立服务器，选择“这台电脑上的 Minecraft 服务器”并填写端口。
3. 点 **复制联机码** 发给朋友（微信、QQ、Discord 都行）。“复制链接”会得到 `lanyard://join/…` 链接，适用于支持这种链接的软件。

### 加入朋友的世界

1. 复制朋友发来的联机码。后院联机会发现剪贴板里的联机码，并询问 **要加入这个世界吗？** 也可以在 **加入** 页面粘贴。
2. 显示 **连接成功** 后，打开 Minecraft → **多人游戏**，世界会出现在“正在扫描你的本地网络中的游戏”下方。也可以用 **直接连接**，输入后院联机显示的 `127.0.0.1:端口` 地址。

**“还差一步”**：如果朋友的网络不能直接接受外来连接，你的软件会显示一个 **回执码**（`LY1R-…`）。把它发回给朋友，朋友在“开房 → 朋友发来了回执码吗？”处粘贴，双方就会同时发起连接（打洞）。

### 工作原理

* 两个后院联机通过加密的 QUIC **直接**相连，同时尝试：**IPv6 直连** → **路由器端口映射**（UPnP-IGD / NAT-PMP / PCP）→ 借助公共 STUN 服务器的 **UDP 打洞**。哪条路先通就用哪条。
* 联机码里包含房主可能的地址、一个随机密钥和房主证书的指纹。加入方只接受证书匹配的房主；房主只接受知道密钥的朋友。联机码会过期（默认 24 小时），“换一个联机码”会让旧码立即失效。房主也可以选择每次加入都手动同意。
* 在加入方的电脑上，后院联机监听 `127.0.0.1` 并把世界广播到 Minecraft 的局域网列表。Minecraft 的每个连接都被原样转发到房主的游戏。详见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。

### 账号与正版验证

后院联机只是一条透明的管道：从不读取、修改或绕过 Minecraft 的数据。账号验证和真正的局域网完全一样：“对局域网开放”的世界由房主的游戏决定（原版会验证微软账号）；独立服务器则按它的 `online-mode` 设置。后院联机没有、也永远不会提供关闭验证的功能。

### 隐私

* **没有服务器。** 本项目不运营任何中继、匹配或“牵线”服务器，联机码由你自己在任意聊天软件里发送。
* **永远不收集统计数据。**
* 会离开你电脑的数据：发给朋友的游戏数据；开房或加入时发给公共 STUN 服务器（默认：小米、哔哩哔哩、斗鱼、CDNBye、Cloudflare、Google、Nextcloud、FreeSWITCH，可修改）的小请求，用于获知你的公网地址；以及（如果开启）检查更新时从 GitHub 或维护者镜像下载一个带签名的版本信息文件。不会自动安装任何东西。
* “网络诊断 → 导出日志”会生成一个 zip，你可以自己附在问题反馈里。其中包含 IP 地址。

### 限制

* 最多 8 人（房主 + 7 位朋友）。
* 如果**双方**都在严格 NAT 后面（对称型 NAT，常见于手机网络和部分运营商大内网），或者一方严格、另一方的路由器只接受精确回复，可能无法直连。后院联机会用通俗的话说明原因并给出建议（换对方开房、开启 UPnP、用手机热点、使用 IPv6）。计划在 v1.1 支持**自建中继**来解决这类情况。本项目永远不会运营官方中继。
* 屏蔽 UDP 的学校和公司网络无法使用。
* 双方都需要安装后院联机，Minecraft 本身不需要任何模组。

### 常见问题

* “网络诊断 → 测试我的网络”可以查看 NAT 类型、IPv6、UPnP、大内网状态以及哪些 STUN 服务器有响应。
* 使用绿色版第一次开房时，Windows 会询问“是否允许访问”：两个选项都勾上并允许。安装包会自动添加规则。如果之前点了“取消”，后院联机会检测到并告诉你如何修复。

### 编译

见上方英文部分的 *Building*。产品名称只在 `internal/brand/brand.json` 一个文件中定义。

仓库统一使用 LF 换行（`.gitattributes`）。在这条规则加入之前检出的 Windows 工作区仍是 CRLF，会导致 gofmt 和 `brandsync -check` 失败：先提交或暂存你的改动，然后运行一次 `git rm --cached -r . && git reset --hard`，按 LF 重新检出全部文件。

许可证：[GPL-3.0](LICENSE)。
