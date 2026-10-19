# Pmwiu Tracker List

<!-- META:START -->
![Last Update](https://img.shields.io/badge/更新-待首次运行-blue) ![Trackers](https://img.shields.io/badge/Top_49-待首次运行-brightgreen)
<!-- META:END -->

> 每 24 小时自动更新的 **Top 49** 公共 BitTorrent Tracker 列表 · 真实 announce 测速 · 速度快在前，速度慢在后 · 自动去重 / 去失效 / 去黑名单

> **English** — An auto-updated, speed-ranked list of the **49 best public BitTorrent trackers**. Sources are aggregated daily, measured with real announce probes (BEP-3 / BEP-15), deduplicated, filtered against a blacklist, and published fastest-first. Just subscribe or copy-paste into your client.

---

## ⚡ 快速订阅

**主订阅（Top 49，推荐）：**

```
https://raw.githubusercontent.com/Pmwiu/Pmwiu-Tracker-List/main/trackers_best.txt
```

<details>
<summary>备用镜像地址（raw 不通时换用）</summary>

```
https://cdn.jsdelivr.net/gh/Pmwiu/Pmwiu-Tracker-List/trackers_best.txt
https://fastly.jsdelivr.net/gh/Pmwiu/Pmwiu-Tracker-List/trackers_best.txt
https://gcore.jsdelivr.net/gh/Pmwiu/Pmwiu-Tracker-List/trackers_best.txt
https://cdn.statically.io/gh/Pmwiu/Pmwiu-Tracker-List/main/trackers_best.txt
```

</details>

---

## 📊 Top 49 速度排行榜

<!-- LEADERBOARD:START -->
> 🚀 排行榜将在首次自动更新后生成，每 24 小时刷新。
<!-- LEADERBOARD:END -->

---

## 📁 列表文件一览

| 文件 | 说明 | 直链 |
| --- | --- | --- |
| `trackers_best.txt` | **Top 49 主订阅**，综合评分最优、快在前 | [下载](https://raw.githubusercontent.com/Pmwiu/Pmwiu-Tracker-List/main/trackers_best.txt) |
| `trackers_all.txt` | 全部存活 Tracker（按速度排序） | [下载](https://raw.githubusercontent.com/Pmwiu/Pmwiu-Tracker-List/main/trackers_all.txt) |
| `trackers_udp.txt` | UDP 协议 Tracker | [下载](https://raw.githubusercontent.com/Pmwiu/Pmwiu-Tracker-List/main/trackers_udp.txt) |
| `trackers_http.txt` | HTTP 协议 Tracker | [下载](https://raw.githubusercontent.com/Pmwiu/Pmwiu-Tracker-List/main/trackers_http.txt) |
| `trackers_https.txt` | HTTPS 协议 Tracker | [下载](https://raw.githubusercontent.com/Pmwiu/Pmwiu-Tracker-List/main/trackers_https.txt) |
| `trackers_ip.txt` | IP 字面量版（免 DNS 解析） | [下载](https://raw.githubusercontent.com/Pmwiu/Pmwiu-Tracker-List/main/trackers_ip.txt) |
| `trackers_i2p.txt` | I2P 网络 Tracker（需 I2P 路由） | [下载](https://raw.githubusercontent.com/Pmwiu/Pmwiu-Tracker-List/main/trackers_i2p.txt) |
| `trackers_yggdrasil.txt` | Yggdrasil 网络 Tracker（需 Yggdrasil 路由） | [下载](https://raw.githubusercontent.com/Pmwiu/Pmwiu-Tracker-List/main/trackers_yggdrasil.txt) |
| `trackers_aria2.txt` | aria2 单行逗号格式（Top 49） | [下载](https://raw.githubusercontent.com/Pmwiu/Pmwiu-Tracker-List/main/trackers_aria2.txt) |
| `stats.json` | 机器可读测速数据（延迟 / 成功率 / 综合分） | [下载](https://raw.githubusercontent.com/Pmwiu/Pmwiu-Tracker-List/main/stats.json) |

---

## 🛠 使用方法

### qBittorrent

`工具 → 选项 → BitTorrent → 自动添加以下 Tracker 到新的下载`，粘贴 `trackers_best.txt` 的全部内容（每行一个）：

```
https://raw.githubusercontent.com/Pmwiu/Pmwiu-Tracker-List/main/trackers_best.txt
```

> 提示：先清空旧 Tracker 列表再粘贴，避免格式错乱。

### aria2

下载 [`trackers_aria2.txt`](https://raw.githubusercontent.com/Pmwiu/Pmwiu-Tracker-List/main/trackers_aria2.txt)，把内容粘贴到 `aria2.conf` 的 `bt-tracker=` 后面：

```
bt-tracker=udp://tracker-a.example:80/announce,udp://tracker-b.example:6969/announce
```

### Transmission

Transmission 没有全局 Tracker 设置，可对单个种子在 `Trackers` 中添加；或使用社区脚本批量注入（见 [ngosang/trackerslist 的第三方工具列表](https://github.com/ngosang/trackerslist#third-party-tools)）。

---

## ⚙️ 更新与筛选机制

- **更新频率**：GitHub Actions 每 24 小时运行一次（UTC 02:23），支持手动触发；每次运行都会重新检索、测速并提交结果。
- **聚合来源**：[ngosang/trackerslist](https://github.com/ngosang/trackerslist) 的 5 个列表（`trackers_best` / `trackers_all_i2p` / `trackers_all_yggdrasil` / `trackers_all_ip` / `trackers_all_yggdrasil_ip`）。
- **测速方式**：真实 Tracker announce 探测——HTTP(S) 按 BEP-3 发起 GET announce，UDP 按 BEP-15 完成 connect + announce 握手；每个 Tracker 探测 3 轮，取成功轮中位延迟。
- **综合评分**：`score = 0.45 × 延迟得分 + 0.30 × 成功率 + 0.10 × 稳定性 + 0.10 × 热度 + 0.05 × 历史在榜加成`；IP 字面量 Tracker 总分 × 0.95。**排序一律快在前、慢在后**。
- **去重规则**：同 URL 去重；同域名只保留最优协议（udp > https > http > ws）；解析到同一 IP 的不同域名只保留一条，域名版优先于 IP 版。
- **过滤规则**：剔除失效（3 轮全失败）、重复、低俗/赌博关键词、黑名单（[`blacklist.txt`](blacklist.txt)，支持精确域名 / 通配后缀 / IP / CIDR / 关键词）以及私网、保留地址的 Tracker。
- **安全边界**：只接受 `udp / http / https / ws / wss` 五种 scheme；Workflow 权限仅 `contents: write`；脚本零第三方依赖（Python 标准库）。
- **兜底保护**：存活 Tracker 少于 30 个时自动中止更新并保留旧列表，防止误发布缩水榜。

---

## 🌐 I2P / Yggdrasil 说明

- I2P Tracker（`*.i2p`）需要 I2P 路由与兼容客户端（如 qBittorrent、BiglyBT、I2PSnark）。
- Yggdrasil Tracker 需要 [Yggdrasil Network](https://yggdrasil-network.github.io/) 路由。
- 这两类 Tracker 位于独立文件，**不参与 Top 49 评选**（托管于 GitHub Actions 的测速节点无法接入这两个特殊网络，测速结果不可信）。

---

## 📜 免责声明与 License

本项目仅聚合公开的公共 Tracker 地址，供学习与研究使用。请遵守当地法律法规，勿用于非法用途；使用本列表产生的任何后果由使用者自行承担。

[MIT License](LICENSE)

---

## 🙏 致谢

- [ngosang/trackerslist](https://github.com/ngosang/trackerslist) — 数据来源
- [XIU2/TrackersListCollection](https://github.com/XIU2/TrackersListCollection) — 格式与使用文档参考
