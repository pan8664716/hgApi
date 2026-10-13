# 搜索接口「不返回数据」定位报告

> 目标：查清 `/reading/bookapi/search/{page,tab,suggest}` 为什么一直返回空。
> 复现：`python3 tools/probe_search.py`（矩阵）/ `--empty`（全量空 body 扫描）
> 日期：2026-10-10

---

## 1. 症状

```
GET /reading/bookapi/search/page/v1/?ss_queries=...&query=斗罗大陆&count=20&offset=0
→ HTTP/2 200   content-length: 0   content-type: application/json      ← 空 body

GET /reading/bookapi/search/tab/v1/?...      → 200  0 B
GET /reading/bookapi/search/suggest/v1/?...  → 200  0 B
```

对照组（同 `service_class=com/dragon/read/rpc/rpc/c$a`、同 `serializer=JSON`）**完全正常**：

```
/reading/bookapi/search/rank_list/v1/   200  13650 B  {"code":0,...,"data":[{"cell_id":0,...
/reading/bookapi/search/user-info/v1/   200  16255 B  {"code":0,"message":"SUCCESS",...
/reading/bookapi/search/hot-search/v1/  200    906 B  {"data":[{"data":"都市",...
/reading/bookapi/bookmall/tab/v1/       200  58023 B  {"code":0,"message":"SUCCESS",...
```

→ 签名链路、ss_queries、域名、网关都没问题，**是这三个端点特有的问题**。

---

## 2. 结论一：**不是 `X-Tt-Token` 缺失**

| 实验 | 结果 |
|---|---|
| 裸请求 | `200  0 B` |
| `X-Tt-Token: AgQAAAAB` | `200  0 B` |
| `Cookie: sessionid=<32hex>` | `200  0 B` |
| `X-Tt-Token` + `Cookie` | `200  0 B` |
| `x-bd-client-key` / `x-bd-kmsv` | `200  0 B` |

三条独立证据说明「空 body ≠ 未登录」：

1. **本 app 的登录态错误是明确的 JSON**，不是空 body：
   - `/app/book/search_chapter/v0/` → `{"code":101,"message":"请先进行登录"}`
   - `/reading/bookapi/reader_settings/load/v1/` → `{"code":101108,"message":"USER_NOT_LOGIN"}`
2. **你自研的 `hongguotv-kotlin` 根本不发 `X-Tt-Token`**（`J0/Y.java` 里只有 `user_is_login=0`，
   全 dex 搜不到任何 token/sessionid 字段），它照样按「有数据」设计解析 `search_tabs`。
3. `search/page` 在参数合法化之后返回的是 **`PARAM_INVALID`（参数问题）**，不是登录问题 ——
   说明它已经越过了任何鉴权检查（见 §4）。

---

## 3. 结论二：空 body 的指纹是「缺少 `X-Tt-Agw-Login` 响应头」

对 120 条 `/reading/*` 路由逐一取头，得到完全对应的关系：

```
(空 body, 有 X-Tt-Agw-Login) → 0 条
(非空,   有 X-Tt-Agw-Login) → 107 条
(空 body, 无 X-Tt-Agw-Login) → 7 条   ← search/page、search/tab、search/suggest、detail、...
```

- 正常接口（含 rank_list / user-info / bookmall）响应里都有 `X-Tt-Agw-Login: 0`；
- 空 body 的接口**一个都没有**这个头；
- 源站确实处理了请求（`X-Dsa-Origin-Status: 200`、`Server-Timing: inner; dur≈20`），
  不是网关超时/拦截。

→ 空 body 表示请求**没被网关当成一次正常业务请求处理**，在框架层就被静默丢弃。

---

## 4. 结论三：关键翻转实验 —— 明文 `device_type`

在 query 里**额外**塞一个明文 `device_type`（`ss_queries` 保持不变），`search/page` 立刻变脸：

```
不加 device_type          → 200   0 B                                        agw-login=False
加 device_type=25053RT47C → 200  53 B  {"code":100103,"message":"PARAM_INVALID"}  agw-login=True
```

对照实验（排除「参数变多/变长」的可能）：

```
+ junk=25053RT47C   → 0 B      （无效）
+ aaa=25053RT47C    → 0 B      （无效）
+ device_type=1     → PARAM_INVALID（有效）
+ device_type=      → 0 B      （空值无效）
重复 6 次           → 6/6 都是 53 B（稳定复现）
```

**含义**：请求只有带上明文 `device_type` 才会被正常识别并进入业务层；
进入业务层后报的是 `PARAM_INVALID`，即**还差一个业务必需参数**（`search/page` 的
`GetSearchPageRequest` 有 55 个字段，我们已逐个试过 40+ 个名字，均未消除该错误）。

注：`search/tab`、`search/suggest`、`bookapi/detail`、`reader/full` 试过 28 种参数名都**无法**翻转，
它们走的是另一条（更早就被丢弃的）路径。

---

## 5. 与自研客户端对照（hongguotv-kotlin 0.9.0）

`A1/C0031d.X()` 是客户端里的 **metasec 重实现**，只有两个端点调用它：

```java
// J0/C0132q.java:1026
X("https://api5-normal-sinfonlineb.fqnovel.com/novel/player/multi_video_model/v1/", Y.f1353a, bytes);
// J0/C0132q.java:1406
X("https://api5-normal-sinfonlinea.fqnovel.com/reading/bookapi/search/tab/v", linkedHashMapQ, null);
```

这两个端点**正好都在我们的「空 body」名单里**。它发出的头是：

```
x-ss-req-ticket / x-tt-request-tag / sdk-version / passport-sdk-version / x-xs-from-web
x-khronos / x-ladon / x-argus / x-gorgon / x-helios / x-medusa / x-tt-dt
```

已按客户端逻辑复现其中确定性部分 → `tools/metasec.py`
（`x-khronos` / `x-ladon` / `x-argus` / `x-gorgon` / `x-ss-req-ticket` 与客户端逐字节一致；
`x-helios` / `x-medusa` 依赖 `S()` 随机数与 300 行 MSManager protobuf，尚未移植）。

**实测：补齐这套头之后 `search/tab` 依旧 0 B，`search/page` 依旧 `PARAM_INVALID`。**
→ metasec 头不是开关（至少不是唯一的开关）。

客户端另外两处与真机不一致，值得先修：

| 项 | 自研客户端 | 红果真机 |
|---|---|---|
| URL | `/reading/bookapi/search/tab/v`（缺版本号） | `/reading/bookapi/search/tab/v1/` |
| 设备指纹 | 完全不发 `ss_queries` | `ss_queries=<base64(ttEncrypt(...))>` |

（`/reading/bookapi/bookmall/tab/v1/` 在**不带** `ss_queries` 时返回 `{"code":110,"message":"ILLEGAL_ACCESS"}`，
说明服务端对 `ss_queries` 至少做「存在性」检查。）

---

## 6. 下一步（按性价比排序）

1. **抓一次真机**（Frida `hook_hongguo.js` 或 Reqable），拿 `search/page` 的真实请求，
   逐字段 diff —— 这是唯一能一锤定音的办法。重点看：
   - query 里到底有没有明文 `device_type`（本次实验的最大嫌疑点）
   - `search_id` / `passback` / `client_ab_info` 的真实取值
   - 是否有我们没覆盖的头
2. 在客户端里**把 `device_type` 明文保留在 query**（不要只塞进 `ss_queries`），先看
   `search/page` 是否从空变成 `PARAM_INVALID` —— 变成 `PARAM_INVALID` 就是进了业务层，
   再按 1 的真实参数补齐。
3. 客户端补 `ss_queries`（`sign_demo.build_request` 已实现），并把 URL 补成 `/v1/`。
4. 若 1 显示真机也没带明文 `device_type`，则考虑服务端对该端点的风控/灰度（
   换 `iid`/`device_id` 为真机值再试）。
