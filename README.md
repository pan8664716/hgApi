# 红果免费短剧（com.phoenix.read）API 逆向交付包

## 样本

| 项 | 值 |
|---|---|
| 文件 | `novelread_69310258a_v12267_73932_d587_1790271867.apk` |
| SHA-256 | `8869931d5cec8b27a86b35af7a95db40db7a0c9264ff5d278c06a0656ea2a0ab` |
| package | `com.phoenix.read` |
| versionCode / versionName | `73932` / `7.3.9.32` |
| flavor / 构建 | `hongguo` / `b5e187f_20260923` |
| ABI | 仅 `arm64-v8a`（117 个 .so） |
| 结构 | 24 个 dex（约 140 MB），`com.bytedance.covode` 字节码虚拟化 + `bytex` Kotlin 中间层 |

## 交付物

| 文件 | 说明 |
|---|---|
| `hongguo_openapi.yaml` | **OpenAPI 3.0.1**，1106 条路径 / 1161 个 operation，含每个接口的详细参数（JSON 名 + Kotlin 字段 + 类型 + QUERY/BODY）、通用参数、签名头、域名 |
| `hongguo_api.json` | 机器可读全量数据：`records`（接口表）+ `models`（2186 个请求/响应模型的字段表） |
| `hongguo_routes.csv` | 路由总表（group / http / host / path / 服务类 / 方法 / 序列化 / 请求模型 / 响应模型 / 原始注解） |
| `SIGNATURE.md` | **签名与加密算法逆向**（请求流水线、通用参数、`X-SS-QUERIES`/ttEncrypt、`X-SS-REQ-TICKET`、`x-bd-client-key`/`x-bd-kmsv`、`X-SS-STUB`、metasec、KMP RPC URL 组装） |
| `REVERSE_NOTES.md` | 静态侦察记录（域名、库、类、注解、常量），可复现整个逆向过程 |
| `sign_demo.py` | Python 参考实现：通用参数生成、`ss_queries` 加密、完整请求组装、路由查询 |
| `TTENCRYPT.md` | **`libEncryptor.so` / `ttEncrypt` 完整还原**（算法、常量、静态地址表、Unicorn 动态复现、踩坑记录） |
| `libencryptor.py` | **`ttEncrypt` 纯 Python 实现**（SHA-512 KDF + AES-128-CBC + PKCS7），含反向解密自检 |
| `tools/emu_core.py` | Unicorn ARM64 仿真器：在任意 host 直接跑真 `libEncryptor.so`，逐字节一致 |
| `tools/selftest.py` | 纯 Python 实现 vs 真 `.so` 的逐字节对拍（53 组全通过） |
| `tools/probe_real_api.py` | 线上真实 API 签名验证（`--smoke` / `--sweep` / `--server`） |
| `tools/probe_search.py` | **搜索接口不返回数据定位**（`--empty` 全量扫描 200+空 body 路由） |
| `tools/metasec.py` | metasec 请求头复现（`x-khronos`/`x-ladon`/`x-argus`/`x-gorgon`），移植自自研客户端 |
| `SEARCH_DEBUG.md` | **搜索接口空 body 定位报告**（排除 X-Tt-Token，定位到 `device_type` 翻转点） |
| `REAL_API_TEST.md` | **线上实测报告**：签名链路验收结论 + 1107 条路由对照数据 |
| `hook_hongguo.js` | Frida 脚本：一键 dump 通用参数 / ss_queries 明文密文 / ttEncrypt I/O / 动态密钥 / 最终请求头 |

## 快速开始

```bash
# 1) 看某个业务域有哪些接口
python3 sign_demo.py --list bookapi

# 2) 构造一个 GET 请求
python3 sign_demo.py --route '/reading/bookapi/detail/v{version}/' --param book_id=7123456789

# 3) 构造一个 POST 请求（ss_queries 走 query，其余进 JSON body）
python3 sign_demo.py --method POST \
    --route '/reading/ugc/novel_comment/digg/v{version}/' --param item_id=123

# 4) 真机抓签名材料
frida -U -f com.phoenix.read -l hook_hongguo.js --no-pause

# 5) 直接跑 ttEncrypt（纯 Python）
python3 libencryptor.py "device_id=1&device_type=2"

# 6) 用真 .so 跑 ttEncrypt（Unicorn，逐字节一致）+ 对拍
python3 tools/emu_core.py
python3 tools/selftest.py

# 7) 打线上真实 API，验证签名
python3 tools/probe_real_api.py --smoke      # 少量端点
python3 tools/probe_real_api.py --server     # 服务端视角解 ss_queries
python3 tools/probe_real_api.py --sweep      # 全量路由 签名/不签名 对照

# 8) 校验 OpenAPI
python3 -c "import yaml;d=yaml.safe_load(open('hongguo_openapi.yaml'));print(len(d['paths']))"
```

## 接口分布（1161 个 operation）

| group | 数量 | group | 数量 |
|---|---|---|---|
| bookapi | 217 | luckycat | 71 |
| ugc | 200 | reader | 69 |
| user | 178 | novel | 58 |
| app | 176 | tradeapi | 30 |
| commerceapi | 72 | distribution | 25 |
| msgapi | 19 | api | 16 |
| ai_search_stream | 7 | media | 7 |
| playlet | 7 | video | 5 |

## 域名

| 域名 | 用途 |
|---|---|
| `api5-normal-sinfonlineb.fqnovel.com` / `api5-normal-sinfonlinea.fqnovel.com` | `fqnovel_api_serial_route` 候选，线上主域名 |
| `api3-normal.fqnovel.com` / `api5-normal.fqnovel.com` | 候选/备选（GSLB 按 `threshold=5000` 轮转） |
| `reading.snssdk.com` | 老域名，KMP RPC 默认 baseUrl（`com.dragon.read.kmp.app.core.rpc.i.b`） |
| `api.fqnovel.com` / `i.snssdk.com` / `ib.snssdk.com` | 部分接口在 `@RpcOperation` 里写死 host |
| `log5-applog.fqnovel.com` / `mon11-misc.fqnovel.com` | 埋点/监控 |

## 响应格式

所有业务接口统一返回：

```json
{ "code": 0, "message": "", "data": { ... } }
```

`code` 为 `com.dragon.read.rpc.model.BookApiERR`（int），`0` 成功；
`data` 结构由各接口的 `*Response` 模型决定（见 `hongguo_api.json` 的 `models`）。
服务端日志 ID 常见于响应头 `x-tt-logid`。

## 重要提示

* 通用参数与签名头的**完整算法**见 `SIGNATURE.md`，其中 `x-bd-client-key` / `x-bd-kmsv`
  由服务端通过响应头 `x-bd-lanusk` / `x-bd-lanusv` 下发，不是本地计算。
* `ttEncrypt`（`libEncryptor.so`）已**完整还原**：`74 63 05 10 00 00 || rnd[32] || AES-128-CBC(key, iv, PKCS7(SHA512(data)||data))`，
  其中 `key||iv = SHA512(SHA512(rnd) || K)`，`K` 为 `.rodata` 常量。
  纯 Python 实现见 `libencryptor.py`，Unicorn 真 `.so` 仿真见 `tools/emu_core.py`，算法细节见 `TTENCRYPT.md`。
  `sign_demo.py` 默认走纯 Python，`TT_MODE=emu` 可切到真 `.so`。
* 路由模板里的 `:version` 由客户端在 KMP RPC 层替换，OpenAPI 中已表达为路径参数 `{version}`，
  红果读书类接口取 `1`（即 `…/v1/`）。
* 所有接口默认 `serializer=JSON`，少量 PB 接口见 `hongguo_routes.csv` 的 `serializer` 列。
