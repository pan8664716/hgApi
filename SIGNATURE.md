# 红果短剧（com.phoenix.read 7.3.9.32）请求签名 / 加密算法逆向

> 样本：`novelread_69310258a_v12267_73932_d587_1790271867.apk`
> SHA-256：`8869931d5cec8b27a86b35af7a95db40db7a0c9264ff5d278c06a0656ea2a0ab`
> package `com.phoenix.read`，versionCode `73932`，versionName `7.3.9.32`，flavor `hongguo`，构建 `b5e187f_20260923`
> 仅 `arm64-v8a`，24 个 dex，`com.bytedance.covode`（字节码虚拟化）+ `com.ss.android.ugc.bytex`（Kotlin 中间层）全量混淆。

---

## 0. 结论速览

| 项 | 结论 |
|---|---|
| 是否有 `X-Gorgon` / `X-Argus` / `X-Khronos` / `X-Ladon` / `X-Bogus` | **没有**。本版本（2026-09）已下线这套旧头，`x-gorgon`/`x-ladon` 在全部 dex 中出现 **0 次** |
| 实际签名头 | `X-SS-QUERIES`、`X-SS-REQ-TICKET`、`X-TT-VERIFY-ID`、`x-bd-client-key`、`x-bd-kmsv` |
| 查询串加密 | `ttEncrypt(device_id=..&device_type=..&device_brand=..&uuid=..&openudid=..)` → Base64(NO_WRAP) → 参数 `ss_queries` + 头 `X-SS-QUERIES` |
| 时间戳 | `X-SS-REQ-TICKET = System.currentTimeMillis()` |
| 动态密钥 | `x-bd-client-key` / `x-bd-kmsv` 由**服务端**通过响应头 `x-bd-lanusk` / `x-bd-lanusv` 下发，客户端只做缓存与回传（Keva） |
| 老式 body 摘要 | `X-SS-STUB = MD5(body).toUpperCase()`，本版本仅保留在隐私合规前的 `pd3/c` 通道 |
| 安全因子 | metasec ML（`libmetasec_ml.so`）通过 `ms.bd.c.k3.a(50331649, 0, handle, url, kvArray)` 原生产出，落地头 `x-security-argus`（媒体/音频、XBridge 场景） |
| 主体加密库 | `libEncryptor.so` → JNI `EncryptorUtil.ttEncrypt([BI)[B]`，**AES**（标准 Te0..Te3 + S-box 表在 .rodata） |

---

## 1. 请求流水线（TTNet 内部拦截器）

红果所有业务请求都走 TTNet 的 `TTInternalInterceptor`，实现类为混淆后的 `dl0/a`
（`com.bytedance.frameworks.baselib.network.http.NetworkParams` 驱动）。

`dl0/a.intercept()` 的完整顺序（逐条对应 smali 偏移）：

```
00c7  HttpRequestInfo.injectCreate()
00d0  request.newBuilder(); headers = request.getHeaders()
00fe  UrlUtils.parseUrlWithValueList(url, map)      // 解析 query
010a  对同名 query 去重（LinkedHashSet）
0155  UrlBuilder.build()                            // 重组 url
01dc  if (ts1.a.a) RequestEncryptUtils.tryEncryptRequest(url, headers)
      -> 可能改写 url（追加 ss_queries）并追加请求头 X-SS-QUERIES
0228  if (c.b)  X-SS-REQ-TICKET = String.valueOf(System.currentTimeMillis())
      （仅当 host.endsWith(com.bytedance.ttnet.b.a())）
0269  if (utils.a.a) X-TT-VERIFY-ID = utils.a.a(uri)
0287  ClientKeyManager.g() -> 追加 x-bd-client-key / x-bd-kmsv
02cf  builder.url(url).headers(headers).build()
02e0  chain.proceed(request)
02f0  响应侧：CommandListener、ClientKeyManager.d()（更新 client key）
```

在它**之前**还有两步（同方法前半段）：

```
0050  NetworkParams.filterUrl(url, ctx, metrics)      // 域名/协议重写
00a1  NetworkParams.addCommonParams(url, true, m)     // 追加通用参数（见 §2）
```

而安全因子（metasec）在 `NetworkParams.tryAddSecurityFactor(url, queryMap)` 中生成，
由 `ms.bd.c.h5` 注册的回调 `ms.bd.c.g5` 提供。

---

## 2. 通用参数（所有接口必带）

来源：`com.ss.android.common.applog.NetUtil.putCommonParamsWithLevel(map, true, Level.L0)`
入口：`com.dragon.read.app` 的 `ApiProcessHook` 实现（混淆名 `od3/a`）

```java
// od3/a.addCommonParams
String s = NetUtil.addCommonParamsWithLevel(url, true, Level.L1);
s = od3.a.c(s);          // postProcessUrl：给 bookmall/tab 补 aid/device_platform/version_*/app_name/channel/cdid
```

### 2.1 参数表（顺序即插入顺序）

| 参数 | 取值 |
|---|---|
| `klink_egdi` | DeviceRegisterManager.getSSIDs 的 `klink_egdi`（可空） |
| `iid` | `install_id` |
| `device_id` | `device_id` |
| `ac` | 网络接入类型（`NetworkUtils.getNetworkAccessType`） |
| `channel` | `AppContext.getTweakedChannel()` |
| `aid` | 应用 ID |
| `app_name` | 应用名 |
| `version_code` | `AppContext.getVersionCode()` |
| `version_name` | `AppContext.getVersion()` |
| `device_platform` | 固定 `android`（鸿蒙为 `harmony`） |
| `os` | `android` / `harmony` |
| `sub_os_api` | 鸿蒙专有 |
| `ab_version` / `ab_client` / `ab_group` / `ab_feature` / `abflag` | ABTest 相关（非空才带） |
| `ssmix` | 固定 `a`（`z19=true`） |
| `device_type` | `Build.MODEL` |
| `device_brand` | `Build.BRAND` |
| `language` | `Locale.getDefault().getLanguage()` |
| `os_api` | `Build.VERSION.SDK_INT` |
| `os_version` | `Build.VERSION.RELEASE`（截断 10 字符） |
| `openudid` | 仅 Level.L0 且非儿童模式 |
| `manifest_version_code` | `AppContext.getManifestVersionCode()` |
| `resolution` | 屏幕分辨率 |
| `dpi` | 屏幕 DPI |
| `update_version_code` | `AppContext.getUpdateVersionCode()` |
| `_rticket` | `System.currentTimeMillis()` |
| `cdid` | `g38.a.a(context)` |
| `uuid` | `AppContext.getDeviceId()`（L0） |
| `oaid` | OAID（L0） |

> 参数插入逻辑：`appendCommonParamsWithLevel` 会先读原 URL 的 query key 集合，
> **已存在的 key 不覆盖**，其余按上表顺序 append。

---

## 3. `X-SS-QUERIES`：查询串加密（ttEncrypt）

### 3.1 Java 侧（`com.bytedance.frameworks.core.encrypt.RequestEncryptUtils`）

```java
public static String tryEncryptRequest(String url, List<Pair<String,String>> outHeaders) {
    if (url.isEmpty() || sEncryptConfig == null || sDebug) return url;
    LinkedHashMap<String,List<String>> q = new LinkedHashMap<>();
    Uri uri = Uri.parse(url);
    parseQueries(uri, q);                       // URLDecode 后放进 map

    List<Pair<String,List<String>>> plain = new LinkedList<>();
    tryAddQuery(q, plain, "device_id");
    tryAddQuery(q, plain, "device_type");
    tryAddQuery(q, plain, "device_brand");
    tryAddQuery(q, plain, "uuid");
    tryAddQuery(q, plain, "openudid");
    // tryAddQuery 在 !isSsQueriesPlaintextOpen() 时把 key 从 q 中移除（=> 明文不再出现在 URL 上）

    String plainText = format(plain, false, "UTF-8");
    // 形如: device_id=xxx&device_type=xxx&device_brand=xxx&uuid=xxx&openudid=xxx
    // 注意: format(z19=false) 不做 URLEncode；只包含 map 中确实存在的 key，全缺则直接返回原 url

    byte[] enc  = EncryptorUtil.a(plainText.getBytes(), plainText.getBytes().length); // -> native ttEncrypt
    String b64  = Base64.encodeToString(enc, Base64.NO_WRAP);                          // 标准 Base64，无换行

    List<Pair<String,List<String>>> out = new LinkedList<>();
    if (sEncryptConfig.isSsQueriesOpen())          out.add(new Pair("ss_queries", [b64]));       // 放在 query 最前
    if (sEncryptConfig.isSsQueriesHeaderOpen())    outHeaders.add(new Pair("X-SS-QUERIES", URLEncoder.encode(b64,"UTF-8")));
    // 其余原有参数按原顺序追加回去
    return createUri(...).toString();
}
```

要点：

* 加密对象只有 **5 个设备参数**，不是整个 query。
* `ss_queries` 被插到 query **最前面**，即 `?ss_queries=<b64>&aid=..&device_id=..`。
* `X-SS-QUERIES` 头的值是 Base64 再做一次 `URLEncoder.encode(...,"UTF-8")`（`+` `/` `=` 被转义）。
* 开关 `isSsQueriesOpen/isSsQueriesHeaderOpen/isSsQueriesPlaintextOpen` 来自服务端配置
  （`RequestEncryptUtils.setEncryptConfig`），线上三者一般为 `true/true/false`。

### 3.2 Native 侧（`libEncryptor.so`）

```
com.bytedance.frameworks.encryptor.EncryptorUtil
    private static native byte[] ttEncrypt(byte[] data, int len);
    static { System.loadLibrary("Encryptor"); }     // 走 Zoin 插件化加载: ZoinSoHelper.b()
```

对 `lib/arm64-v8a/libEncryptor.so` 的静态分析 + Unicorn 动态复现结果（**已完整还原，见 `TTENCRYPT.md`**）：

```
输出 = 74 63 05 10 00 00 || rnd[32] || AES-128-CBC(key, iv, PKCS7(salt || data))

rnd  = 32 字节随机材料（真机: srand(time(NULL)) 后 32 次 rand() 取低字节）
D1   = SHA-512(rnd)
D2   = SHA-512(D1 || K)              K = 64B 常量 = .rodata[0xdf50] XOR .rodata[0xdf90]
key  = D2[0:16]                      AES-128
iv   = D2[16:32]                     CBC IV
salt = SHA-512(data)                 64B 明文前缀（完整性校验）
```

| 项 | 值 |
|---|---|
| 导出符号 | 仅 `JNI_OnLoad` @ `0xc38`（124 B） |
| JNI 名字/签名串 | `.rodata` `0x895c`：`"ttEncrypt\0([BI)[B\0"` |
| 注册表 | `.data` `0x18000`：`{self, "ttEncrypt", "([BI)[B", 0x7d8c}` |
| 真实入口 | `.mytext` `0x7d8c`（JNI 包装，env 函数表**前置 27 个私有槽**） |
| 主体 | 两层 Zoin VM：`0xd94`（JNI_OnLoad）与 `0x2bd8`/`0x2d2c`（ttEncrypt） |
| AES | `0x4678` 密钥扩展、`0x66d4` 装配、`0x65d0` XOR、`0x26e0` T-table 单块 |
| 摘要 | `0x683c` SHA-512 压缩、`0x6c40` SHA-512 final |
| 常量 | `0x4bbc` 做 `.rodata[0xdf50] ^ [0xdf90]` → 64B `K` |
| 依赖导入 | `srand` / `time` / `rand` / `malloc` / `memcpy` / `memset` / `free` |

**复现方式（三选一，均已落地）**

1. **纯 Python**：`libencryptor.py` 的 `tt_encrypt()`，跨平台、无 native 依赖。
2. **Unicorn 仿真真 `.so`**：`tools/emu_core.py`，在任意 host 上把 `libEncryptor.so` 跑起来，
   与真机逐字节一致（`tools/selftest.py` 53 组对拍全过）。
3. **真机 Frida hook**：`hook_hongguo.js` 直接 dump `(明文, 密文)` 对。

## 4. `X-SS-REQ-TICKET` / `X-TT-VERIFY-ID`

```java
// dl0/a
if (c.f75814b) {                                  // 开关
    String ticket = URIUtils.safeCreateUri(url).getHost().endsWith(com.bytedance.ttnet.b.a())
                    ? String.valueOf(System.currentTimeMillis()) : null;
    if (!StringUtils.isEmpty(ticket)) headers.add(new Header("X-SS-REQ-TICKET", ticket));
}
if (com.bytedance.ttnet.utils.a.f75805a) {
    String verify = com.bytedance.ttnet.utils.a.a(URIUtils.safeCreateUri(url));
    if (!TextUtils.isEmpty(verify)) headers.add(new Header("X-TT-VERIFY-ID", verify));
}
```

* `X-SS-REQ-TICKET`：毫秒时间戳，服务端做时间窗校验 + 防重放（响应侧会比对 `X-SS-REQ-TICKET` 是否匹配，
  不匹配时上报 `reqTicketUnmatch` 埋点）。
* `X-TT-VERIFY-ID`：预 CDN 缓存校验 ID。

---

## 5. `x-bd-client-key` / `x-bd-kmsv`：服务端下发的动态密钥

`com.bytedance.ttnet.clientkey.ClientKeyManager`（classes22.dex）

### 5.1 取值

```java
// dl0/a
ClientKeyManager m = ClientKeyManager.g();
if (ClientKeyManager.i != null && ClientKeyManager.j /*client_key_sign_enabled*/) {
    headers.add(new Header("x-bd-client-key", m.c));   // = Keva "client_key"
    headers.add(new Header("x-bd-kmsv",       m.f));   // = Keva "kms_version"
}
```

`ClientKeyManager.g()` 单例；`c` / `f` 从 `Keva`（`com.bytedance.keva`，底层 `libkeva.so`/MMKV）读取，
key 为 `client_key` / `kms_version`。

### 5.2 更新链路（响应侧 `ClientKeyManager.d(request, response)`）

```
1. 只在 host 命中 client_key_config.update_host_list、path 命中 update_path_list 时才处理
2. 取响应 Set-Cookie 中的 sessionid=<sid>
3. 读响应头 x-bd-lanusk / x-bd-lanusv：
     两个都存在且非空 -> 直接用它们作为新的 client_key / kms_version（状态 0）
     否则若 sid 变了      -> 清空（状态 3）
     否则                 -> 沿用旧值（状态 2）
4. 写回 Keva: session_url / session_id / client_key / kms_version / session_time
5. f(client_key, kms_version) -> {x-bd-client-key, x-bd-kmsv} 缓存到静态字段 l
```

### 5.3 配置下发

`ClientKeyManager.a(json)` 解析设置里的 `data.client_key_config`：

```
client_key_sign_enabled : 总开关（>0 才启用）
rewrite_session_enabled : 是否把服务端 sessionid 写回 CookieHandler
update_host_list        : 触发更新的 host 通配（UrlUtils.matchPattern）
update_path_list        : 触发更新的 path 通配
```

> **结论**：这两个头**不是本地算出来的签名**，而是服务端签发的一次性凭证。
> 想复现必须先有一次成功请求拿到 `x-bd-lanusk`/`x-bd-lanusv`，并保持 `sessionid` 一致。

---

## 6. `X-SS-STUB`：老协议 body 摘要（仍保留在隐私合规通道）

类 `pd3/c`（`com.dragon.read.base.util.LogHelper("PrivacyEvent-Http")`，
`OkHttpClient` 10s 超时，`retryOnConnectionFailure=false`）：

```
URL = AppProperty.getBaseUrl() + "reading/user/event/report"
query: aid, app_id, platform=android, device_platform=android,
       version_code, update_version_code, manifest_version_code,
       version_name, app_version, app_name, channel, os_version, ...
header: X-SS-STUB   （POST body 的 MD5，大写十六进制）
header: x-ss-req-ticket
header: x-tt-logid（响应侧读取）
```

`X-SS-STUB` 的语义在 TTNet/AppLog 中是 `MD5(body).toUpperCase()`，用于 body 完整性校验。

---

## 7. metasec（`libmetasec_ml.so`）与安全因子

### 7.1 注册链路

```
MSManagerUtils.init(context, MSConfig)         // com.bytedance.mobsec.metasec.ml
   -> i3.c(context, config)
MSManagerUtils.get(serviceName) -> new MSManager(f3)   // f3 实现 ms.bd.c.h3
MSManager.frameSign / getFeatureHash / getReportRaw / getToken / setDeviceID ...
```

应用启动任务中调用：`com.dragon.read.app.launch.task.d3 / e3 / f3`。

### 7.2 网络侧安全因子

```java
// com.bytedance.frameworks.baselib.network.http.NetworkParams.tryAddSecurityFactor(url, queryMap)
String[] kv = (String[]) k3.a(50331649, 0, g5Var.f394485a.f394500a, url, flattenedKeyValues);
// flattenedKeyValues = [k1,v1,k2,v2, ...]
// 返回值按 [name, value, name, value, ...] 回填成 header
```

* `ms.bd.c.k3.a(int, int, long, String, Object)` 是 **native**（`libmetasec_ml.so`）；
  Java 兜底走 `ms.bd.c.d3.a(...)`。
* `ms.bd.c.h5` 继承 `a3`，在 `a(long handle)` 中把 `g5` 注册给 `NetworkParams.setAddSecurityFactorProcessCallback`；
  `finalize()` 时用 `k3.a(50331650/100663298, 0, handle, null, null)` 释放。
* `k3.a(...)` 同时承担**字符串解密**（混淆串如 `"3b346d"` + byte[] 密文）。

### 7.3 落地头

* `x-security-argus`：媒体/音频播放（`MediaPlayer.setDataSource(ctx, uri, {"x-security-argus": <sign>})`，
  见 `e12/a.handleOperateAudio`）、部分 XBridge 请求。
* `x-metasec-mode` / `x-metasec-content-encoding` / `x-metasec-bypass-*`：metasec 运行控制头。

---

## 8. KMP RPC 的 URL 组装（决定最终请求路径）

红果的 API 不是 Retrofit 注解，而是字节自研 **KMP multi-rpc**：

```java
@com.bytedance.rpc.annotation.RpcOperation("$GET /reading/bookapi/detail/v:version/")
@com.bytedance.rpc.annotation.RpcParams(true)
@com.bytedance.rpc.annotation.RpcSerializer(JSON)
Observable<BookDetailResponse> bookDetailRxJava(BookDetailRequest req);
```

运行时（`com.bytedance.multi.rpc.core.proxy.a#f`）：

```
url = "https://" + hostMap.get(serviceName) /* 缺省 f357257a */ + path(bVar.c())
query/body 由请求对象序列化而来（kotlinx.serialization 或 Gson）
if (serializeType == JSON || FORM)
    url = e(e(url, queryMap), convertToMap(request))   // e() 做 :placeholder 替换
headers += {"Content-Type": ContentType}
```

`e(String url, Map params)`（同文件）逐个把 `:<name>` 替换成 `params.remove(name)`，
**取不到就原样返回**；`RpcHttpRequest.a()` 里对 body 做同样的替换。

因此路由里的 `:version` 是"接口版本段"占位符，OpenAPI 中已表达为路径参数 `{version}`。

同一 IDL 在 APK 里存在 4 套模型（同一接口多端共用）：

| 模型包 | 用途 |
|---|---|
| `com/dragon/read/rpc/model/*` | Android 主包（`com/dragon/read/rpc/rpc/*` 服务） |
| `readersaas/com/dragon/read/saas/rpc/model/*` | Reader SaaS 包（`aj8/m` = ReaderApiService） |
| `seriessdk/com/dragon/read/saas/rpc/model/*` | 短剧 SaaS 包 |
| `com/bytedance/kmp/reading/model/*` | KMP 共享层（`Kmp*ApiService`） |

---

## 9. Frida Hook（一键 dump 所有签名材料）

```javascript
// frida -U -f com.phoenix.read -l hook_hongguo.js --no-pause
Java.perform(function () {
  function b64(bytes) {
    return Java.use('android.util.Base64').encodeToString(bytes, 2);
  }

  // 1) 通用参数 + 最终 URL
  var NetUtil = Java.use('com.ss.android.common.applog.NetUtil');
  NetUtil.addCommonParamsWithLevel.overload('java.lang.String', 'boolean',
      'com.bytedance.bdinstall.Level').implementation = function (url, z, lv) {
    var r = this.addCommonParamsWithLevel(url, z, lv);
    console.log('[commonParams] ' + r);
    return r;
  };

  // 2) 查询串加密：明文 / 密文 / Base64
  var REU = Java.use('com.bytedance.frameworks.core.encrypt.RequestEncryptUtils');
  REU.tryEncryptRequest.overload('java.lang.String', 'java.util.List')
     .implementation = function (url, list) {
    var r = this.tryEncryptRequest(url, list);
    console.log('[tryEncryptRequest]\n  in : ' + url + '\n  out: ' + r);
    for (var i = 0; i < list.size(); i++) {
      var p = list.get(i);
      console.log('  header ' + p.first + ': ' + p.second);
    }
    return r;
  };

  // 3) ttEncrypt 原始输入输出
  var Enc = Java.use('com.bytedance.frameworks.encryptor.EncryptorUtil');
  Enc.a.overload('[B', 'int').implementation = function (b, n) {
    var plain = Java.array('byte', b).toString();
    var out = this.a(b, n);
    console.log('[ttEncrypt] plain(len=' + n + ')=' + plain);
    console.log('[ttEncrypt] out=' + (out ? b64(out) : 'null'));
    return out;
  };

  // 4) 动态密钥
  var CKM = Java.use('com.bytedance.ttnet.clientkey.ClientKeyManager');
  CKM.d.implementation = function (req, resp) {
    console.log('[ClientKey] url=' + req.getUrl());
    var r = this.d(req, resp);
    console.log('[ClientKey] client_key=' + this.c.value + ' kmsv=' + this.f.value);
    return r;
  };

  // 5) 最终请求头（TTInternalInterceptor）
  var Chain = Java.use('com.bytedance.retrofit2.intercept.Interceptor$Chain');
  // 直接 hook 混淆类 dl0.a
  try {
    var A = Java.use('dl0.a');
    A.intercept.implementation = function (chain) {
      var req = chain.request();
      console.log('[final] ' + req.getUrl());
      var hs = req.getHeaders();
      for (var i = 0; i < hs.size(); i++) console.log('   ' + hs.get(i).getName() + ': ' + hs.get(i).getValue());
      return this.intercept(chain);
    };
  } catch (e) { console.log('dl0.a not found: ' + e); }
});
```

---

## 10. 复现一个合法请求的最小步骤

1. 生成通用参数（§2），`_rticket` 用当前毫秒。
2. 拼 URL：`https://<host><path>`，`{version}` 按接口填 `1`。
3. 若启用 query 加密：取 `device_id/device_type/device_brand/uuid/openudid` 拼成
   `k=v&k=v` → `ttEncrypt` → Base64 → 追加 `ss_queries=<b64>` 到 query 最前，
   并加头 `X-SS-QUERIES: <URLEncoder(b64)>`；同时从 query 里删掉这 5 个明文参数。
4. 加 `X-SS-REQ-TICKET = now()`。
5. 若已有 `x-bd-lanusk`/`x-bd-lanusv`，加 `x-bd-client-key` / `x-bd-kmsv`。
6. 登录态：`X-Tt-Token` / `Cookie: sessionid=...`。
7. `User-Agent` 建议与客户端一致（`com.phoenix.read/73932 ...`）。

参考实现见同目录 `sign_demo.py`。
