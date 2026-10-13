# 静态侦察记录（可复现）

工具：`unzip` / `apkanalyzer` / `jadx 1.5.6` / `dexdump`（build-tools 36.0.0）/ `lief` + `capstone`。

---

## 1. 样本基础信息

```bash
apkanalyzer manifest print novelread_*.apk | head -20
# package="com.phoenix.read"  versionCode="73932"  versionName="7.3.9.32"
# compileSdkVersion=35  minSdkVersion=21  targetSdkVersion=35

unzip -l novelread_*.apk | awk '{print $4}' | grep -c '^assets/'
ls lib/            # 只有 arm64-v8a，117 个 .so
```

`assets/custom_build.properties`：

```
flavor = hongguo
v2_sign_channels = update_64
release_build = b5e187f_20260923
```

`assets/live_build_info.properties`：

```
jekins_name: hongguo_gray_test_build_64_update
release_build: b5e187f_20260923_185040_7688671317016856630
```

> 说明：包名 `com.phoenix.read` 是**红果免费短剧**；代码主体复用番茄小说 `com.dragon.read.*` /
> `com.bytedance.novel.*`，属于同一套“小说/短剧”中台。

---

## 2. 域名与网络配置

### 2.1 `assets/common_url_default.json`

CDN/图片资源域名（`lf3-reading.fqnovelpic.com` 等），不含 API 域名。

### 2.2 GRS 配置（华为 `assets/grs_sdk_server_config.json`）

```
grs_base_url: https://grs.dbankcloud.com | .cn | .asia | .ru | .eu
grs_query_endpoint_1.0: /grs/1.0/%1$s/router
```

### 2.3 网络调度表（dex 内嵌 JSON）

`service_name = fqnovel_api_serial_route`：

```json
"strategy_info": {
  "candidates": [
    {"host": "api5-normal.fqnovel.com", "threshold": 5000, "weight": 0},
    {"host": "api3-normal.fqnovel.com", "threshold": 5000, "weight": 0}
  ],
  "scheme_option": 1, "working_mode": 2
}
```

同类还有 `fqnovel_log_serial_route`、`fqnovel_rtlog_serial_route`。

host 改写映射（片段）：

```
"api.fqnovel.com"     -> "api5-normal.fqnovel.com"
"log.snssdk.com"      -> "log5-applog.fqnovel.com"
"mon.snssdk.com"      -> "mon11-misc.fqnovel.com"
"rtlog.snssdk.com"    -> "rtlog5-applog.fqnovel.com"
"rtlog.zijieapi.com"  -> "rtlog5-applog.fqnovel.com"
share_cookie_host_list: ".snssdk.com,.zijieapi.com,.ulpay.com,.fqnovel.com,.ecombdapi.com,.luckysf.net,.iluckysf.net,.awemeughun.com,.awemeugsoul.com"
```

### 2.4 全量域名统计（`strings classes*.dex | grep -oE 'https?://…'`）

```
144  https://lf3-reading.fqnovelpic.com
 51  https://reading.snssdk.com
 21  https://api5-normal-sinfonlinea.fqnovel.com
 18  https://polaris.zijieapi.com
 15  http://xml.org
 14  https://i.snssdk.com
 12  https://mon.zijieapi.com
 11  https://is.snssdk.com
 10  https://ib.snssdk.com
  9  https://log.snssdk.com
  4  https://api.fqnovel.com
```

---

## 3. 关键 native 库

| 库 | 作用 | 关键字符串 |
|---|---|---|
| `libEncryptor.so` | ttEncrypt（查询串/请求体加密） | `ttEncrypt`、`([BI)[B`、AES Te0..Te3 + S-box |
| `libmetasec_ml.so` | metasec ML 安全 SDK（x-argus 系） | `X-BD-CLIENT-KEY`、`X-BD-KMSV` |
| `libencrypt.so` | 小说内容加密 | `JAVA_CLASS_NAME`、`com/bytedance/novel/encrypt/Encrypt` |
| `libdragon_crypt.so` / `libdragoncore.so` | 阅读器内容加密 | — |
| `libttmverify.so` | TTNet 证书校验 | `SSL_get0_signed_cert_timestamp_list` |
| `liblynxsecurity.so` | Lynx 模板签名校验 | `nativeVerifySignBlock`、`RSA-SHA256` |
| `libsliver.so` | 反调试（线程挂起/信号） | `SuspendThreadByPeer` |
| `libnpth_*` / `libshadowhook.so` | PLT/GOT hook、反注入 | — |
| `libcovode*`（dex 层 `com.bytedance.covode`） | 字节码虚拟化（`recordClassIndex` 遍布全包） | — |

---

## 4. 网络层关键类（jadx / dexdump 定位）

| 类 | 作用 |
|---|---|
| `dl0/a`（classes19.dex） | `TTInternalInterceptor`：**唯一的请求签名装配点** |
| `com.bytedance.frameworks.baselib.network.http.NetworkParams` | `filterUrl` / `addCommonParams` / `tryAddSecurityFactor` |
| `com.ss.android.common.applog.NetUtil` | 通用参数（`putCommonParamsWithLevel`） |
| `od3/a`（classes24.dex） | 应用侧 `NetworkParams.ApiProcessHook` 实现 |
| `com.bytedance.frameworks.core.encrypt.RequestEncryptUtils` | `ss_queries` / `X-SS-QUERIES` 生成 |
| `com.bytedance.frameworks.encryptor.EncryptorUtil` | JNI `ttEncrypt` |
| `com.bytedance.ttnet.clientkey.ClientKeyManager`（classes22.dex） | `x-bd-client-key` / `x-bd-kmsv` 缓存与更新 |
| `pd3/c`（classes24.dex） | 隐私合规前的 `reading/user/event/report` 通道（`X-SS-STUB`） |
| `com.bytedance.mobsec.metasec.ml.MSManager` / `MSManagerUtils` | metasec 入口 |
| `ms.bd.c.k3` | metasec native 桥：`static native Object a(int,int,long,String,Object)` |
| `ms.bd.c.h5` / `ms.bd.c.g5` | 注册 `NetworkParams.setAddSecurityFactorProcessCallback` |
| `com.bytedance.multi.rpc.core.proxy.a` | KMP RPC URL 组装 + `:placeholder` 替换 |
| `com.dragon.read.kmp.app.core.rpc.RpcHttpRequest` | KMP 传输实现，body 的 `:placeholder` 替换 |
| `com.dragon.read.kmp.app.core.rpc.a` | `n51.d` 实现：baseUrl=`reading.snssdk.com` |

### 定位技巧

```bash
# 1) 找路由注解（RpcOperation）在哪些 dex
for f in classes*.dex; do echo -n "$f "; grep -ao 'RpcOperation' $f | wc -l; done

# 2) 带注解反汇编
dexdump -a -d classes8.dex > dex8a.txt
grep -n 'RpcOperation' dex8a.txt | head

# 3) 找实现某个接口的类
grep -n "NetworkParams\$ApiProcessHook;'" dex24b.txt

# 4) 找 header 常量
grep -n 'X-SS-STUB\|x-ss-req-ticket' dex24.txt
```

---

## 5. 路由/注解体系

红果不使用 Retrofit 注解，使用自研 RPC：

```java
@com.bytedance.rpc.annotation.RpcOperation("$GET /reading/bookapi/detail/v:version/")
@com.bytedance.rpc.annotation.RpcParams(true)
@com.bytedance.rpc.annotation.RpcSerializer(JSON)
Observable<BookDetailResponse> bookDetailRxJava(BookDetailRequest req);
```

模型字段上的注解：

```java
@com.bytedance.rpc.annotation.RpcField(BODY|QUERY)   // 字段走 body 还是 query
@com.bytedance.rpc.annotation.RpcFieldModify         // 类级，字段改写
@com.google.gson.annotations.SerializedName("book_id")   // Gson 侧 JSON 名
@kotlinx.serialization.SerialName("book_id")             // kotlinx 侧 JSON 名
```

统计（`dexdump -a -d` 全量）：

```
RpcOperation : 923 (dex8) + 178 (dex7) + 55 (dex14) + 5 (dex21) = 1161
RpcField     : 643 (dex7) + 147 (dex8) + 143 (dex24) + 130 (dex16) + 79 (dex21) + 29 (dex14)
```

服务接口类（KMP / Android 双份）：

```
KmpBookApiService, KmpReaderApiService, KmpUgcApiService, KmpUserApiService,
KmpCommerceApiService, KmpDistributionApiService, KmpMsgApiService,
KmpNovelImApiService, KmpSocialApiService, KmpWorksApiService
ReaderApiService, BookApiService, UserApiService, UgcApiService, MsgApiService,
ArticleApiService, CommentApiService, PlayerApiService
```

---

## 6. 模型包分布

```
com/dragon/read/rpc/model/*                      16020 个类（Android 主包）
com/bytedance/kmp/reading/model/*                KMP 共享层
readersaas/com/dragon/read/saas/rpc/model/*      Reader SaaS
seriessdk/com/dragon/read/saas/rpc/model/*       短剧 SaaS
com/dragon/read/pbrpc/*                          Protobuf 接口模型
com/dragon/read/origin/rpc/model/*               创作者/原创
```

响应包裹统一为 `{ code, data, message }`（`code: com.dragon.read.rpc.model.BookApiERR`）。

---

## 7. 逆向命令清单（复现步骤）

```bash
# 解包
unzip -o novelread_*.apk -d apk -x "res/*"

# 反编译（139 MB / 24 dex，约 40 分钟）
jadx -d jadx --no-res -j 8 novelread_*.apk

# 反汇编（带注解，用于提取 RpcOperation）
DEXDUMP=/opt/homebrew/share/android-commandlinetools/build-tools/36.0.0/dexdump
for d in 3 5 6 7 8 9 14 15 16 21 22 23 24; do $DEXDUMP -a -d apk/classes$d.dex > dex${d}a.txt; done

# 提取接口表
grep -n 'RpcOperation' dex*a.txt

# 提取通用参数
grep -n 'putCommonParamsWithLevel' dex*a.txt
```

---

## 8. 已知坑

1. `com.bytedance.covode` 给每个类插入 `recordClassIndex(int)`，`jadx` 输出里到处是它，可忽略。
2. Kotlin 中间层 `CheckNpeV2` / `bytex` 会把 `checkNotNull` 展开，反编译代码比源码长得多。
3. `:version` 占位符只出现在注解里，**运行期才替换**；`/v1/` 这类字面量路由是另一些接口。
4. 同一接口在 4 套模型包里各有一份，参数名一致、类型不同（`J` vs `Ljava/lang/String;`）。
5. `x-bd-client-key` / `x-bd-kmsv` 依赖服务端下发，冷启动第一次请求必然缺失，属正常。
6. `libEncryptor.so` 走 Zoin 插件化加载（`ZoinSoHelper.b()` / `ModuleManager.isSoDepsNeedsResolve`），
   APK 内路径 `lib/arm64-v8a/libEncryptor.so`。
