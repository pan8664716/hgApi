# `libEncryptor.so` / `ttEncrypt` 完整还原

> 样本：`libEncryptor.so`（APK 内 `lib/arm64-v8a/libEncryptor.so`，83,928 B，仅 `arm64-v8a`，Zoin VM 保护）
> 对应 Java：`com.bytedance.frameworks.encryptor.EncryptorUtil.ttEncrypt(byte[] data, int len)`
> 用途：`X-SS-QUERIES` / `ss_queries` 查询串加密（见 `SIGNATURE.md §3`）

---

## 0. 结论速览

```text
输入: data (任意字节)
输出: 74 63 05 10 00 00 || rnd[32] || AES-128-CBC(key, iv, PKCS7(salt || data))

rnd   = 32 字节随机材料（真机: srand(time(NULL)) 后 32 次 rand() 取低字节）
D1    = SHA-512(rnd)
D2    = SHA-512(D1 || K)          K = 64 字节常量（.rodata[0xdf50] XOR .rodata[0xdf90]）
key   = D2[0:16]
iv    = D2[16:32]
salt  = SHA-512(data)             64 字节，作为明文前缀（完整性校验）
```

* 分组密码：**标准 AES-128-CBC**（T-table 实现），PKCS#7 填充。
* `rnd` 是**明文随机数（nonce）**，随密文一起下发，服务端用它重新推导 `key/iv` —— 所以本地生成任意
  `rnd`（如 `os.urandom(32)`）产生的密文都是**服务端可解**的；只有在需要与某台设备**逐字节一致**时才需要复现
  `srand(time()) + rand()`。
* 输出长度：`6 + 32 + 16*ceil((len(data)+64+1)/16)`。

常量 `K`：

```text
4dd4c2e6b83162090e52b3c7a6733ba41cb2462b829ab58a196b39db57177524
f49baf7f08e8d68d26a72e37c1a95a2f1f05a51892aef2949732b62a38aadd58
```

---

## 1. 静态结构

| 地址 | 内容 |
|---|---|
| `0xc38` | `JNI_OnLoad`（124 B），内部调用 Zoin VM `0xd94` 完成 `RegisterNatives` |
| `0xd94` | Zoin 解释器 #1：4 字节/指令，`opcode = word & 0x3f`，分派表 `.rodata @0x7ef0`（32-bit 自相对偏移） |
| `0x8890` | JNI_OnLoad 用的 VM 程序（内嵌 `"ttEncrypt"` / `"([BI)[B"` 字面量） |
| `0xcb4` | host 通用 3 参调用器 `fn([ctx],[ctx+8],[ctx+0x10],[ctx+0x18]) → [ctx+0x1c]` |
| `0xcd8` | 解出类名（`.rodata@0x8850` XOR `0x73`）→ `FindClass` → `RegisterNatives(…, 1)` |
| `0x7d8c` | `.mytext` 段，**注册给 `ttEncrypt` 的 JNI 入口** |
| `0x2bd8` | 第二层 Zoin VM（程序 `@0xb2d0`，常量 `@0x17ce0`），真正干活 |
| `0x4678` | AES-128 密钥扩展（`(keylen>>2 & 0x3ffffffe)+6` = 轮数，写 `[ctx+0x1e0]`） |
| `0x65d0` | 16 字节 XOR（明文写入状态缓冲） |
| `0x66d4` | 拷贝密钥调度（`0x1e8` B）+ 追加 16 B IV |
| `0x26e0` | AES T-table 单块加密 |
| `0x683c` | SHA-512 压缩函数 |
| `0x6c40` | SHA-512 final（`(ctx, out)`，ctx 布局 `[0]=bits, [8..0x48]=H, [0x48]=buflen, [0x4c..]=buf`） |
| `0x4bbc` | VM opcode：把 `.rodata@0xdf50` 与 `.rodata@0xdf90` 逐字节 XOR（生成常量 `K`） |

### 1.1 JNI 包装（`0x7d8c`）

```asm
0x7dd0  ldr  x8, [x20]            ; env->functions
0x7de0  ldr  x8, [x8, #0x5c0]     ; 索引 184 = 27 + 157 = GetByteArrayElements
0x7dfc  bl   0xac0                ; malloc(len + 0x76)
0x7e18  bl   0x2bd8               ; ★ ttEncrypt(plain, len, out, &outlen)
0x7e2c  ldr  x8, [x8, #0x580]     ; 索引 176 = 27 + 149 = NewByteArray
0x7e44  ldr  x8, [x8, #0x680]     ; 索引 208 = 27 + 181 = SetByteArrayRegion
0x7e94  ldr  x8, [x8, #0x600]     ; 索引 192 = 27 + 165 = ReleaseByteArrayElements
```

> ⚠️ 本库给 native 方法传的 `JNIEnv*` 在标准函数表**前面插了 27 个私有槽**（`JNI_OnLoad` 期的 env 则是
> 标准表）。仿真时必须建两张表，否则 `FindClass` 会错位。

---

## 2. 动态还原（Unicorn）

`tools/emu_core.py` 把真 `.so` 直接跑起来（任意 host，无需 arm64 硬件）：

* 映射两个 `PT_LOAD` + `.bss`；`tpidr_el0` 指向自建 TLS（栈保护字 `[+0x28]`）；
* 改 `.got` 表项指向 hook，实现 `malloc/free/memcpy/memset/srand/time/rand/__stack_chk_fail`；
* 伪造 `JavaVM`（`functions[6] = GetEnv` → 回填标准 `JNIEnv*`）与两张 `JNIEnv` 表；
* 跑 `JNI_OnLoad` → 捕获 `RegisterNatives` 注册的 `ttEncrypt` 地址（`0x7d8c`）→ 按 JNI 约定调用。

关键还原路径：

1. `RegisterNatives` 注册 `("ttEncrypt", "([BI)[B", 0x7d8c)`；
2. `0x2bd8` 进第二层 VM → `0x2a5c(aes_ctx, 0x10, key_ptr, data_ptr, datalen, _, &outlen)`；
3. 追 `0x4678`（密钥扩展，参数就是 AES key）→ 得到 `key`；
4. 追 `0x66d4`（参数就是 IV）→ 得到 `iv`；
5. 追 `0x26e0` + `0x65d0` → 确认 **CBC + 全块**，用 PyCryptodome 解密 `out[38:]` 得
   `SHA-512(data) || data || PKCS7`；
6. 抓 `0x683c`（SHA-512 压缩）的 128 B 输入块：
   * 块 1 = `rnd[32] || 0x80 || … || 0x0100` → `D1 = SHA512(rnd)`；
   * 块 2 = `D1 || K`（128 B）→ `D2 = SHA512(D1 || K)`，且 `key/iv = D2[0:32]`；
   * 块 4 = `"hello" || 0x80 || … || 0x0028` → `salt = SHA512(data)`；
7. `K` 由 `0x4bbc`（`.rodata@0xdf50` XOR `@0xdf90`）生成。

### 2.1 复现要点（踩坑记录）

| 坑 | 现象 | 处理 |
|---|---|---|
| `.got` vs PLT | 只把 PLT 桩改成 `ret` → `malloc/memcpy/memset` 全变 no-op，AES 轮数变成垃圾导致死循环 | 保留 PLT 桩，改 `.got` 表项指向 hook |
| `memcpy(dst, src, n)` | 参数顺序写反 → 随机材料全变 0，`key` 全 0 | `a[0]=dst, a[1]=src` |
| `JavaVM` | `functions[6] = GetEnv` 未实现 → VM 返回 `JNI_ERR(-1)` | 回填 `JNIEnv*` 并返回 `JNI_OK` |
| env 双表 | native 方法收到的 env 前置 27 槽 | 分别构造标准表 / 前置表 |

---

## 3. 纯 Python 实现

`libencryptor.py`（无 native 依赖，PyCryptodome 可选，缺失时用内置纯 Python AES）：

```python
import hashlib, os
from Crypto.Cipher import AES

MAGIC = bytes((0x74, 0x63, 0x05, 0x10, 0x00, 0x00))
K = bytes.fromhex("4dd4c2e6b83162090e52b3c7a6733ba41cb2462b829ab58a196b39db57177524"
                  "f49baf7f08e8d68d26a72e37c1a95a2f1f05a51892aef2949732b62a38aadd58")

def tt_encrypt(data: bytes, rnd: bytes | None = None) -> bytes:
    rnd = rnd or os.urandom(32)
    d1 = hashlib.sha512(rnd).digest()
    d2 = hashlib.sha512(d1 + K).digest()
    key, iv = d2[:16], d2[16:32]
    body = hashlib.sha512(data).digest() + data
    pad = 16 - len(body) % 16
    body += bytes([pad]) * pad
    return MAGIC + rnd + AES.new(key, AES.MODE_CBC, iv).encrypt(body)
```

命令行：

```bash
python3 libencryptor.py "device_id=1&device_type=2"     # 输出 hex + 反向解密自检
python3 tools/emu_core.py                              # 用真 .so 跑一遍（Unicorn）
python3 tools/selftest.py                              # 纯 Python vs 真 .so 逐字节对拍
```

---

## 4. 验证

```
$ python3 tools/selftest.py
对拍结果: OK=53 FAIL=0  (共 53 组)
```

* 覆盖长度 `1..39, 48, 63..65, 80, 100, 127..129, 200, 255, 256, 500, 1000`；
* 每组均做 **纯 Python 密文 == 真 .so 密文** 的逐字节比对 + 反向解密回原文校验；
* 额外验证：纯 Python AES 兜底（去掉 PyCryptodome）同样逐字节一致；更换仿真器 `time()` 种子后仍一致。

---

## 5. 与请求流水线的衔接

`sign_demo.py` 已接入（`TT = TTEncrypt(mode=os.environ.get("TT_MODE","py"))`）：

```bash
python3 sign_demo.py --route '/reading/bookapi/detail/v{version}/' --param book_id=7123456789
#   ?ss_queries=dGMFEAAAZodhT0Eo1KJCaJFuEjk3CuzDbCCqsvdJDukqaNF1fpKbmX9Pkr+/jhH48YP7…
#   X-SS-QUERIES: dGMFEAAAZodhT0Eo1KJCaJFuEjk3CuzDbCCqsvdJDukqaNF1fpKbmX9Pkr%2B%2FjhH48YP7…

python3 -c "import base64;print(base64.b64decode('dGMFEAAA').hex())"   # 746305100000
```

`TT_MODE`：

| 值 | 行为 |
|---|---|
| `py`（默认） | 纯 Python，跨平台 |
| `emu` | Unicorn 直接跑 `libEncryptor.so`，逐字节一致 |
| `device` | `glibc rand(seed=now())` 复现真机字节 |

---

## 6. 校验位说明

* `salt = SHA512(data)` 放在明文最前，服务端解出后可用来自证「密文未被篡改」；
* `rnd` 明文下发，是 **KDF 的输入而非密钥本身**，因此每次请求 `ss_queries` 都不同；
* 头部 `74 63 05 10 00 00`：`74 63` = `"tc"` 魔数，`05` = 版本，`10` = 块大小 16。
