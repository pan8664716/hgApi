#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
metasec 请求头复现（移植自 hongguotv-kotlin 0.9.0 的 A1.d.X() / J0.Y）
======================================================================
产出与自研客户端完全一致的头：

    x-khronos / x-ladon / x-argus / x-gorgon / x-ss-req-ticket
    x-tt-request-tag / sdk-version / passport-sdk-version / x-xs-from-web / x-tt-dt

未移植（需要 native / 额外常量，见文末 TODO）：
    x-helios（依赖 S() 随机数 + 34 轮 TEA 类变换）
    x-medusa（N()，完整 MSManager protobuf 载荷，约 300 行）

参考：/tmp/hgtv09_jadx/sources/A1/C0031d.java 的 X()/H()/M()，J0/C0123h.java case 7。
"""
from __future__ import annotations

import base64
import hashlib
import random
import struct
import time
import urllib.parse

__all__ = ["sign", "build_qs", "urlenc", "gorgon", "gate_ok"]


# ----------------------------------------------------------------------
# 原语（对应 A1/C0031d.java 的 H() / M()）
# ----------------------------------------------------------------------
def _u32(x: int) -> int:
    return x & 0xFFFFFFFF


def H(i: int, b: bytes) -> int:
    """A1/C0031d.H(int, byte[])：自定义 32 位混合散列。"""
    i = _u32(i)
    for idx, x in enumerate(b):
        if (idx & 1) == 0:
            i = _u32((i << 6) ^ ((i >> 4) ^ i) ^ (x & 0xFF))
        else:
            i = _u32(~(((i << 12) | (x & 0xFF)) ^ ((i >> 7) ^ i)))
    return i


def M(b1: bytes, b2: bytes, i: int) -> int:
    """A1/C0031d.M(byte[], byte[], int)：H(H(539167016, a), b) 再喂 le32(i)。"""
    x = H(539167016, b1)
    x = H(x, b2)
    return H(x, struct.pack("<I", i & 0xFFFFFFFF))


def le32(i: int) -> bytes:
    return struct.pack("<I", i & 0xFFFFFFFF)


def be32(i: int) -> bytes:
    return struct.pack(">I", i & 0xFFFFFFFF)


# ----------------------------------------------------------------------
# URL 编码（对应 k1/l.A：URLEncoder.encode + "+"->"%20" + "%7E"->"~"）
# ----------------------------------------------------------------------
def urlenc(v) -> str:
    return urllib.parse.quote(str(v), safe="").replace("+", "%20").replace("%7E", "~")


def build_qs(items) -> str:
    """items: [(k, v), ...]（保持插入顺序）→ 与客户端一致的 query 串。"""
    return "&".join("%s=%s" % (urlenc(k), urlenc(v)) for k, v in items)


# ----------------------------------------------------------------------
# x-gorgon（A1/C0031d.X() 内的 RC4 变体 + 二次置换）
# ----------------------------------------------------------------------
def gorgon(qs: str, body: bytes | None, i3: int, rnd16: int) -> str:
    md5q = hashlib.md5(qs.encode()).digest()
    md5b = hashlib.md5(body).digest() if body else bytes(16)
    p = md5q[:4] + md5b[:4] + b"\x00" * 4 + le32(67503104) + be32(i3)

    i5 = (rnd16 >> 8) & 0xFF
    key = [74, 64, 22, i5, 71, 108, 1, rnd16 & 0xFF]

    sbox = list(range(256))
    j = 0
    for i in range(256):
        j = (j + sbox[i] + key[i % 8]) & 0xFF
        sbox[i], sbox[j] = sbox[j], sbox[i]

    out = bytearray(len(p))
    i = j = 0
    for k in range(len(p)):
        i = (i + 1) & 0xFF
        j = (j + sbox[i]) & 0xFF
        sbox[i], sbox[j] = sbox[j], sbox[i]
        out[k] = p[k] ^ sbox[(sbox[j] * 2) & 0xFF]

    # 二次置换：步长 2，读奇数位写偶数位
    n = len(out)
    for k in range(0, n, 2):
        v = out[k]
        nxt = out[k + 1] if k + 1 < n else out[0]
        x = (nxt ^ (((v << 4) | (v >> 4)) & 0xFF)) & 0xFF
        rev = int(format(x, "032b")[::-1], 2)
        out[k] = (~((rev >> 24) ^ 20)) & 0xFF

    blob = bytes.fromhex("8404") + bytes([rnd16 & 0xFF, i5, 64, 1]) + bytes(out)
    return blob.hex()


def gate_ok(qs: str, body: bytes | None, i3: int) -> bool:
    """客户端必须满足 (M(...) & 15) % 3 == 0 才会发出请求，否则换 _rticket 重试。"""
    md5b = hashlib.md5(body).digest() if body else bytes(16)
    return (M(hashlib.sha256(qs.encode()).digest(), md5b, i3) & 15) % 3 == 0


# ----------------------------------------------------------------------
# 对外入口
# ----------------------------------------------------------------------
def sign(url: str, items, body: bytes | None = None, now_ms: int | None = None,
         rnd16: int | None = None, ua: str | None = None) -> dict:
    """
    生成 {url, headers}。items 为 [(k, v), ...]，ts/_rticket 由本函数追加。
    """
    now_ms = now_ms if now_ms is not None else int(time.time() * 1000)
    i3 = int(now_ms / 1000)
    for i4 in range(128):
        j2 = now_ms + i4
        qs = build_qs(list(items) + [("ts", str(i3)), ("_rticket", str(j2))])
        if gate_ok(qs, body, i3):
            break
    else:
        raise RuntimeError("gate 128 次未满足，换个 now_ms 再试")

    rnd16 = random.getrandbits(16) if rnd16 is None else rnd16
    headers = {
        "x-ss-req-ticket": str(j2),
        "x-tt-request-tag": "t=0;n=0",
        "sdk-version": "2",
        "passport-sdk-version": "50561",
        "x-xs-from-web": "0",
        "x-khronos": str(i3),
        "x-ladon": base64.b64encode(be32(i3)).decode(),
        "x-argus": base64.b64encode(le32(i3)).decode(),
        "x-gorgon": gorgon(qs, body, i3, rnd16),
        "x-tt-dt": "",
    }
    if ua:
        headers["User-Agent"] = ua
    return {"url": url + "?" + qs, "headers": headers}


if __name__ == "__main__":
    r = sign("https://api5-normal-sinfonlinea.fqnovel.com/reading/bookapi/search/tab/v1/",
             [("iid", "1905892595382586"), ("device_id", "1905892595378490"), ("aid", "8662"),
              ("query", "斗罗大陆"), ("count", "20"), ("offset", "0")])
    print(r["url"][:160], "...")
    for k, v in r["headers"].items():
        print("  %s: %s" % (k, v))
