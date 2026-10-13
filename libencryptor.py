#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
libEncryptor.so / ttEncrypt 纯 Python 复现
=========================================
对应 APK 内 lib/arm64-v8a/libEncryptor.so 的
    com.bytedance.frameworks.encryptor.EncryptorUtil.ttEncrypt(byte[] data, int len)

完整算法（静态还原 + Unicorn 动态对拍确认，见 TTENCRYPT.md）
--------------------------------------------------------------
    rnd[32] = 32 字节随机材料           (原实现: srand(time(NULL)) + rand() & 0xff ×32)
    D1      = SHA512(rnd)
    D2      = SHA512(D1 || K)           K = .rodata 中 64 字节常量 (0xdf50 ^ 0xdf90)
    key     = D2[0:16]                  AES-128 密钥
    iv      = D2[16:32]                 AES-128-CBC IV
    salt    = SHA512(data)              明文前缀(64 字节)
    body    = salt || data
    ct      = AES-128-CBC(key, iv, PKCS7(body))
    out     = 74 63 05 10 00 00 || rnd[32] || ct

用法
----
    from libencryptor import tt_encrypt
    tt_encrypt(b"device_id=1&device_type=2")   # -> bytes
"""
from __future__ import annotations

import hashlib
import os
import struct
import time

__all__ = ["tt_encrypt", "derive_key_iv", "MAGIC", "KDF_SALT", "TTEncrypt"]

MAGIC = bytes((0x74, 0x63, 0x05, 0x10, 0x00, 0x00))
BLOCK = 16

# 密钥派生常量：libEncryptor.so .rodata 0xdf50[0:64] XOR 0xdf90[0:64]
KDF_SALT = bytes.fromhex(
    "4dd4c2e6b83162090e52b3c7a6733ba41cb2462b829ab58a196b39db57177524"
    "f49baf7f08e8d68d26a72e37c1a95a2f1f05a51892aef2949732b62a38aadd58"
)


# ---------------------------------------------------------------- AES-128-CBC
def _aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """优先用 PyCryptodome；不可用时退化为纯 Python AES 实现。"""
    try:
        from Crypto.Cipher import AES
        return AES.new(key, AES.MODE_CBC, iv).encrypt(data)
    except Exception:
        return _PureAES_CBC(key, iv).encrypt(data)


class _PureAES_CBC:
    """纯 Python AES-128-CBC（无第三方依赖时的兜底）。"""

    SBOX = None
    RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)

    @classmethod
    def _sbox(cls):
        if cls.SBOX is None:
            p = q = 1
            sbox = [0] * 256
            while True:
                p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
                q ^= (q << 1) & 0xFF
                q ^= (q << 2) & 0xFF
                q ^= (q << 4) & 0xFF
                if q & 0x80:
                    q ^= 0x09
                x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) \
                      ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))
                sbox[p] = (x ^ 0x63) & 0xFF
                if p == 1:
                    break
            sbox[0] = 0x63
            cls.SBOX = sbox
        return cls.SBOX

    def __init__(self, key: bytes, iv: bytes):
        self.sbox = self._sbox()
        self.rk = self._expand(key)
        self.iv = iv

    @staticmethod
    def _xtime(a):
        a <<= 1
        return (a ^ 0x1B) & 0xFF if a & 0x100 else a

    def _expand(self, key: bytes):
        sbox = self.sbox
        nk = len(key) // 4
        nr = nk + 6
        w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
        for i in range(nk, 4 * (nr + 1)):
            t = list(w[i - 1])
            if i % nk == 0:
                t = t[1:] + t[:1]
                t = [sbox[b] for b in t]
                t[0] ^= self.RCON[i // nk - 1]
            elif nk > 6 and i % nk == 4:
                t = [sbox[b] for b in t]
            w.append([w[i - nk][j] ^ t[j] for j in range(4)])
        return [bytes(b for word in w[4 * r:4 * r + 4] for b in word)
                for r in range(nr + 1)]

    def _encrypt_block(self, blk: bytes) -> bytes:
        s = [b ^ k for b, k in zip(blk, self.rk[0])]
        for rnd in range(1, len(self.rk)):
            s = [self.sbox[b] for b in s]
            # ShiftRows
            s = [s[0], s[5], s[10], s[15],
                 s[4], s[9], s[14], s[3],
                 s[8], s[13], s[2], s[7],
                 s[12], s[1], s[6], s[11]]
            if rnd != len(self.rk) - 1:
                # MixColumns
                out = [0] * 16
                for c in range(4):
                    a = s[4 * c:4 * c + 4]
                    t = a[0] ^ a[1] ^ a[2] ^ a[3]
                    out[4 * c + 0] = a[0] ^ t ^ self._xtime(a[0] ^ a[1])
                    out[4 * c + 1] = a[1] ^ t ^ self._xtime(a[1] ^ a[2])
                    out[4 * c + 2] = a[2] ^ t ^ self._xtime(a[2] ^ a[3])
                    out[4 * c + 3] = a[3] ^ t ^ self._xtime(a[3] ^ a[0])
                s = out
            s = [b ^ k for b, k in zip(s, self.rk[rnd])]
        return bytes(s)

    def encrypt(self, data: bytes) -> bytes:
        prev = self.iv
        out = bytearray()
        for i in range(0, len(data), BLOCK):
            blk = bytes(x ^ y for x, y in zip(data[i:i + BLOCK], prev))
            prev = self._encrypt_block(blk)
            out += prev
        return bytes(out)


# ---------------------------------------------------------------- rand (设备侧)
class GlibcRand:
    """glibc rand() 的 TYPE_3（默认）实现，用于按 seed 复现设备字节。"""

    def __init__(self, seed: int = 1):
        self.srand(seed)

    def srand(self, seed: int):
        seed &= 0xFFFFFFFF
        if seed == 0:
            seed = 1
        self.r = [0] * 344
        self.r[0] = seed
        for i in range(1, 31):
            self.r[i] = (16807 * self.r[i - 1]) % 2147483647
            if self.r[i] < 0:
                self.r[i] += 2147483647
        for i in range(31, 34):
            self.r[i] = self.r[i - 31]
        for i in range(34, 344):
            self.r[i] = (self.r[i - 31] + self.r[i - 3]) & 0xFFFFFFFF
        self.idx = 344

    def rand(self) -> int:
        if self.idx >= 344:
            for i in range(344 - 31):
                self.r[i] = (self.r[i + 31] + self.r[i + 3]) & 0xFFFFFFFF
            self.idx = 344 - 31
        val = self.r[self.idx] >> 1
        self.idx += 1
        return val


def _nonce_from_glibc(seed: int) -> bytes:
    r = GlibcRand(seed)
    return bytes(r.rand() & 0xFF for _ in range(32))


# ---------------------------------------------------------------- 主流程
def derive_key_iv(rnd: bytes) -> tuple[bytes, bytes]:
    """rnd(32B) -> (key16, iv16)"""
    if len(rnd) != 32:
        raise ValueError("rnd 必须是 32 字节")
    d1 = hashlib.sha512(rnd).digest()
    d2 = hashlib.sha512(d1 + KDF_SALT).digest()
    return d2[0:16], d2[16:32]


def _pkcs7(data: bytes) -> bytes:
    n = BLOCK - (len(data) % BLOCK)
    return data + bytes([n]) * n


def tt_encrypt(data: bytes, rnd: bytes | None = None,
               seed: int | None = None) -> bytes:
    """等价于 native ttEncrypt(byte[] data, int len) -> byte[]。

    rnd  : 指定 32 字节随机材料（不给则 os.urandom）
    seed : 指定 srand 种子，用 glibc rand() 生成 rnd（复现真机字节时使用）
    """
    data = bytes(data)
    if rnd is None:
        if seed is not None:
            rnd = _nonce_from_glibc(seed)
        else:
            rnd = os.urandom(32)
    key, iv = derive_key_iv(rnd)
    body = hashlib.sha512(data).digest() + data
    ct = _aes_cbc_encrypt(key, iv, _pkcs7(body))
    return MAGIC + rnd + ct


def tt_decrypt(blob: bytes) -> bytes:
    """反向解析（服务端视角），用于自检。"""
    if blob[:6] != MAGIC:
        raise ValueError("bad magic")
    rnd, ct = blob[6:38], blob[38:]
    key, iv = derive_key_iv(rnd)
    try:
        from Crypto.Cipher import AES
        body = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    except Exception:
        raise RuntimeError("需要 PyCryptodome 才能解密")
    pad = body[-1]
    body = body[:-pad]
    salt, data = body[:64], body[64:]
    if hashlib.sha512(data).digest() != salt:
        raise ValueError("salt 校验失败")
    return data


class TTEncrypt:
    """sign_demo.py 的接入层：优先纯 Python，其次 Unicorn 仿真真 .so。"""

    def __init__(self, so_path: str | None = None, mode: str = "auto"):
        self.mode = mode
        self.so_path = so_path
        self._emu = None

    @property
    def available(self) -> bool:
        return True

    def _emulator(self):
        if self._emu is None:
            import sys
            sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools"))
            from emu_core import Encryptor
            e = Encryptor(self.so_path or os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "libEncryptor.so"))
            e.init()
            self._emu = e
        return self._emu

    def encrypt(self, data: bytes) -> bytes:
        if self.mode == "emu":
            return self._emulator().tt_encrypt(data)
        if self.mode == "device":
            return tt_encrypt(data, seed=int(time.time()))
        return tt_encrypt(data)


if __name__ == "__main__":
    import sys
    msg = sys.argv[1].encode() if len(sys.argv) > 1 else b"hello"
    out = tt_encrypt(msg)
    print("in :", msg)
    print("out:", out.hex())
    print("len:", len(out))
    print("rt :", tt_decrypt(out))
