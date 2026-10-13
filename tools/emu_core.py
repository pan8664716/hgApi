#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
libEncryptor.so (ttEncrypt) ARM64 仿真核心
=========================================
在任意 host 上把 APK 里的 lib/arm64-v8a/libEncryptor.so 跑起来，无需 arm64 硬件。

结构（逆向结论）
  JNI_OnLoad @0xc38
      └─ Zoin VM @0xd94（解释器，指令 4 字节/条，opcode=word&0x3f，分派表 .rodata@0x7ef0）
             ├─ 读 vm->functions[3] 取 JNIEnv*（Zoin 自有的 JavaVM 抽象）
             ├─ 调 host 函数 @0xcb4（通用 3 参调用器）
             └─ 调 host 函数 @0xcd8（XOR 0x73 解出类名 → FindClass → RegisterNatives）
  RegisterNatives 注册 {"ttEncrypt", "([BI)[B", @0x7d8c}
      └─ @0x7d8c  JNI 包装：GetByteArrayElements → malloc(len+118) → @0x2bd8 → NewByteArray/SetByteArrayRegion
             └─ @0x2bd8  再进一层 Zoin VM @0x2d2c（程序 @0xb2d0）
                    └─ AES(T-table) 核心 @0x26e0，密钥扩展 @0x4678，状态填充 @0x65d0/@0x66d4

两个 env 的索引基不同：
  * JNI_OnLoad 期的 env 是标准 JNIEnv（FindClass = index 6）
  * 注册给 native 方法的 env 前置了 27 个 Zoin 私有槽（GetByteArrayElements = index 27+157）
"""
from __future__ import annotations

import struct
import os

from unicorn import *
from unicorn.arm64_const import *

SO_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "libEncryptor.so")

TEXT_BASE, TEXT_SIZE = 0x0, 0x11000
DATA_BASE, DATA_SIZE = 0x17000, 0x4000
STACK_BASE, STACK_SIZE = 0x40000000, 0x800000
TLS_BASE, TLS_SIZE = 0x30000000, 0x10000
HEAP_BASE, HEAP_SIZE = 0x50000000, 0x2000000

ENV_STD, ENV_STD_TABLE = 0x60000000, 0x60010000       # 标准 JNIEnv
ENV_SHIFT, ENV_SHIFT_TABLE = 0x60040000, 0x60050000   # Zoin 前置 27 槽的 env
JVM_PTR, JVM_TABLE = 0x60080000, 0x60090000
ARRAY_BASE, ARRAY_SIZE = 0x68000000, 0x100000

HOOK_BASE, HOOK_SLOT = 0x70000000, 0x10
KIND_BASE = {"libc": 0x0, "priv": 0x1000, "jni": 0x2000, "jvm": 0x3000}

JNI_EXTRA = 27

# ---- 标准 JNI 索引 ---------------------------------------------------------
(JNI_GetVersion, JNI_FindClass, JNI_GetObjectClass, JNI_GetMethodID,
 JNI_GetStaticMethodID, JNI_DeleteLocalRef, JNI_ExceptionCheck, JNI_NewStringUTF,
 JNI_GetStringUTFChars, JNI_GetArrayLength, JNI_NewByteArray,
 JNI_GetByteArrayElements, JNI_ReleaseByteArrayElements, JNI_SetByteArrayRegion,
 JNI_RegisterNatives, JNI_GetJavaVM, JNI_GetStringUTFRegion, JNI_GetStringLength
 ) = (4, 6, 31, 33, 113, 23, 201, 140, 142, 144, 149, 157, 165, 181, 188, 219, 194, 137)

# .got 表项地址 -> 导入名（PLT 桩会 br x17 到这里）
PLT_NAMES = {
    0x17f70: "__cxa_finalize", 0x17f78: "__deregister_frame_info", 0x17f80: "srand",
    0x17f88: "time", 0x17f90: "rand", 0x17f98: "__stack_chk_fail",
    0x17fa0: "__register_frame_info", 0x17fa8: "malloc", 0x17fb0: "memcpy",
    0x17fb8: "memset", 0x17fc0: "free",
}


class Hook:
    def __init__(self, idx, kind, name):
        self.idx, self.kind, self.name = idx, kind, name
        self.addr = HOOK_BASE + (KIND_BASE[kind] + idx) * HOOK_SLOT
        self.calls = 0


class Encryptor:
    def __init__(self, so_path: str = SO_PATH, seed_time: int = 0x5F000000,
                 trace: bool = False, rand_mode: str = "lcg"):
        self.so_path = so_path
        self.blob = open(so_path, "rb").read()
        self.seed_time = seed_time
        self.trace = trace
        self.rand_mode = rand_mode
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.hooks: list[Hook] = []
        self.hook_by_addr: dict[int, Hook] = {}
        self.plt_hook: dict[int, Hook] = {}
        self.heap_ptr = HEAP_BASE + 0x1000
        self.arrays: dict[int, bytearray] = {}
        self.next_array = ARRAY_BASE + 0x100
        self.log: list[str] = []
        self.rand_calls: list[int] = []
        self._rand_state = 0
        self.tt_encrypt_addr = 0x7d8c
        self._setup()

    # ------------------------------------------------------------------ setup
    def _alloc(self, kind, name) -> Hook:
        n = sum(1 for x in self.hooks if x.kind == kind)
        h = Hook(n, kind, name)
        self.hooks.append(h)
        self.hook_by_addr[h.addr] = h
        return h

    def _setup(self):
        uc = self.uc
        uc.mem_map(TEXT_BASE, TEXT_SIZE)
        uc.mem_write(TEXT_BASE, self.blob[:TEXT_SIZE])
        uc.mem_map(DATA_BASE, DATA_SIZE)
        uc.mem_write(0x17cb8, self.blob[0x13cb8:0x13cb8 + 0x368])

        for base, size in ((STACK_BASE, STACK_SIZE), (TLS_BASE, TLS_SIZE),
                           (HEAP_BASE, HEAP_SIZE), (ENV_STD, 0x1000), (ENV_STD_TABLE, 0x1000),
                           (ENV_SHIFT, 0x1000), (ENV_SHIFT_TABLE, 0x1000),
                           (JVM_PTR, 0x1000), (JVM_TABLE, 0x1000),
                           (ARRAY_BASE, ARRAY_SIZE)):
            uc.mem_map(base, size)
        uc.mem_map(HOOK_BASE, 0x80000)

        uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS_BASE)
        uc.mem_write(TLS_BASE + 0x28, struct.pack("<Q", 0xDEADBEEFCAFEBABE))

        # libc：改 .got 表项指向 hook（保留原 PLT 桩代码，让它 br x17 过去）
        for got_addr, name in PLT_NAMES.items():
            h = self._alloc("libc", name)
            self.plt_hook[got_addr] = h
            uc.mem_write(got_addr, struct.pack("<Q", h.addr))

        # 27 个 Zoin 私有槽
        self.priv = [self._alloc("priv", f"priv[{i}]") for i in range(JNI_EXTRA)]
        # 标准 JNI 索引池
        self.jni = {i: self._alloc("jni", f"jni[{i}]") for i in range(0, 205)}
        # JavaVM
        self.jvm = {i: self._alloc("jvm", f"jvm[{i}]") for i in range(0, 8)}

        for i in range(205):
            uc.mem_write(ENV_STD_TABLE + i * 8, struct.pack("<Q", self.jni[i].addr))
            uc.mem_write(ENV_SHIFT_TABLE + (i + JNI_EXTRA) * 8, struct.pack("<Q", self.jni[i].addr))
        for i in range(JNI_EXTRA):
            uc.mem_write(ENV_SHIFT_TABLE + i * 8, struct.pack("<Q", self.priv[i].addr))
        uc.mem_write(ENV_STD, struct.pack("<Q", ENV_STD_TABLE))
        uc.mem_write(ENV_SHIFT, struct.pack("<Q", ENV_SHIFT_TABLE))

        for i in range(8):
            uc.mem_write(JVM_TABLE + i * 8, struct.pack("<Q", self.jvm[i].addr))
        uc.mem_write(JVM_PTR, struct.pack("<Q", JVM_TABLE))

        for h in self.hooks:
            uc.mem_write(h.addr, b"\xc0\x03\x5f\xd6")
        uc.hook_add(UC_HOOK_CODE, self._on_code, begin=HOOK_BASE, end=HOOK_BASE + 0x80000)

    # ------------------------------------------------------------ 寄存器/内存
    def r(self, reg):
        return self.uc.reg_read(reg)

    def w(self, reg, val):
        self.uc.reg_write(reg, val)

    def arg(self, i):
        return self.r([UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
                       UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7][i])

    def set_ret(self, v):
        self.w(UC_ARM64_REG_X0, v)

    def _ret(self):
        self.w(UC_ARM64_REG_PC, self.r(UC_ARM64_REG_LR))

    def rd(self, addr, n):
        return bytes(self.uc.mem_read(addr, n))

    def rdq(self, addr):
        return struct.unpack("<Q", self.rd(addr, 8))[0]

    def wr(self, addr, data):
        self.uc.mem_write(addr, data)

    def _malloc(self, size):
        size = max(size, 1)
        addr = (self.heap_ptr + 0xF) & ~0xF
        self.heap_ptr = addr + size + 0x10
        self.uc.mem_write(addr, b"\x00" * size)
        return addr

    def _new_array(self, n):
        h = self.next_array
        self.next_array += 0x100
        self.arrays[h] = bytearray(n)
        return h

    # ---------------------------------------------------------------- 回调
    def _on_code(self, uc, address, size, user):
        h = self.hook_by_addr.get(address)
        if h is None:
            return
        h.calls += 1
        if h.kind == "libc":
            self._do_libc(h)
        elif h.kind == "jni":
            self._do_jni(h)
        elif h.kind == "priv":
            self._do_priv(h)
        else:
            self._do_jvm(h)

    def _do_libc(self, h):
        name = h.name
        a = [self.arg(i) for i in range(5)]
        if name == "malloc":
            self.set_ret(self._malloc(a[0]))
        elif name == "free":
            self.set_ret(0)
        elif name == "memcpy":
            # memcpy(dst, src, n)：a[0]=dst, a[1]=src
            if a[2]:
                self.wr(a[0], self.rd(a[1], a[2]))
            self.set_ret(a[0])
        elif name == "memset":
            if a[2]:
                self.wr(a[0], bytes([a[1] & 0xFF]) * a[2])
            self.set_ret(a[0])
        elif name == "srand":
            self._rand_state = a[0] & 0xFFFFFFFF
            self.set_ret(0)
        elif name == "time":
            self.set_ret(self.seed_time)
        elif name == "rand":
            if self.rand_mode == "lcg":
                self._rand_state = (self._rand_state * 1103515245 + 12345) & 0x7FFFFFFF
            elif self.rand_mode == "glibc":
                self._rand_state = (self._rand_state * 1103515245 + 12345) & 0xFFFFFFFF
            else:
                self._rand_state = 0x12345678
            self.rand_calls.append(self._rand_state)
            self.set_ret(self._rand_state)
        elif name == "__stack_chk_fail":
            raise RuntimeError("emulated __stack_chk_fail")
        else:
            self.set_ret(0)
        self._ret()

    def _do_priv(self, h):
        a = [self.arg(i) for i in range(4)]
        self.log.append(f"priv[{h.idx}] args={[hex(x) for x in a]}")
        self.set_ret(0)
        self._ret()

    def _do_jvm(self, h):
        a = [self.arg(i) for i in range(4)]
        if h.idx in (3, 4, 6, 7):        # Zoin GetEnv / Attach*：回填标准 JNIEnv*
            if a[1]:
                self.wr(a[1], struct.pack("<Q", ENV_STD))
            if self.trace:
                self.log.append(f"JavaVM[{h.idx}](vm={a[0]:#x}, out={a[1]:#x}, ver={a[2]:#x}) -> ENV_STD")
            self.set_ret(0)
        else:
            self.set_ret(0)
        self._ret()

    def _do_jni(self, h):
        i = h.idx
        a = [self.arg(k) for k in range(8)]
        if i == JNI_GetVersion:
            self.set_ret(0x00010006)
        elif i == JNI_FindClass:
            self.set_ret(0x12340001)                       # 非空假 jclass
        elif i == JNI_GetObjectClass:
            self.set_ret(0x12340001)
        elif i in (JNI_GetMethodID, JNI_GetStaticMethodID):
            self.set_ret(0x12360001)
        elif i == JNI_NewStringUTF:
            self.set_ret(0x12350001)
        elif i == JNI_GetStringUTFChars:
            self.set_ret(a[2] or 0x12370001)
        elif i == JNI_GetStringLength:
            self.set_ret(0)
        elif i == JNI_GetArrayLength:
            self.set_ret(len(self.arrays.get(a[1], b"")))
        elif i == JNI_GetByteArrayElements:
            arr, is_copy = a[1], a[2]
            data = bytes(self.arrays.get(arr, b""))
            buf = self._malloc(len(data) + 8)
            if data:
                self.wr(buf, data)
            if self.trace:
                self.log.append(f"GetByteArrayElements(h={arr:#x}, len={len(data)}) -> {buf:#x}")
            self.set_ret(buf)
        elif i == JNI_NewByteArray:
            self.set_ret(self._new_array(a[1]))
        elif i == JNI_SetByteArrayRegion:
            arr, start, n, buf = a[1], a[2], a[3], a[4]
            if arr in self.arrays and n:
                self.arrays[arr][start:start + n] = self.rd(buf, n)
            self.set_ret(0)
        elif i == JNI_ReleaseByteArrayElements:
            self.set_ret(0)
        elif i == JNI_RegisterNatives:
            cls, methods, n = a[1], a[2], a[3]
            for k in range(n):
                np_, sp_, fn = (self.rdq(methods + k * 24), self.rdq(methods + k * 24 + 8),
                                self.rdq(methods + k * 24 + 16))
                nm = self.rd(np_, 64).split(b"\x00")[0].decode("latin1")
                sg = self.rd(sp_, 64).split(b"\x00")[0].decode("latin1")
                self.log.append(f"RegisterNatives({nm!r}, {sg!r}, {fn:#x})")
                if nm == "ttEncrypt":
                    self.tt_encrypt_addr = fn
            self.set_ret(0)
        elif i in (JNI_DeleteLocalRef, JNI_ExceptionCheck, JNI_GetStringUTFRegion):
            self.set_ret(0)
        elif i == JNI_GetJavaVM:
            self.wr(a[1], struct.pack("<Q", JVM_PTR))
            self.set_ret(0)
        else:
            self.log.append(f"!! unhandled JNI index={i} args={[hex(x) for x in a[:5]]}")
            self.set_ret(0)
        self._ret()

    # ---------------------------------------------------------------- 调用
    def _call(self, addr, args, ret_reg=UC_ARM64_REG_X0, count=200_000_000):
        uc = self.uc
        sp = (STACK_BASE + STACK_SIZE - 0x1000) & ~0xF
        self.wr(sp, b"\x00" * 0x100)
        self.w(UC_ARM64_REG_SP, sp)
        self.w(UC_ARM64_REG_LR, 0)
        self.w(UC_ARM64_REG_FP, 0)
        for i, v in enumerate(args):
            self.w([UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                    UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5][i], v)
        uc.emu_start(addr, 0, count=count)
        return self.r(ret_reg)

    def init(self):
        """执行 JNI_OnLoad，完成 Zoin VM 全局初始化并取得 ttEncrypt 原生函数地址。"""
        ret = self._call(0xc38, [JVM_PTR, 0])
        if self.trace:
            self.log.append(f"JNI_OnLoad -> {ret:#x}")
        return self.tt_encrypt_addr

    def tt_encrypt(self, data: bytes, env=None):
        """等价于 Java 侧 EncryptorUtil.ttEncrypt(byte[] data, int len) -> byte[]"""
        arr = self._new_array(len(data))
        self.arrays[arr] = bytearray(data)
        out = self._call(self.tt_encrypt_addr,
                         [ENV_SHIFT if env is None else env, 0x20000000, arr, len(data)])
        if not out:
            return None
        return bytes(self.arrays.get(out, b""))


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(description="Unicorn ARM64 跑真 libEncryptor.so 的 ttEncrypt")
    ap.add_argument("text", nargs="*", help="待加密文本（默认 hello）")
    ap.add_argument("--seed", type=lambda x: int(x, 0), default=0x5F000000,
                    help="伪造 time() 的返回值（决定 rand 序列）")
    ap.add_argument("--trace", action="store_true")
    args = ap.parse_args(argv)
    data = (" ".join(args.text) or "hello").encode()
    e = Encryptor(trace=args.trace, seed_time=args.seed)
    e.init()
    out = e.tt_encrypt(data)
    print(f"ttEncrypt @ {e.tt_encrypt_addr:#x}")
    print(f"in  ({len(data):4d}B): {data!r}")
    print(f"out ({len(out) if out else 0:4d}B): {out.hex() if out else None}")
    for l in e.log:
        print("  [log]", l)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main(sys.argv[1:]))
