#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""纯 Python 复现 vs Unicorn 跑真 .so 的对拍自检。"""
import os, sys, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from emu_core import Encryptor
import libencryptor as L

def main():
    emu = Encryptor(); emu.init()
    random.seed(20261010)
    ok = fail = 0
    lens = list(range(1, 40)) + [48, 63, 64, 65, 80, 100, 127, 128, 129, 200, 255, 256, 500, 1000]
    for n in lens:
        msg = bytes(random.randrange(256) for _ in range(n))
        e = emu.tt_encrypt(msg)
        rnd = e[6:38]
        p = L.tt_encrypt(msg, rnd=rnd)
        if p == e:
            ok += 1
        else:
            fail += 1
            print(f"MISMATCH len={n}\n  emu={e.hex()}\n  py ={p.hex()}")
        # 反向自检
        if L.tt_decrypt(e) != msg:
            fail += 1
            print(f"DECRYPT FAIL len={n}")
    print(f"对拍结果: OK={ok} FAIL={fail}  (共 {len(lens)} 组)")
    return 0 if fail == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
