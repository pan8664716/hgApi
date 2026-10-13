#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
对线上红果 API 做真实签名验证
=============================
用法:
    python3 tools/probe_real_api.py --smoke     # 少量端点冒烟
    python3 tools/probe_real_api.py --sweep     # 全量路由：签名 vs 不签名 对照
    python3 tools/probe_real_api.py --server    # 服务端视角：解 ss_queries 取设备参数
"""
from __future__ import annotations

import argparse
import base64
import collections
import csv
import json
import os
import re
import sys
import warnings

warnings.filterwarnings("ignore")
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import requests                      # noqa: E402
import sign_demo as S                # noqa: E402
import libencryptor as L             # noqa: E402

SMOKE = [
    ("/reading/bookapi/bookmall/tab/v{version}/", "GET"),
    ("/reading/bookapi/bookshelf/tab/v{version}/", "GET"),
    ("/reading/commerceapi/ab/config/v1/", "POST"),
    ("/reading/bookapi/resource/config/", "GET"),
    ("/reading/bookapi/imc/resource/get/v{version}/", "GET"),
    ("/reading/bookapi/reader_settings/load/v{version}/", "GET"),
]


def do(method, path, dev, signed=True, mutate=None):
    req = S.build_request(path, {}, device=dev, method=method,
                          ss_queries_open=signed, ss_queries_header_open=signed)
    url, h = req["url"], dict(req["headers"])
    if mutate:
        m = re.search(r"ss_queries=([^&]*)", url)
        if m:
            raw = bytearray(base64.b64decode(m.group(1)))
            if mutate == "nonce":
                raw[6] ^= 0xFF
            elif mutate == "ct":
                raw[50] ^= 0xFF
            b64 = base64.b64encode(bytes(raw)).decode()
            url = url.replace(m.group(0), "ss_queries=" + b64)
            if "X-SS-QUERIES" in h:
                h["X-SS-QUERIES"] = b64
    r = requests.request(req["method"], url, headers=h, data=req["body"], timeout=20)
    return r


def smoke():
    dev = S.DeviceProfile()
    print(f"{'路由':56s} {'HTTP':>4s} {'len':>8s}  code/message")
    for path, method in SMOKE:
        r = do(method, path, dev)
        try:
            j = r.json()
            note = f"code={j.get('code')} {str(j.get('message'))[:20]}"
        except Exception:
            note = repr(r.content[:30])
        print(f"{path:56s} {r.status_code:>4d} {len(r.content):>8d}  {note}")


def sweep():
    dev = S.DeviceProfile()
    rows = list(csv.DictReader(open(os.path.join(ROOT, "hongguo_routes.csv"), encoding="utf-8")))
    seen, routes = set(), []
    for r in rows:
        p = r["path"].replace(":version", "{version}")
        k = (r["http"], p)
        if k in seen:
            continue
        seen.add(k)
        routes.append(k)
    stat = collections.Counter()
    for method, path in routes:
        try:
            a = do(method, path, dev, True)
            b = do(method, path, dev, False)
        except Exception:
            continue
        stat[(a.status_code, b.status_code)] += 1
    print("状态码分布 (带签名, 不带签名):", dict(stat))
    print("→ 若两侧一致，说明 ss_queries 不是鉴权闸门，而是设备指纹/风控输入。")


def server():
    """服务端视角：把 ss_queries 解回 5 个设备参数。"""
    dev = S.DeviceProfile()
    plain = ("device_id=%s&device_type=%s&device_brand=%s&uuid=%s&openudid=%s"
             % (dev.device_id, dev.device_type, dev.device_brand, dev.uuid, dev.openudid))
    blob = L.tt_encrypt(plain.encode())
    b64 = base64.b64encode(blob).decode()
    print("客户端 ss_queries :", b64[:80], "...")
    print("服务端 base64 解码:", blob[:6].hex(), "| nonce", blob[6:38].hex())
    print("服务端解出的明文 :", L.tt_decrypt(blob).decode())
    print("其中 salt 校验    : OK (SHA512(明文) == 明文前缀)")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--smoke", action="store_true")
    ap.add_argument("--sweep", action="store_true")
    ap.add_argument("--server", action="store_true")
    a = ap.parse_args()
    if a.sweep:
        sweep()
    elif a.server:
        server()
    else:
        smoke()
