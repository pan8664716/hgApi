#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
搜索接口「不返回数据」定位工具
==============================
用法:
    python3 tools/probe_search.py            # 全矩阵
    python3 tools/probe_search.py --empty    # 全量路由扫描：列出 200 但 body 为空的路由

结论要点（实测）:
  1. /reading/bookapi/search/{page,tab,suggest} 返回 HTTP 200 + Content-Length: 0；
     同一批响应里 **没有** X-Tt-Agw-Login 头（正常的接口都有）。
  2. 加 X-Tt-Token / Cookie: sessionid 完全不影响响应 → 与登录态无关。
  3. 在 query 里额外塞一个**明文** device_type，search/page 会从「空 body」
     变成 {"code":100103,"message":"PARAM_INVALID"} → 说明空 body 是请求
     根本没进业务层（框架层静默失败），而不是「没登录 / 没权限」。
"""
from __future__ import annotations

import argparse
import base64
import collections
import csv
import os
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import requests                        # noqa: E402
import sign_demo as S                  # noqa: E402
import libencryptor as L               # noqa: E402

HOST = "https://api5-normal-sinfonlinea.fqnovel.com"

# 自研客户端 hongguotv-kotlin 0.9.0 里的真实档案（J0/Y.java）
CLIENT = dict(iid="1905892595382586", device_id="1905892595378490", aid=8662,
              app_name="novelread", version_code="71332", version_name="7.1.3.32",
              update_version_code="71332", manifest_version_code="71332",
              os_api="36", os_version="16", device_type="25053RT47C",
              device_brand="Redmi", resolution="1280*2772", dpi="520")
CLIENT_UA = ("com.phoenix.read/72232 (Linux; U; Android 16; zh_CN; 25053RT47C; "
             "Build/BP2A.250605.031.A3)")

SEARCH = [
    ("search/tab", "/reading/bookapi/search/tab/v{version}/",
     {"query": "斗罗大陆", "count": "20", "offset": "0", "tab_type": "0"}),
    ("search/page", "/reading/bookapi/search/page/v{version}/",
     {"query": "斗罗大陆", "count": "20", "offset": "0"}),
    ("search/suggest", "/reading/bookapi/search/suggest/v{version}/",
     {"q": "斗罗", "count": "10"}),
    ("search/search", "/reading/bookapi/search/search/v{version}/",
     {"q": "斗罗大陆", "offset": "0"}),
    ("search/hot-search", "/reading/bookapi/search/hot-search/v{version}/", {"limit": "10"}),
    # 对照组：同 service_class、同 serializer，但能正常返回
    ("search/rank_list", "/reading/bookapi/search/rank_list/v{version}/", {}),
    ("search/user-info", "/reading/bookapi/search/user-info/v{version}/",
     {"query": "斗罗大陆", "count": "10", "offset": "0"}),
    ("bookmall/tab", "/reading/bookapi/bookmall/tab/v{version}/", {}),
]


def show(tag, r):
    note = "EMPTY(0B)" if len(r.content) == 0 else repr(r.content[:70])
    print("%-22s %3d %8d  agw-login=%-5s  %s"
          % (tag, r.status_code, len(r.content),
             "X-Tt-Agw-Login" in r.headers, note))


def matrix():
    dev = S.DeviceProfile(**CLIENT)
    for name, path, params in SEARCH:
        req = S.build_request(path, params, device=dev, method="GET", host=HOST)
        show(name, requests.get(req["url"], headers={"User-Agent": CLIENT_UA}, timeout=20))

    print("\n-- 登录态对照（search/page） --")
    path = "/reading/bookapi/search/page/v{version}/"
    par = {"query": "斗罗大陆", "count": "20", "offset": "0"}
    for tag, h in [
        ("裸请求", {}),
        ("X-Tt-Token", {"X-Tt-Token": "AgQAAAAB"}),
        ("Cookie sessionid", {"Cookie": "sessionid=" + "a" * 32}),
        ("token+cookie", {"X-Tt-Token": "AgQAAAAB", "Cookie": "sessionid=" + "a" * 32}),
        ("x-bd-client-key", {"x-bd-client-key": "AA==", "x-bd-kmsv": "AA=="}),
    ]:
        req = S.build_request(path, par, device=dev, method="GET", host=HOST)
        hh = {"User-Agent": CLIENT_UA}
        hh.update(h)
        show(tag, requests.get(req["url"], headers=hh, timeout=20))

    print("\n-- 明文 device_type 翻转（search/page） --")
    for tag, extra in [("不加 device_type", {}), ("加明文 device_type", {"device_type": "25053RT47C"})]:
        req = S.build_request(path, par, device=dev, method="GET", host=HOST)
        url = req["url"] + ("&" + urllib.parse.urlencode(extra) if extra else "")
        show(tag, requests.get(url, headers={"User-Agent": CLIENT_UA}, timeout=20))

    print("\n-- 服务端视角：ss_queries 可被解出（证明指纹不是问题） --")
    plain = ("device_id=%s&device_type=%s&device_brand=%s&uuid=%s&openudid=%s"
             % (CLIENT["device_id"], CLIENT["device_type"], CLIENT["device_brand"],
                CLIENT["device_id"], "a" * 16))
    blob = L.tt_encrypt(plain.encode())
    print("  ss_queries 明文 =", L.tt_decrypt(blob).decode())


def scan_empty():
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
    empty = []
    for method, path in routes:
        try:
            req = S.build_request(path, {}, device=dev, method=method)
            r = requests.request(req["method"], req["url"], headers=req["headers"],
                                 data=req["body"], timeout=20)
        except Exception:
            continue
        stat[r.status_code] += 1
        if r.status_code == 200 and len(r.content) == 0:
            empty.append((method, path, "X-Tt-Agw-Login" in r.headers))
    print("status:", dict(stat))
    print("HTTP200 但 body 为空的路由（%d）:" % len(empty))
    for m, p, login in empty:
        print("   %-5s %-70s agw-login=%s" % (m, p, login))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--empty", action="store_true", help="全量路由扫描，列出空 body 的 200")
    a = ap.parse_args()
    scan_empty() if a.empty else matrix()
