#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
红果短剧 (com.phoenix.read 7.3.9.32) 请求构造 / 签名复现 Demo

覆盖：
  1. 通用参数 (com.ss.android.common.applog.NetUtil.putCommonParamsWithLevel)
  2. X-SS-QUERIES / ss_queries  (RequestEncryptUtils + native ttEncrypt + Base64)
  3. X-SS-REQ-TICKET
  4. x-bd-client-key / x-bd-kmsv (服务端下发)
  5. X-TT-VERIFY-ID / X-Tt-Token / User-Agent
  6. 路由表查询 (hongguo_routes.csv)

注意：ttEncrypt 是 libEncryptor.so 中的 native 函数（AES 系、控制流平坦化）。
本脚本给出三种接入方式，见 TTEncrypt 类。

用法：
  python3 sign_demo.py --route /reading/bookapi/detail/v{version}/ --param book_id=123456
  python3 sign_demo.py --list bookapi | head
"""

from __future__ import annotations

import argparse
import base64
import csv
import ctypes
import hashlib
import os
import platform
import random
import sys
import time
import urllib.parse
import uuid as _uuid

HERE = os.path.dirname(os.path.abspath(__file__))

# --------------------------------------------------------------------------
# 0. 常量（来自 APK 逆向）
# --------------------------------------------------------------------------

HOSTS = [
    "https://api5-normal-sinfonlineb.fqnovel.com",   # 线上主域名
    "https://api5-normal-sinfonlinea.fqnovel.com",
    "https://api3-normal.fqnovel.com",
    "https://api5-normal.fqnovel.com",
    "https://reading.snssdk.com",                    # KMP RPC 默认 baseUrl
    "https://api.fqnovel.com",
]

DEFAULT_HOST = HOSTS[0]

# 通用参数里「每次请求都要现算」的
def rticket() -> str:
    return str(int(time.time() * 1000))


def _rnd_hex(n: int) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


class DeviceProfile:
    """设备/应用档案：真实抓包时把这些值填成与目标设备一致。"""

    def __init__(self, **kw):
        self.aid = kw.get("aid", 1967)
        self.app_name = kw.get("app_name", "novelread")
        self.version_code = kw.get("version_code", "73932")
        self.version_name = kw.get("version_name", "7.3.9.32")
        self.update_version_code = kw.get("update_version_code", "73932")
        self.manifest_version_code = kw.get("manifest_version_code", "73932")
        self.device_platform = "android"
        self.os = "android"
        self.os_api = kw.get("os_api", "33")
        self.os_version = kw.get("os_version", "13")
        self.device_id = kw.get("device_id", str(random.randint(10**18, 10**19 - 1)))
        self.iid = kw.get("iid", str(random.randint(10**18, 10**19 - 1)))
        self.device_type = kw.get("device_type", "Pixel 7")
        self.device_brand = kw.get("device_brand", "google")
        self.channel = kw.get("channel", "update_64")
        self.ac = kw.get("ac", "wifi")
        self.cdid = kw.get("cdid", _uuid.uuid4().hex)
        self.openudid = kw.get("openudid", _rnd_hex(16))
        self.uuid = kw.get("uuid", self.device_id)
        self.oaid = kw.get("oaid", "")
        self.resolution = kw.get("resolution", "1080x2400")
        self.dpi = kw.get("dpi", "420")
        self.language = kw.get("language", "zh")
        self.ab_version = kw.get("ab_version", "")
        self.ab_client = kw.get("ab_client", "")
        self.ab_group = kw.get("ab_group", "")
        self.ab_feature = kw.get("ab_feature", "")
        self.abflag = kw.get("abflag", "")
        self.klink_egdi = kw.get("klink_egdi", "")

    # 与 NetUtil.putCommonParamsWithLevel 的参数顺序完全一致
    def common_params(self) -> "dict[str, str]":
        p = {}
        if self.klink_egdi:
            p["klink_egdi"] = self.klink_egdi
        p["iid"] = self.iid
        p["device_id"] = self.device_id
        if self.ac:
            p["ac"] = self.ac
        p["channel"] = self.channel
        p["aid"] = str(self.aid)
        p["app_name"] = self.app_name
        p["version_code"] = str(self.version_code)
        p["version_name"] = self.version_name
        p["device_platform"] = self.device_platform
        p["os"] = self.os
        if self.ab_version:
            p["ab_version"] = self.ab_version
        if self.ab_client:
            p["ab_client"] = self.ab_client
        if self.ab_group:
            p["ab_group"] = self.ab_group
        if self.ab_feature:
            p["ab_feature"] = self.ab_feature
        if self.abflag:
            p["abflag"] = self.abflag
        p["ssmix"] = "a"
        p["device_type"] = self.device_type
        p["device_brand"] = self.device_brand
        p["language"] = self.language
        p["os_api"] = str(self.os_api)
        p["os_version"] = self.os_version
        p["openudid"] = self.openudid          # Level.L0
        p["manifest_version_code"] = str(self.manifest_version_code)
        p["resolution"] = self.resolution
        p["dpi"] = str(self.dpi)
        p["update_version_code"] = str(self.update_version_code)
        p["_rticket"] = rticket()
        p["cdid"] = self.cdid
        p["uuid"] = self.uuid                  # Level.L0
        if self.oaid:
            p["oaid"] = self.oaid              # Level.L0
        return p


# --------------------------------------------------------------------------
# 1. ttEncrypt 接入层
# --------------------------------------------------------------------------

class TTEncrypt:
    """
    com.bytedance.frameworks.encryptor.EncryptorUtil.ttEncrypt(byte[] data, int len)

    算法已完整还原并落地为纯 Python 实现（libencryptor.py）：

        rnd[32] = 32 字节随机材料           （原实现 srand(time(NULL)) + rand()&0xff ×32）
        D1      = SHA512(rnd)
        D2      = SHA512(D1 || K)           K = libEncryptor.so .rodata[0xdf50]^[0xdf90] 的 64B
        key,iv  = D2[0:16], D2[16:32]
        salt    = SHA512(data)              明文前缀 64 字节
        ct      = AES-128-CBC(key, iv, PKCS7(salt || data))
        out     = 74 63 05 10 00 00 || rnd[32] || ct

    三种接入方式：
      py      —— libencryptor.tt_encrypt()，纯 Python + PyCryptodome（默认，跨平台）
      emu     —— Unicorn 直接跑 APK 里的 libEncryptor.so（tools/emu_core.py，逐字节一致）
      device  —— 用 glibc rand(seed=now()) 复现真机字节
    """

    def __init__(self, so_path: "str | None" = None, mode: str = "py"):
        self.mode = mode
        self.so_path = so_path or os.path.join(HERE, "libEncryptor.so")
        sys.path.insert(0, HERE)
        import libencryptor as _L
        self._L = _L

    @property
    def available(self) -> bool:
        return True

    def encrypt(self, data: bytes) -> bytes:
        if self.mode == "emu":
            import libencryptor as _L
            return _L.TTEncrypt(self.so_path, mode="emu").encrypt(data)
        if self.mode == "device":
            return self._L.tt_encrypt(data, seed=int(time.time()))
        return self._L.tt_encrypt(data)


TT = TTEncrypt(mode=os.environ.get("TT_MODE", "py"))


# --------------------------------------------------------------------------
# 2. RequestEncryptUtils 复现
# --------------------------------------------------------------------------

SS_QUERY_KEYS = ["device_id", "device_type", "device_brand", "uuid", "openudid"]

# POST 时被 @RpcField(QUERY) 标记、需要走 query 的接口参数名（JSON 名）。
# 从 hongguo_api.json（逆向产物）里动态加载；完整映射见 hongguo_openapi.yaml。
def _load_query_field_hint() -> "set[str]":
    import json as _json
    p = os.path.join(HERE, "hongguo_api.json")
    hint = set()
    try:
        data = _json.load(open(p, encoding="utf-8"))
        for _cls, fs in (data.get("models") or {}).items():
            for f in fs:
                if f.get("in") == "query":
                    hint.add(f["json"])
    except Exception:
        pass
    return hint


_QUERY_FIELD_HINT: "set[str]" = _load_query_field_hint()


def build_ss_queries_plain(query: "dict[str, str]") -> "str | None":
    """按 APK 里 format(list, false, "UTF-8") 的规则拼明文（不做 URLEncode）。"""
    parts = []
    for k in SS_QUERY_KEYS:
        v = query.get(k)
        if v is None or v == "":
            continue
        parts.append("%s=%s" % (k, v))
    return "&".join(parts) if parts else None


def encrypt_queries(url: str, query: "dict[str, str]",
                    headers: "dict[str, str]",
                    ss_queries_open: bool = True,
                    ss_queries_header_open: bool = True,
                    ss_queries_plaintext_open: bool = False,
                    allow_plain_fallback: bool = False):
    """
    对应 RequestEncryptUtils.tryEncryptRequest(url, outHeaders)
    返回 (new_url, query, headers)
    """
    plain = build_ss_queries_plain(query)
    if not plain:
        return url, query, headers

    try:
        cipher = TT.encrypt(plain.encode("utf-8"))
        b64 = base64.b64encode(cipher).decode("ascii")     # Base64.NO_WRAP
    except RuntimeError:
        if not allow_plain_fallback:
            raise
        # 无 native 环境：用明文占位，方便看清将要被加密的内容
        print("[warn] ttEncrypt 不可用，ss_queries 用占位符代替")
        print("[warn] 待加密明文: %s" % plain)
        b64 = "<BASE64(ttEncrypt(%s))>" % plain

    new_q = {}
    if ss_queries_open:
        new_q["ss_queries"] = b64                      # 放在最前
    if ss_queries_header_open:
        headers["X-SS-QUERIES"] = urllib.parse.quote(b64, safe="")   # URLEncoder.encode

    for k, v in query.items():
        if k in SS_QUERY_KEYS and not ss_queries_plaintext_open:
            continue                                    # 明文参数被移除
        new_q[k] = v
    return url, new_q, headers


def md5_stub(body: bytes) -> str:
    """X-SS-STUB（老协议 / pre-privacy 通道）。"""
    return hashlib.md5(body).hexdigest().upper()


# --------------------------------------------------------------------------
# 3. 完整请求构造
# --------------------------------------------------------------------------

def build_request(route: str,
                  params: "dict[str, str] | None" = None,
                  device: "DeviceProfile | None" = None,
                  host: str = DEFAULT_HOST,
                  method: str = "GET",
                  version: str = "1",
                  client_key: str = "",
                  kmsv: str = "",
                  tt_token: str = "",
                  sessionid: str = "",
                  body: "bytes | None" = None,
                  ss_queries_open: bool = True,
                  ss_queries_header_open: bool = True,
                  ):
    """
    组装一个红果 API 请求。

    route  : 路由模板，如 "/reading/bookapi/detail/v:version/" 或 OpenAPI 里的 ".../v{version}/"
    params : 接口自身参数（JSON 名，如 book_id）
    """
    device = device or DeviceProfile()
    params = dict(params or {})

    # 1) :placeholder 替换（com.bytedance.multi.rpc.core.proxy.a.e）
    path = route
    for name in ("version",):
        path = path.replace(":%s" % name, version).replace("{%s}" % name, version)

    # 2) 接口参数 + 通用参数（通用参数在后，且不覆盖已有 key）
    query = {}
    query.update({k: str(v) for k, v in params.items()})
    for k, v in device.common_params().items():
        query.setdefault(k, v)

    headers = {
        "User-Agent": "com.phoenix.read/%s (Linux; U; Android %s; %s; %s; %s; %s; %s)"
                      % (device.version_code, device.os_version, device.language,
                         device.device_type, device.device_brand, device.resolution, device.dpi),
        "Accept-Encoding": "gzip",
    }

    url = host.rstrip("/") + path

    # 3) X-SS-QUERIES / ss_queries
    url, query, headers = encrypt_queries(url, query, headers,
                                          ss_queries_open=ss_queries_open,
                                          ss_queries_header_open=ss_queries_header_open,
                                          allow_plain_fallback=True)

    # 4) X-SS-REQ-TICKET
    headers["X-SS-REQ-TICKET"] = str(int(time.time() * 1000))

    # 5) 服务端下发的动态密钥
    if client_key:
        headers["x-bd-client-key"] = client_key
    if kmsv:
        headers["x-bd-kmsv"] = kmsv

    # 6) 登录态
    if tt_token:
        headers["X-Tt-Token"] = tt_token
    if sessionid:
        headers["Cookie"] = "sessionid=%s" % sessionid

    if method.upper() == "GET":
        final_url = url + "?" + urllib.parse.urlencode(query)
        return {"method": "GET", "url": final_url, "headers": headers, "body": None}

    # POST/FORM：ss_queries 与 @RpcField(QUERY) 参数走 query，其余进 JSON body
    q_only = {}
    if "ss_queries" in query:
        q_only["ss_queries"] = query.pop("ss_queries")
    body_query = {k: v for k, v in query.items() if k in params and k in _QUERY_FIELD_HINT}
    for k in body_query:
        q_only[k] = query.pop(k)
    if q_only:
        url = url + "?" + urllib.parse.urlencode(q_only)

    headers["Content-Type"] = "application/json; charset=utf-8"
    import json as _json
    payload = body if body is not None else _json.dumps(query, ensure_ascii=False).encode("utf-8")
    return {"method": method.upper(), "url": url, "headers": headers, "body": payload}


# --------------------------------------------------------------------------
# 4. 路由表查询
# --------------------------------------------------------------------------

def load_routes():
    p = os.path.join(HERE, "hongguo_routes.csv")
    if not os.path.exists(p):
        return []
    with open(p, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--route", help="路由模板，例如 /reading/bookapi/detail/v{version}/")
    ap.add_argument("--param", action="append", default=[], help="接口参数 k=v，可重复")
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--method", default="GET")
    ap.add_argument("--version", default="1")
    ap.add_argument("--list", help="按 group 列出路由")
    ap.add_argument("--client-key", default="")
    ap.add_argument("--kmsv", default="")
    ap.add_argument("--tt-token", default="")
    args = ap.parse_args()

    if args.list:
        for r in load_routes():
            if r["group"] == args.list:
                print("%-6s %-70s %s" % (r["http"], r["path"], r["method"]))
        return

    if not args.route:
        ap.print_help()
        return

    params = {}
    for kv in args.param:
        k, _, v = kv.partition("=")
        params[k] = v

    req = build_request(args.route, params, host=args.host, method=args.method,
                        version=args.version, client_key=args.client_key,
                        kmsv=args.kmsv, tt_token=args.tt_token)

    print("== 请求 ==")
    print(req["method"], req["url"])
    print("-- headers --")
    for k, v in req["headers"].items():
        print("  %s: %s" % (k, v))
    if req["body"]:
        print("-- body --")
        print(" ", req["body"][:500])
    print()
    print("ttEncrypt 可用:", TT.available)
    if not TT.available:
        print("  -> 把 libEncryptor.so 放到", os.path.join(HERE, "libEncryptor.so"),
              "并在 arm64 Linux/Android 运行，或用 unicorn/frida（见 SIGNATURE.md §3.2）")


if __name__ == "__main__":
    main()
