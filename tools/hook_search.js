/*
 * 红果 (com.phoenix.read 7.3.9.32) —— 搜索请求全量 dump
 *
 *   frida -U -f com.phoenix.read -l tools/hook_search.js --no-pause
 *   （本机已验证可用：MuMu 模拟器 127.0.0.1:16416，Android 12，arm64，frida-server 17.16.4）
 *
 * 只打印命中 /search 的请求：最终 URL（含完整 query）、全部请求头。
 * 这是定位「搜索接口不返回数据」的关键证据 —— 看真机到底发了什么。
 */
var T = '[search-hook]';

function dumpHeaders(req) {
    // getHeaders() 返回的 List 在 frida 里不直接暴露 size()/get()，逐级探。
    try {
        var hs = req.getHeaders();
        console.log(T + '    hs.toString=' + hs);
        try { console.log(T + '    hs.class=' + hs.$className); } catch (e) {}
        try { console.log(T + '    hs.size=' + hs.size()); } catch (e) { console.log(T + '    size() err: ' + e); }
        try { console.log(T + '    hs.length=' + hs.length); } catch (e) {}
        try {
            var it = hs.iterator();
            while (it.hasNext()) {
                var h = it.next();
                console.log(T + '    H ' + h.getName() + ': ' + h.getValue());
            }
        } catch (e) { console.log(T + '    iterator err: ' + e); }
    } catch (e) { console.log(T + '    getHeaders() err: ' + e); }
    var probe = ['User-Agent', 'X-SS-QUERIES', 'X-Tt-Token', 'x-tt-token', 'x-gorgon',
                 'x-argus', 'x-khronos', 'x-ladon', 'x-medusa', 'x-helios', 'x-ss-stub',
                 'Cookie', 'x-bd-client-key'];
    for (var i = 0; i < probe.length; i++) {
        try {
            var v = req.getFirstHeader(probe[i]);
            if (v !== null) console.log(T + '    [first] ' + probe[i] + ': ' + v);
        } catch (e) {}
    }
}

function interesting(url) {
    return url.indexOf('/search') >= 0 || url.indexOf('search/') >= 0;
}

Java.perform(function () {
    console.log(T + ' pid=' + Process.id + ' arch=' + Process.arch);

    // 1) 最终请求（TTInternalInterceptor）—— 唯一签名装配点
    try {
        var A = Java.use('dl0.a');
        A.intercept.implementation = function (chain) {
            var req = chain.request();
            var url = req.getUrl();
            if (interesting(url)) {
                console.log(T + ' ===== REQUEST =====');
                console.log(T + ' ' + req.getMethod() + ' ' + url);
                dumpHeaders(req);
                try {
                    var b = req.getBody();
                    if (b) {
                        var buf = Java.use('okio.Buffer').$new();
                        b.writeTo(buf);
                        console.log(T + '    BODY: ' + buf.readUtf8());
                    }
                } catch (e) { console.log(T + '    (body err ' + e + ')'); }
            }
            var resp = this.intercept(chain);
            if (interesting(url)) {
                try {
                    console.log(T + ' ----- RESPONSE -----');
                    console.log(T + '    status=' + resp.getStatus() + '  reason=' + resp.getReason());
                    var hs = resp.getHeaders();
                    for (var i = 0; i < hs.size(); i++) {
                        var n = hs.get(i).getName();
                        if (/logid|content-length|content-type|agw|origin-status/i.test(n)) {
                            console.log(T + '    R ' + n + ': ' + hs.get(i).getValue());
                        }
                    }
                } catch (e) { console.log(T + '    (resp err ' + e + ')'); }
            }
            return resp;
        };
        console.log(T + ' hooked dl0.a');
    } catch (e) { console.log(T + ' dl0.a FAILED: ' + e); }

    // 2) ss_queries / X-SS-QUERIES
    try {
        var REU = Java.use('com.bytedance.frameworks.core.encrypt.RequestEncryptUtils');
        REU.tryEncryptRequest.overload('java.lang.String', 'java.util.List').implementation = function (url, list) {
            var out = this.tryEncryptRequest(url, list);
            if (interesting(url) || interesting(String(out))) {
                console.log(T + ' [encrypt] in : ' + url);
                console.log(T + ' [encrypt] out: ' + out);
            }
            return out;
        };
        console.log(T + ' hooked RequestEncryptUtils');
    } catch (e) { console.log(T + ' RequestEncryptUtils FAILED: ' + e); }

    // 3) 通用参数拼接（含 device_type 等是否留在明文 query）
    try {
        var NP = Java.use('com.bytedance.frameworks.baselib.network.http.NetworkParams');
        NP.addCommonParams.overload('java.lang.String', 'boolean').implementation = function (u, z) {
            var r = this.addCommonParams(u, z);
            if (interesting(String(r))) console.log(T + ' [commonParams] ' + r);
            return r;
        };
        console.log(T + ' hooked NetworkParams.addCommonParams');
    } catch (e) { console.log(T + ' NetworkParams FAILED: ' + e); }

    // 4) 搜索接口的 KMP/RPC 入口，确认 :version 替换后的真实路径
    try {
        var P = Java.use('com.bytedance.multi.rpc.core.proxy.a');
        P.e.overload('java.lang.String', 'java.util.Map').implementation = function (url, map) {
            var r = this.e(url, map);
            if (interesting(String(r)) || interesting(url)) {
                console.log(T + ' [kmp] ' + url + '  ->  ' + r);
            }
            return r;
        };
        console.log(T + ' hooked proxy.a');
    } catch (e) { console.log(T + ' proxy.a FAILED: ' + e); }

    console.log(T + ' ready');
});
