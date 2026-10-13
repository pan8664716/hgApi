/*
 * 红果短剧 (com.phoenix.read 7.3.9.32) 请求签名材料 dump
 *
 *   frida -U -f com.phoenix.read -l hook_hongguo.js --no-pause
 *   frida -U -n 红果免费短剧 -l hook_hongguo.js
 *
 * 输出：通用参数、ss_queries 明文/密文、ttEncrypt 输入输出、
 *       x-bd-client-key/x-bd-kmsv、最终请求头、metasec 安全因子。
 */

var LOGTAG = '[hongguo]';

function b64(bytes) {
    try {
        return Java.use('android.util.Base64').encodeToString(bytes, 2); // NO_WRAP
    } catch (e) { return '<b64 err>'; }
}

function bytesToStr(arr) {
    try { return Java.array('byte', arr).toString(); } catch (e) { return '<bytes>'; }
}

function safe(name, fn) {
    try { fn(); } catch (e) { console.log(LOGTAG + ' hook ' + name + ' failed: ' + e); }
}

Java.perform(function () {
    console.log(LOGTAG + ' start, pid=' + Process.id);

    // ---------------------------------------------------------------- 1. 通用参数
    safe('NetUtil.addCommonParamsWithLevel', function () {
        var NetUtil = Java.use('com.ss.android.common.applog.NetUtil');
        NetUtil.addCommonParamsWithLevel.overload(
            'java.lang.String', 'boolean', 'com.bytedance.bdinstall.Level'
        ).implementation = function (url, z, lv) {
            var r = this.addCommonParamsWithLevel(url, z, lv);
            console.log(LOGTAG + ' [commonParams] ' + r);
            return r;
        };
        // putCommonParams（部分链路直接往 map 里塞）
        NetUtil.putCommonParamsWithLevel.overload(
            'java.util.Map', 'boolean', 'com.bytedance.bdinstall.Level'
        ).implementation = function (m, z, lv) {
            this.putCommonParamsWithLevel(m, z, lv);
            console.log(LOGTAG + ' [commonParams(map)] ' + m.toString());
        };
    });

    // ------------------------------------------------------- 2. 应用侧 ApiProcessHook
    safe('od3.a', function () {
        var A = Java.use('od3.a');
        A.addCommonParams.overload('java.lang.String', 'boolean').implementation = function (u, z) {
            var r = this.addCommonParams(u, z);
            console.log(LOGTAG + ' [ApiProcessHook] ' + r);
            return r;
        };
    });

    // -------------------------------------------------- 3. ss_queries / X-SS-QUERIES
    safe('RequestEncryptUtils', function () {
        var REU = Java.use('com.bytedance.frameworks.core.encrypt.RequestEncryptUtils');
        REU.tryEncryptRequest.overload('java.lang.String', 'java.util.List').implementation = function (url, list) {
            console.log(LOGTAG + ' [tryEncryptRequest] in : ' + url);
            var r = this.tryEncryptRequest(url, list);
            console.log(LOGTAG + ' [tryEncryptRequest] out: ' + r);
            try {
                for (var i = 0; i < list.size(); i++) {
                    var p = list.get(i);
                    console.log(LOGTAG + '   header ' + p.first + ' = ' + p.second);
                }
            } catch (e) {}
            return r;
        };
    });

    // ------------------------------------------------------------ 4. ttEncrypt 原始 I/O
    safe('EncryptorUtil', function () {
        var Enc = Java.use('com.bytedance.frameworks.encryptor.EncryptorUtil');
        Enc.a.overload('[B', 'int').implementation = function (b, n) {
            var out = this.a(b, n);
            console.log(LOGTAG + ' [ttEncrypt] len=' + n + ' plain=' + bytesToStr(b));
            console.log(LOGTAG + ' [ttEncrypt] out  =' + (out ? b64(out) : 'null'));
            return out;
        };
    });

    // ------------------------------------------------- 5. 服务端下发动态密钥
    safe('ClientKeyManager', function () {
        var CKM = Java.use('com.bytedance.ttnet.clientkey.ClientKeyManager');
        CKM.d.implementation = function (req, resp) {
            var r = this.d(req, resp);
            console.log(LOGTAG + ' [ClientKey] url=' + req.getUrl());
            console.log(LOGTAG + '   client_key=' + this.c.value + '  kmsv=' + this.f.value);
            try {
                var l = resp.headers('x-bd-lanusk');
                var v = resp.headers('x-bd-lanusv');
                console.log(LOGTAG + '   resp x-bd-lanusk=' + l + '  x-bd-lanusv=' + v);
            } catch (e) {}
            return r;
        };
        CKM.getClientKeyHeaders.implementation = function () {
            var m = this.getClientKeyHeaders();
            console.log(LOGTAG + ' [ClientKey] headers=' + m);
            return m;
        };
    });

    // --------------------------------------------- 6. 最终请求头（TTInternalInterceptor）
    safe('dl0.a', function () {
        var A = Java.use('dl0.a');
        A.intercept.implementation = function (chain) {
            var req = chain.request();
            console.log(LOGTAG + ' [final] ' + req.getUrl());
            try {
                var hs = req.getHeaders();
                for (var i = 0; i < hs.size(); i++) {
                    console.log(LOGTAG + '    ' + hs.get(i).getName() + ': ' + hs.get(i).getValue());
                }
            } catch (e) {}
            return this.intercept(chain);
        };
    });

    // ------------------------------------------------------ 7. metasec 安全因子
    safe('NetworkParams.tryAddSecurityFactor', function () {
        var NP = Java.use('com.bytedance.frameworks.baselib.network.http.NetworkParams');
        NP.tryAddSecurityFactor.implementation = function (url, map) {
            var r = this.tryAddSecurityFactor(url, map);
            console.log(LOGTAG + ' [securityFactor] url=' + url + ' -> ' + r);
            return r;
        };
    });

    // ------------------------------------------------------------- 8. KMP RPC 层
    safe('proxy.a', function () {
        var P = Java.use('com.bytedance.multi.rpc.core.proxy.a');
        P.e.overload('java.lang.String', 'java.util.Map').implementation = function (url, map) {
            var r = this.e(url, map);
            console.log(LOGTAG + ' [kmp:placeholder] ' + url + ' -> ' + r);
            return r;
        };
    });

    console.log(LOGTAG + ' hooks installed');
});

// ---------------------------------------------------------------- native 侧
// libEncryptor.so 的 ttEncrypt 是 JNI 导出（非导出符号），用 frida 抓 Java 层即可；
// 若要直接看 native 入参，可在 JNI_OnLoad 返回后对 0xd94（ARM64 偏移）下断：
//   var m = Process.getModuleByName('libEncryptor.so');
//   Interceptor.attach(m.base.add(0xd94), {
//     onEnter(args) { console.log('ttEncrypt core, x0=' + args[0] + ' x1=' + args[1]); }
//   });
