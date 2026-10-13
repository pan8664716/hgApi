/*
 * hongguo_unpin.js
 * 目标: com.phoenix.read (红果免费短剧 7.3.9.32)
 * 栈:  libsscronet.so (Cronet) -> libttboringssl.so (BoringSSL API) -> libttcrypto.so (BoringSSL 实现)
 *      libttmverify.so / libttmverifylite.so (ByteDance Cronet 自定义证书校验 C API)
 *
 * 静态依据:
 *   libttcrypto.so      X509_verify_cert            @0xdab60  (返回 1 = 链校验通过)
 *   libttcrypto.so      X509_STORE_CTX_get_error    @0xdbe78  (返回 0 = X509_V_OK)
 *   libttboringssl.so   SSL_CTX_set_custom_verify   @0x49dac  (mode=0/cb=NULL => 不做校验)
 *   libttboringssl.so   SSL_CTX_set_verify          @0x50810
 *   libttboringssl.so   SSL_get_verify_result       @0x50834
 *   libttmverifylite.so vcn_internal_custom_verify_android  (返回 0 = ssl_verify_ok)
 *   libttmverify.so     vcn_custom_verify_2                 (返回 0 = ssl_verify_ok)
 *   libttmverifylite.so convertToVerifyRet          (w0 = (w0-1 < 4) ? 1 : 0)
 */
'use strict';

var T0 = Date.now();
function log(s) { console.log('[unpin +' + ((Date.now() - T0) / 1000).toFixed(1) + 's] ' + s); }

/* ------------------------------------------------------------------ */
/* 1) Native: BoringSSL / Cronet 证书校验                              */
/* ------------------------------------------------------------------ */

var HITTED = {};

function hookExport(mod, sym, handlers) {
    var key = mod + '!' + sym;
    if (HITTED[key] === 'hooked') return true;
    var addr;
    try { addr = Process.getModuleByName(mod).getExportByName(sym); } catch (e) { return false; }
    try {
        Interceptor.attach(addr, handlers);
        HITTED[key] = 'hooked';
        log('HOOKED  ' + key + '  @ ' + addr);
        return true;
    } catch (e) {
        HITTED[key] = 'fail';
        log('FAIL    ' + key + ' : ' + e);
        return false;
    }
}

var NATIVE_HOOKS = [
    /* ---- 最深层: BoringSSL 链校验 ---- */
    { mod: 'libttcrypto.so', sym: 'X509_verify_cert',
      onEnter: function (a) { log('>> X509_verify_cert(ctx=' + a[0] + ')'); },
      onLeave: function (r) { if (r.toInt32() !== 1) log('<< X509_verify_cert -> 1 (was ' + r + ')'); r.replace(1); } },

    { mod: 'libttcrypto.so', sym: 'X509_STORE_CTX_get_error',
      onLeave: function (r) { r.replace(0); } },

    /* ---- BoringSSL API 层: 关掉 custom verify ---- */
    { mod: 'libttboringssl.so', sym: 'SSL_CTX_set_custom_verify',
      onEnter: function (a) { log('>> SSL_CTX_set_custom_verify(mode=' + a[1] + ', cb=' + a[2] + ') -> 强制 NONE'); a[1] = ptr(0); a[2] = ptr(0); } },

    { mod: 'libttboringssl.so', sym: 'SSL_CTX_set_verify',
      onEnter: function (a) { log('>> SSL_CTX_set_verify(mode=' + a[1] + ') -> 强制 NONE'); a[1] = ptr(0); a[2] = ptr(0); } },

    { mod: 'libttboringssl.so', sym: 'SSL_get_verify_result',
      onLeave: function (r) { if (r.toInt32() !== 0) log('<< SSL_get_verify_result -> 0 (was ' + r + ')'); r.replace(0); } },

    /* ---- ByteDance Cronet 自定义校验回调 ---- */
    { mod: 'libttmverifylite.so', sym: 'vcn_internal_custom_verify_android',
      onEnter: function () { log('>> vcn_internal_custom_verify_android'); },
      onLeave: function (r) { if (r.toInt32() !== 0) log('<< vcn_internal_custom_verify_android -> 0 (was ' + r + ')'); r.replace(0); } },

    { mod: 'libttmverifylite.so', sym: 'convertToVerifyRet',
      onLeave: function (r) { r.replace(0); } },

    { mod: 'libttmverify.so', sym: 'vcn_custom_verify_2',
      onEnter: function () { log('>> vcn_custom_verify_2'); },
      onLeave: function (r) { if (r.toInt32() !== 0) log('<< vcn_custom_verify_2 -> 0 (was ' + r + ')'); r.replace(0); } },

    /* ---- 阻止注册校验回调 ---- */
    { mod: 'libsscronet.so', sym: 'tt_set_verify_callback',
      onEnter: function () { log('>> tt_set_verify_callback -> 丢弃'); this.drop = true; },
      onLeave: function (r) { r.replace(0); } },

    { mod: 'libsscronet.so', sym: 'set_vcn_custom_verify_callback',
      onEnter: function () { log('>> set_vcn_custom_verify_callback -> 丢弃'); },
      onLeave: function (r) { r.replace(0); } }
];

var TARGET_RE = /lib(sscronet|ttboringssl|ttcrypto|ttmverify|ttmverifylite|vcnverify|vcnverifylite|vcn)\.so$/;

function tryHookAll() {
    var n = 0;
    NATIVE_HOOKS.forEach(function (h) { if (hookExport(h.mod, h.sym, { onEnter: h.onEnter, onLeave: h.onLeave })) n++; });
    return n;
}

/* 模块加载监听: 新模块一加载就立刻挂 (Frida 17: Module.findGlobalExportByName) */
(function watchLoads() {
    var find = (typeof Module.findGlobalExportByName === 'function')
        ? Module.findGlobalExportByName
        : function (n) { try { return Module.findExportByName(null, n); } catch (e) { return null; } };
    ['android_dlopen_ext', 'dlopen'].forEach(function (s) {
        var p = null;
        try { p = find(s); } catch (e) {}
        if (!p) { log('dlopen-watch ' + s + ' 未找到'); return; }
        try {
            Interceptor.attach(p, {
                onEnter: function (args) { try { this.path = args[0].readCString(); } catch (e) { this.path = null; } },
                onLeave: function () { if (this.path && TARGET_RE.test(this.path)) setTimeout(tryHookAll, 0); }
            });
            log('HOOKED  dlopen-watch ' + s);
        } catch (e) { log('dlopen-watch ' + s + ' 失败: ' + e); }
    });
})();

/* 轮询兜底 */
var tries = 0, lastOk = 0;
var iv = setInterval(function () {
    tries++;
    tryHookAll();
    var ok = NATIVE_HOOKS.filter(function (h) { return HITTED[h.mod + '!' + h.sym] === 'hooked'; }).length;
    if (ok !== lastOk) { lastOk = ok; log('native hooks: ' + ok + '/' + NATIVE_HOOKS.length + ' 已装载'); }
    if (ok === NATIVE_HOOKS.length || tries > 2400) clearInterval(iv);
}, 250);

/* ------------------------------------------------------------------ */
/* 2) Java 层兜底 (OkHttp / Conscrypt)                                  */
/* ------------------------------------------------------------------ */
setTimeout(function () {
    if (!Java.available) return;
    Java.perform(function () {
        function jtry(name, fn) { try { fn(); log('JAVA  + ' + name); } catch (e) { log('JAVA  - ' + name + ' : ' + e); } }

        jtry('okhttp3.CertificatePinner.check(String,List)', function () {
            var P = Java.use('okhttp3.CertificatePinner');
            P.check.overload('java.lang.String', 'java.util.List').implementation = function (h) {
                log('JAVA  >> OkHttp pinner 放行 ' + h); return;
            };
        });
        jtry('okhttp3.CertificatePinner.check(String,Certificate[])', function () {
            var P = Java.use('okhttp3.CertificatePinner');
            P.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (h) {
                log('JAVA  >> OkHttp pinner[] 放行 ' + h); return;
            };
        });
        jtry('okhttp3.CertificatePinner.check$okhttp', function () {
            var P = Java.use('okhttp3.CertificatePinner');
            P.check$okhttp.overload('java.lang.String', 'kotlin.jvm.functions.Function0').implementation = function (h) { return; };
        });
        jtry('TrustManagerImpl.verifyChain', function () {
            var T = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            T.verifyChain.implementation = function (untrustedChain) { log('JAVA  >> TrustManagerImpl.verifyChain 放行'); return untrustedChain; };
        });
        jtry('TrustManagerImpl.checkTrustedRecursive', function () {
            var T = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            var AL = Java.use('java.util.ArrayList');
            T.checkTrustedRecursive.implementation = function () { return AL.$new(); };
        });
    });
}, 1500);

log('脚本已加载 (frida ' + Frida.version + ', runtime ' + Script.runtime + ')');
