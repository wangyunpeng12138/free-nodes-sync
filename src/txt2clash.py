#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
txt2clash.py —— 把 free-vpn-anti-rkn 的明文节点 txt 订阅转换成 Clash.Meta / mihomo 订阅。

特性：
  * 纯 Python 3 标准库，零第三方依赖（Windows / macOS / Linux 直接跑）
  * 支持 vless / vmess / trojan / ss / hysteria2 / hysteria / tuic 链接
  * 自动去重、清洗节点名、按来源打标签
  * 输出可直接被 mihomo(Clash.Meta) / Clash Verge / ClashX Meta 导入的完整配置
  * 内容未变化时跳过写盘，方便挂定时任务 / CI

用法：
  python src/txt2clash.py                      # 下载上游全部短订阅并转换
  python src/txt2clash.py --only 1.1,5.1       # 只转换指定源
  python src/txt2clash.py --local cache        # 用本地已下载的 txt（离线模式）
  python src/txt2clash.py --no-merged          # 只出分源订阅，不出合并订阅
"""

from __future__ import annotations

import argparse
import base64
import fnmatch
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(ROOT, "config", "sources.json")
CACHE_DIR = os.path.join(ROOT, "cache")
OUTPUT_DIR = os.path.join(ROOT, "output")

UA = "clash.meta/txt2clash (+https://github.com/Hidashimora/free-vpn-anti-rkn)"
SUPPORTED_SCHEMES = ("vless", "vmess", "trojan", "ss", "hysteria2", "hy2", "hysteria", "tuic")

# mihomo 支持的 uTLS 指纹；其余（如 xray 的 unsafe）会被丢弃，避免配置加载失败
FP_WHITELIST = {"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"}

# mihomo 支持的传输层（httpupgrade 在 mihomo 里是 ws 的变体，单独映射）
NET_WHITELIST = {"tcp", "ws", "grpc", "h2", "http", "xhttp", "httpupgrade"}

# mihomo 支持的 ss 加密方式；不在列表里的（多为源数据错误）直接丢弃，否则整份配置会加载失败
SS_CIPHERS = {
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "rc4-md5", "rc4", "chacha20", "chacha20-ietf", "xchacha20",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
    "none", "dummy",
}
SS_CIPHER_ALIAS = {
    "chacha20-poly1305": "chacha20-ietf-poly1305",
    "xchacha20-poly1305": "xchacha20-ietf-poly1305",
    "aes-256-gcm-siv": "aes-256-gcm",
}
# vmess 支持的加密方式
VMESS_CIPHERS = {"auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"}


# --------------------------------------------------------------------------- #
# 基础工具
# --------------------------------------------------------------------------- #
def log(msg: str) -> None:
    print(msg, flush=True)


def b64decode_any(s: str) -> str:
    """尽量宽松地解 base64（兼容 urlsafe、缺 padding、混入非法字符、+ 被写成空格）。"""
    s = urllib.parse.unquote((s or "").strip())
    if not s:
        return ""
    # 部分来源把 base64 里的 + 变成了空格，两种都试
    for cand in (s.replace(" ", "+"), s.replace(" ", "")):
        t = cand.replace("-", "+").replace("_", "/")
        t = re.sub(r"[^A-Za-z0-9+/=]", "", t).rstrip("=")
        if not t:
            continue
        t += "=" * ((-len(t)) % 4)
        try:
            out = base64.b64decode(t).decode("utf-8", "replace")
        except Exception:
            continue
        if out and "\ufffd" not in out[:20]:
            return out
    return ""


def maybe_b64(s: str) -> str:
    """如果字符串看起来是 base64，则解码；否则原样返回。"""
    s = (s or "").strip()
    if not s:
        return s
    if re.fullmatch(r"[A-Za-z0-9+/_\-=\s]+", s) and len(s) >= 8:
        out = b64decode_any(s)
        if out and ("://" in out or ":" in out or "{" in out):
            return out
    # 兜底：截取开头连续合法的 base64 片段再试一次（尾部可能混入垃圾字符）
    m = re.match(r"^[A-Za-z0-9+/_\-]+={0,2}", s)
    if m and len(m.group(0)) >= 8:
        out = b64decode_any(m.group(0))
        if out and ("://" in out or ":" in out or "{" in out):
            return out
    return s


def qs_get(q: dict, *keys, default=""):
    for k in keys:
        if k in q and q[k] != "":
            return q[k][0] if isinstance(q[k], list) else q[k]
    return default


def qs_bool(q: dict, *keys) -> bool:
    v = str(qs_get(q, *keys, default="")).strip().lower()
    return v in ("1", "true", "yes", "on")


def as_int(v, default=None):
    try:
        return int(str(v).strip())
    except Exception:
        return default


def clean_name(name: str, fallback: str = "node") -> str:
    name = urllib.parse.unquote(name or "")
    name = re.sub(r"[\x00-\x1f\x7f-\x9f\u200b\ufeff]", "", name)
    name = re.sub(r"\s+", " ", name).strip()
    return name or fallback


# --------------------------------------------------------------------------- #
# YAML 输出（只覆盖本项目用到的结构，避免引入 PyYAML 依赖）
# --------------------------------------------------------------------------- #
_SAFE_STR = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-/]*$")
_NUM_LIKE = re.compile(r"^[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$")
_RESERVED = {"true", "false", "yes", "no", "on", "off", "null", "~", "y", "n"}
_SAFE_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]*$")
_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _scalar(v) -> str:
    if v is True:
        return "true"
    if v is False:
        return "false"
    if v is None:
        return "null"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return repr(v)
    s = _CTRL.sub("", str(v))  # YAML 不接受控制字符
    if _SAFE_STR.match(s) and not _NUM_LIKE.match(s) and s.lower() not in _RESERVED:
        return s
    return json.dumps(s, ensure_ascii=False)


def _dump(obj, ind: int, out: list) -> None:
    pad = "  " * ind
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = k if _SAFE_KEY.match(str(k)) else json.dumps(str(k), ensure_ascii=False)
            if isinstance(v, dict):
                if not v:
                    out.append(f"{pad}{key}: {{}}")
                else:
                    out.append(f"{pad}{key}:")
                    _dump(v, ind + 1, out)
            elif isinstance(v, list):
                if not v:
                    out.append(f"{pad}{key}: []")
                else:
                    out.append(f"{pad}{key}:")
                    _dump(v, ind + 1, out)
            else:
                out.append(f"{pad}{key}: {_scalar(v)}")
    elif isinstance(obj, list):
        for it in obj:
            if isinstance(it, (dict, list)) and it:
                sub: list = []
                _dump(it, ind + 1, sub)
                out.append(f"{pad}- {sub[0][len(pad) + 2:]}")
                out.extend(sub[1:])
            elif isinstance(it, (dict, list)):
                out.append(f"{pad}- {'{}' if isinstance(it, dict) else '[]'}")
            else:
                out.append(f"{pad}- {_scalar(it)}")


def dump_yaml(data) -> str:
    out: list = []
    _dump(data, 0, out)
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- #
# 链接解析：统一输出 (proxy_dict, meta)
# meta = {"proto": "vless", "server": ..., "port": ..., "key": 去重指纹}
# --------------------------------------------------------------------------- #
class Skip(Exception):
    """该节点无法转换，跳过。"""


def _split_uri(uri: str):
    """拆出 scheme / body / fragment(name)。"""
    scheme, _, rest = uri.partition("://")
    body, _, frag = rest.partition("#")
    return scheme.lower(), body, clean_name(frag)


def _split_query(body: str):
    """拆出 主体 与 query 字典（保持大小写不敏感取值）。"""
    main, _, query = body.partition("?")
    q = urllib.parse.parse_qs(query, keep_blank_values=True)
    return main, q


def _host_port(netloc: str):
    netloc = (netloc or "").strip().rstrip("/")
    if not netloc:
        raise Skip("缺少 host/port")
    if netloc.startswith("["):  # IPv6
        host, _, rest = netloc[1:].partition("]")
        port = rest.lstrip(":").rstrip("/")
    else:
        m = re.match(r"^(.*):(\d+)$", netloc)
        if not m:
            raise Skip("缺少 host/port")
        host, port = m.group(1), m.group(2)
    p = as_int(port)
    if not host or p is None:
        raise Skip("缺少 host/port")
    return host.strip(), p


def _tls_common(proxy: dict, q: dict, default_sni: str = "") -> None:
    """填充 tls / sni / alpn / 证书校验 / 指纹等公共字段。"""
    sni = qs_get(q, "sni", "peer", "servername", default=default_sni)
    if sni:
        proxy["servername"] = sni
    fp = qs_get(q, "fp", "fingerprint").lower()
    if fp in FP_WHITELIST:
        proxy["client-fingerprint"] = fp
    alpn = qs_get(q, "alpn")
    if alpn:
        proxy["alpn"] = [a.strip() for a in alpn.split(",") if a.strip()]
    if qs_bool(q, "allowInsecure", "insecure", "skip-cert-verify", "allow_insecure"):
        proxy["skip-cert-verify"] = True


def _transport(proxy: dict, q: dict, default_host: str = "") -> None:
    """填充 network 及各传输层参数（按 mihomo 的传输层规则映射）。"""
    net = (qs_get(q, "type", "net", default="tcp") or "tcp").strip().lower()
    if net in ("", "none", "raw", "tcp"):
        net = "tcp"
    if net in ("splithttp", "split-http"):
        net = "xhttp"  # xray 里 splithttp 已改名为 xhttp
    if net not in NET_WHITELIST:
        raise Skip(f"不支持的传输层 {net}")

    host = qs_get(q, "host") or default_host
    path = urllib.parse.unquote(qs_get(q, "path", default="")) or "/"

    if net == "tcp":
        proxy["network"] = "tcp"
        if (qs_get(q, "headerType") or "").lower() == "http":
            proxy["network"] = "http"
            proxy["http-opts"] = {"path": [path or "/"]}
            if host:
                proxy["http-opts"]["headers"] = {"Host": [host]}
        return

    if net == "httpupgrade":
        # mihomo 没有独立的 httpupgrade，用 ws + v2ray-http-upgrade 表达
        proxy["network"] = "ws"
        opts = {"path": path or "/", "v2ray-http-upgrade": True}
        if host:
            opts["headers"] = {"Host": host}
        proxy["ws-opts"] = opts
        return

    proxy["network"] = net
    if net == "ws":
        opts = {"path": path or "/"}
        if host:
            opts["headers"] = {"Host": host}
        proxy["ws-opts"] = opts
    elif net == "grpc":
        proxy["grpc-opts"] = {"grpc-service-name": qs_get(q, "serviceName", "servicename", default="")}
    elif net == "h2":
        opts = {"path": path or "/"}
        if host:
            opts["host"] = [h.strip() for h in host.split(",") if h.strip()]
        proxy["h2-opts"] = opts
    elif net == "http":
        opts = {"path": [path or "/"]}
        if host:
            opts["headers"] = {"Host": [host]}
        proxy["http-opts"] = opts
    elif net == "xhttp":
        opts = {"path": path or "/"}
        if host:
            opts["host"] = host
        mode = qs_get(q, "mode")
        if mode:
            opts["mode"] = mode
        proxy["xhttp-opts"] = opts


def parse_vless(uri: str) -> dict:
    _, body, name = _split_uri(uri)
    main, q = _split_query(body)
    uuid, _, netloc = main.rpartition("@")
    if not uuid or not netloc:
        raise Skip("vless 缺少 uuid")
    host, port = _host_port(netloc)

    p: dict = {
        "name": name or f"vless-{host}:{port}",
        "type": "vless",
        "server": host,
        "port": port,
        "uuid": urllib.parse.unquote(uuid).strip(),
        "udp": True,
    }
    security = (qs_get(q, "security", default="none") or "none").lower()
    flow = qs_get(q, "flow")
    if security in ("tls", "xtls", "reality"):
        p["tls"] = True
        _tls_common(p, q, default_sni=host)
        if security == "reality":
            pbk = qs_get(q, "pbk", "publicKey", "public-key").strip()
            sid = qs_get(q, "sid", "shortId", "short-id").strip()
            # pbk 必须是 43 位 base64url 的 X25519 公钥，否则 mihomo 拒绝加载
            if not pbk or not re.fullmatch(r"[A-Za-z0-9_-]{43}", pbk):
                raise Skip("reality 缺少或非法的 pbk")
            p["reality-opts"] = {"public-key": pbk}
            # short-id 必须是偶数长度的 hex，否则 mihomo 拒绝加载
            if sid and re.fullmatch(r"[0-9a-fA-F]{0,16}", sid) and len(sid) % 2 == 0:
                p["reality-opts"]["short-id"] = sid
            p.setdefault("client-fingerprint", "chrome")
    elif security in ("", "none", "false"):
        p["tls"] = False
    else:
        raise Skip(f"不支持的 security {security}")

    # flow 只认 xtls-rprx-vision；被截断或写错的值直接忽略，不影响节点本身
    if flow and flow.strip() == "xtls-rprx-vision":
        p["flow"] = "xtls-rprx-vision"
    _transport(p, q, default_host=qs_get(q, "sni") or host)
    return p


def parse_trojan(uri: str) -> dict:
    _, body, name = _split_uri(uri)
    main, q = _split_query(body)
    pwd, _, netloc = main.rpartition("@")
    if not pwd or not netloc:
        raise Skip("trojan 缺少密码")
    host, port = _host_port(netloc)
    p: dict = {
        "name": name or f"trojan-{host}:{port}",
        "type": "trojan",
        "server": host,
        "port": port,
        "password": urllib.parse.unquote(pwd),
        "udp": True,
    }
    _tls_common(p, q, default_sni=host)
    _transport(p, q, default_host=qs_get(q, "sni") or host)
    return p


def parse_vmess(uri: str) -> dict:
    _, body, name = _split_uri(uri)
    raw = maybe_b64(body.split("?", 1)[0])
    if not raw.strip().startswith("{"):
        raise Skip("vmess 不是 JSON 格式")
    try:
        j = json.loads(raw)
    except Exception as e:
        raise Skip(f"vmess JSON 解析失败: {e}")

    host = str(j.get("add", "")).strip()
    port = as_int(j.get("port"))
    uuid = str(j.get("id", "")).strip()
    if not host or not port or not uuid:
        raise Skip("vmess 缺少 add/port/id")

    cipher = (str(j.get("scy") or j.get("security") or "auto")).strip().lower()
    if cipher not in VMESS_CIPHERS:
        cipher = "auto"
    p: dict = {
        "name": name or clean_name(str(j.get("ps", "")), f"vmess-{host}:{port}"),
        "type": "vmess",
        "server": host,
        "port": port,
        "uuid": uuid,
        "alterId": as_int(j.get("aid"), 0) or 0,
        "cipher": cipher,
        "udp": True,
    }
    tls = str(j.get("tls", "")).strip().lower()
    if tls in ("tls", "reality", "true", "1"):
        p["tls"] = True
        sni = str(j.get("sni") or j.get("host") or "").strip()
        if sni:
            p["servername"] = sni
        fp = str(j.get("fp", "")).strip().lower()
        if fp in FP_WHITELIST:
            p["client-fingerprint"] = fp
        alpn = str(j.get("alpn", "")).strip()
        if alpn:
            p["alpn"] = [a.strip() for a in alpn.split(",") if a.strip()]
        if str(j.get("verify_cert", "")).strip() in ("0", "false") or str(j.get("allowInsecure", "")).strip() in ("1", "true"):
            p["skip-cert-verify"] = True

    net = str(j.get("net", "tcp")).strip().lower() or "tcp"
    if net in ("", "none", "raw"):
        net = "tcp"
    if net in ("kcp", "mkcp", "mekya"):
        raise Skip("vmess 的 kcp/mekya 暂不支持")
    if net == "xhttp":
        raise Skip("xhttp 仅 vless 支持")
    # vmess 的 JSON 字段名与 URI query 不同，这里转成统一的 query 结构复用 _transport
    tq = {
        "type": [net],
        "host": [str(j.get("host", "") or "")],
        "path": [str(j.get("path", "") or "")],
        "serviceName": [str(j.get("path", "") or "").strip("/")],
        "headerType": [str(j.get("type", "") or "")],
    }
    _transport(p, tq, default_host=str(j.get("sni") or host))
    return p


def parse_ss(uri: str) -> dict:
    _, body, name = _split_uri(uri)
    main, q = _split_query(body)

    if "@" in main:
        userinfo, _, netloc = main.rpartition("@")
        raw_ui = urllib.parse.unquote(userinfo)
        # 明文写法 method:password@host:port 优先；否则按 base64 解
        cred = raw_ui if ":" in raw_ui else b64decode_any(userinfo)
        if ":" not in cred:
            raise Skip("ss 凭据格式错误")
        method, _, password = cred.partition(":")
        host, port = _host_port(netloc)
    else:
        decoded = b64decode_any(main)
        if not decoded:
            raise Skip("ss base64 解码失败")
        # 可能内部还带 query（plugin）
        inner_main, _, inner_q = decoded.partition("?")
        if inner_q and not q:
            q = urllib.parse.parse_qs(inner_q, keep_blank_values=True)
        cred, _, netloc = inner_main.rpartition("@")
        if ":" not in cred:
            raise Skip("ss 凭据格式错误")
        method, _, password = cred.partition(":")
        host, port = _host_port(netloc)

    method = method.strip().lower()
    method = SS_CIPHER_ALIAS.get(method, method)
    if method not in SS_CIPHERS:
        raise Skip(f"ss 加密方式不支持: {method}")
    p: dict = {
        "name": name or f"ss-{host}:{port}",
        "type": "ss",
        "server": host,
        "port": port,
        "cipher": method,
        "password": password,
        "udp": True,
    }

    plugin = qs_get(q, "plugin")
    if plugin:
        parts = [x.strip() for x in urllib.parse.unquote(plugin).split(";")]
        pname = parts[0]
        popts = {}
        for item in parts[1:]:
            if "=" in item:
                k, _, v = item.partition("=")
                popts[k.strip()] = v.strip()
            elif item:
                popts[item] = "true"
        if pname in ("obfs-local", "simple-obfs", "obfs"):
            p["plugin"] = "obfs"
            opts = {"mode": popts.get("obfs", "http")}
            if popts.get("obfs-host"):
                opts["host"] = popts["obfs-host"]
            p["plugin-opts"] = opts
        elif pname in ("v2ray-plugin", "xray-plugin"):
            p["plugin"] = "v2ray-plugin"
            opts = {"mode": popts.get("mode", "websocket")}
            if popts.get("host"):
                opts["host"] = popts["host"]
            if popts.get("path"):
                opts["path"] = popts["path"]
            if "tls" in popts:
                opts["tls"] = True
            p["plugin-opts"] = opts
        else:
            raise Skip(f"不支持的 ss 插件 {pname}")
    return p


def parse_hysteria2(uri: str) -> dict:
    _, body, name = _split_uri(uri)
    main, q = _split_query(body)
    auth, sep, netloc = main.rpartition("@")
    if not sep:
        auth, netloc = "", main
    host, port = _host_port(netloc)
    p: dict = {
        "name": name or f"hy2-{host}:{port}",
        "type": "hysteria2",
        "server": host,
        "port": port,
        "password": urllib.parse.unquote(auth).strip(),
        "udp": True,
    }
    _tls_common(p, q, default_sni=qs_get(q, "sni") or host)
    obfs = qs_get(q, "obfs")
    if obfs and obfs.lower() != "none":
        p["obfs"] = obfs
        obfs_pwd = qs_get(q, "obfs-password", "obfs_password")
        if obfs_pwd:
            p["obfs-password"] = obfs_pwd
    up = qs_get(q, "up", "upmbps")
    down = qs_get(q, "down", "downmbps")
    if up:
        p["up"] = f"{up} Mbps" if str(up).isdigit() else up
    if down:
        p["down"] = f"{down} Mbps" if str(down).isdigit() else down
    return p


def parse_hysteria(uri: str) -> dict:
    _, body, name = _split_uri(uri)
    main, q = _split_query(body)
    host, port = _host_port(main.rpartition("@")[2] if "@" in main else main)
    p: dict = {
        "name": name or f"hy-{host}:{port}",
        "type": "hysteria",
        "server": host,
        "port": port,
        "protocol": qs_get(q, "protocol", default="udp"),
        "udp": True,
    }
    auth = qs_get(q, "auth", "auth_str", "auth-str")
    if auth:
        p["auth-str"] = auth
    _tls_common(p, q, default_sni=qs_get(q, "peer") or host)
    for key, src in (("up", ("upmbps", "up")), ("down", ("downmbps", "down"))):
        v = qs_get(q, *src)
        if v:
            p[key] = f"{v} Mbps" if str(v).isdigit() else v
    return p


def parse_tuic(uri: str) -> dict:
    _, body, name = _split_uri(uri)
    main, q = _split_query(body)
    userinfo, _, netloc = main.rpartition("@")
    host, port = _host_port(netloc)
    uuid, _, password = urllib.parse.unquote(userinfo).partition(":")
    p: dict = {
        "name": name or f"tuic-{host}:{port}",
        "type": "tuic",
        "server": host,
        "port": port,
        "uuid": uuid,
        "password": password,
        "udp": True,
        "congestion-controller": qs_get(q, "congestion_control", "congestion-controller", default="bbr"),
        "udp-relay-mode": qs_get(q, "udp_relay_mode", "udp-relay-mode", default="native"),
    }
    _tls_common(p, q, default_sni=qs_get(q, "sni") or host)
    return p


PARSERS = {
    "vless": parse_vless,
    "vmess": parse_vmess,
    "trojan": parse_trojan,
    "ss": parse_ss,
    "hysteria2": parse_hysteria2,
    "hy2": parse_hysteria2,
    "hysteria": parse_hysteria,
    "tuic": parse_tuic,
}


_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def sniff_scheme(scheme: str, uri: str) -> str:
    """源数据里大量出现协议前缀写错的情况（ss:// 里其实是 vless 或 vmess），按内容纠正。"""
    if scheme != "ss":
        return scheme
    body = uri.split("://", 1)[1]
    main = body.split("#", 1)[0]
    head = main.split("?", 1)[0]
    userinfo = head.rpartition("@")[0]

    # ss 的凭据一定是 method:password，userinfo 为裸 UUID 时实际是 vless
    if _UUID_RE.match(urllib.parse.unquote(userinfo).strip()):
        return "vless"
    # 整段 base64 且解码后是 vmess 的 JSON -> vmess
    if "@" not in head:
        dec = b64decode_any(head).strip()
        if dec.startswith("{") and '"add"' in dec:
            return "vmess"
    return scheme


def parse_uri(uri: str, cfg: dict) -> dict | None:
    uri = uri.strip()
    # 部分源从 HTML 页面抓取，参数分隔符是 &amp; 而不是 &
    if "&amp;" in uri or "&#38;" in uri or "&#x26;" in uri:
        uri = uri.replace("&amp;", "&").replace("&#38;", "&").replace("&#x26;", "&")
    if not uri or uri.startswith("#") or uri.startswith("//"):
        return None
    scheme = uri.split("://", 1)[0].lower() if "://" in uri else ""
    if scheme not in PARSERS:
        return None
    scheme = sniff_scheme(scheme, uri)
    try:
        p = PARSERS[scheme](uri)
    except Skip as e:
        STATS["skipped"][str(e)] = STATS["skipped"].get(str(e), 0) + 1
        return None
    except Exception as e:  # 单条坏数据不影响整体
        STATS["skipped"][f"解析异常: {type(e).__name__}"] = STATS["skipped"].get(f"解析异常: {type(e).__name__}", 0) + 1
        return None

    # xhttp 兼容策略
    if p.get("network") == "xhttp" and cfg.get("xhttp_mode") == "drop":
        STATS["skipped"]["xhttp(已按配置丢弃)"] = STATS["skipped"].get("xhttp(已按配置丢弃)", 0) + 1
        return None
    if p.get("network") in set(cfg.get("drop_networks", [])):
        STATS["skipped"][f"network={p['network']}"] = STATS["skipped"].get(f"network={p['network']}", 0) + 1
        return None

    # 新版 mihomo 已移除 global-client-fingerprint，指纹必须逐节点声明
    if p.get("tls") and p.get("type") in ("vless", "vmess", "trojan") and "client-fingerprint" not in p:
        p["client-fingerprint"] = "chrome"
    return p


def fingerprint(p: dict) -> str:
    cred = p.get("uuid") or p.get("password") or p.get("auth-str") or ""
    net = p.get("network", "tcp")
    return f"{p.get('type')}|{str(p.get('server', '')).lower()}|{p.get('port')}|{cred}|{net}|{p.get('servername', '')}"


STATS = {"skipped": {}}


# --------------------------------------------------------------------------- #
# 订阅文件处理
# --------------------------------------------------------------------------- #
def ensure_unique_names(nodes: list, max_len: int = 60) -> list:
    """Clash 要求节点名唯一，重名的追加序号。"""
    used = set()
    for p in nodes:
        base = (p.get("name") or "node").strip()[:max_len]
        name, i = base, 1
        while name in used:
            i += 1
            suffix = f" {i}"
            name = base[: max_len - len(suffix)] + suffix
        used.add(name)
        p["name"] = name
    return nodes


_SCHEME_SPLIT = re.compile(r"(?=(?:vless|vmess|trojan|ss|hysteria2|hy2|hysteria|tuic)://)")


def iter_links(text: str):
    """逐条产出链接；源文件里存在多个链接粘在同一行的情况，这里一并拆开。"""
    for raw in text.splitlines():
        raw = raw.strip()
        if not raw or raw.startswith("#") or raw.startswith("//"):
            continue
        if raw.lower().startswith(("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "hysteria://", "tuic://")):
            parts = [p for p in _SCHEME_SPLIT.split(raw) if "://" in p]
            for p in parts:
                p = p.strip()
                if p:
                    yield p
        # 整段 base64 的订阅（少见）在这里不展开，由上层按需处理


def parse_subscription_text(text: str, cfg: dict, tag: str = "") -> list:
    nodes, seen = [], set()
    max_len = int(cfg.get("max_name_len", 60))
    for line in iter_links(text):
        p = parse_uri(line, cfg)
        if not p:
            continue
        fp = fingerprint(p)
        if fp in seen:
            continue
        seen.add(fp)
        nm = p["name"]
        if tag and cfg.get("name_prefix", True):
            nm = f"[{tag}] {nm}"
        p["name"] = nm
        nodes.append(p)
    return ensure_unique_names(nodes, max_len)


def dedupe_nodes(nodes: list) -> list:
    out, seen = [], set()
    for p in nodes:
        fp = fingerprint(p)
        if fp in seen:
            continue
        seen.add(fp)
        out.append(p)
    return out


# --------------------------------------------------------------------------- #
# Clash 配置构建
# --------------------------------------------------------------------------- #
GROUP_AUTO = "♻️ 自动选择"
GROUP_SELECT = "🚀 节点选择"
GROUP_DIRECT = "🎯 全球直连"


def build_config(proxies: list, clash_cfg: dict, title: str, groups_by_tag: dict | None = None) -> dict:
    names = [p["name"] for p in proxies]
    test_url = clash_cfg.get("test_url", "https://www.gstatic.com/generate_204")

    groups: list = [
        {
            "name": GROUP_SELECT,
            "type": "select",
            "proxies": [GROUP_AUTO, "DIRECT"] + names,
        },
        {
            "name": GROUP_AUTO,
            "type": "url-test",
            "url": test_url,
            "interval": int(clash_cfg.get("test_interval", 300)),
            "tolerance": int(clash_cfg.get("tolerance", 50)),
            "proxies": names,
        },
    ]
    if groups_by_tag:
        for tag, members in groups_by_tag.items():
            if not members:
                continue
            groups.append(
                {
                    "name": f"📡 {tag}",
                    "type": "url-test",
                    "url": test_url,
                    "interval": int(clash_cfg.get("test_interval", 300)),
                    "tolerance": int(clash_cfg.get("tolerance", 50)),
                    "proxies": members,
                }
            )
        groups[0]["proxies"] = [GROUP_AUTO, "DIRECT"] + [g["name"] for g in groups[2:]] + names

    config = {
        "mixed-port": int(clash_cfg.get("mixed_port", 7890)),
        "allow-lan": bool(clash_cfg.get("allow_lan", False)),
        "bind-address": "*",
        "mode": clash_cfg.get("mode", "rule"),
        "log-level": clash_cfg.get("log_level", "info"),
        "ipv6": False,
        "external-controller": clash_cfg.get("external_controller", "127.0.0.1:9090"),
        "unified-delay": True,
        "tcp-concurrent": True,
        "find-process-mode": "off",
        "profile": {"store-selected": True, "store-fake-ip": True},
        "dns": {
            "enable": True,
            "ipv6": False,
            "listen": "0.0.0.0:1053",
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16",
            "fake-ip-filter": ["*.lan", "*.local", "*.localdomain", "*.localhost", "+.msftconnecttest.com", "+.msftncsi.com", "localhost.ptlogin2.qq.com"],
            "default-nameserver": ["223.5.5.5", "119.29.29.29"],
            "nameserver": ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"],
            "proxy-server-nameserver": ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"],
        },
        "proxies": proxies,
        "proxy-groups": groups,
        "rules": [
            "GEOIP,LAN,DIRECT,no-resolve",
            "GEOIP,CN,DIRECT",
            "MATCH," + GROUP_SELECT,
        ],
    }
    return config


def render(config: dict, title: str, count: int) -> str:
    # 注意：这里不能写生成时间戳，否则每次运行都会产生 diff，定时任务会刷出无意义的提交
    header = [
        f"# {title}",
        f"# 节点数量: {count}",
        "# 源: https://github.com/Hidashimora/free-vpn-anti-rkn",
        "# 由 src/txt2clash.py 自动生成，请勿手动编辑",
        "# 客户端: mihomo / Clash.Meta / Clash Verge Rev / ClashX Meta（原生 Clash 不支持 vless）",
        "",
    ]
    return "\n".join(header) + dump_yaml(config)


# --------------------------------------------------------------------------- #
# 下载
# --------------------------------------------------------------------------- #
def http_get_any(urls: list, timeout: int = 60, retries: int = 2):
    """依次尝试多个镜像地址，返回 (文本, 实际使用的 URL)。"""
    last = None
    for url in urls:
        for i in range(retries):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    data = r.read()
                if data:
                    return data.decode("utf-8", "replace"), url
                last = f"{url} -> 空响应"
            except urllib.error.HTTPError as e:
                last = f"{url} -> HTTP {e.code}"
                if e.code in (403, 404):
                    break
            except Exception as e:
                last = f"{url} -> {type(e).__name__}: {e}"
            time.sleep(0.6 * (i + 1))
    raise RuntimeError(str(last))


def mirror_urls(conf: dict, name: str) -> list:
    up = conf["upstream"]
    path = f"{up['configs_dir']}/{name}.txt"
    urls = []
    for m in conf.get("mirrors", []):
        try:
            urls.append(m["url"].format(repo=up["repo"], branch=up["branch"], path=path))
        except (KeyError, IndexError):
            continue
    if not urls:
        urls = [f"https://raw.githubusercontent.com/{up['repo']}/{up['branch']}/{path}"]
    return urls


def list_remote_sources(up: dict) -> list:
    """通过 GitHub API 列出 configs/ 下所有 txt（无需 token，受 60 次/小时限流）。"""
    api = f"https://api.github.com/repos/{up['repo']}/git/trees/{up['branch']}?recursive=1"
    txt, _ = http_get_any([api], timeout=30, retries=1)
    data = json.loads(txt)
    names = [
        os.path.basename(t["path"])[:-4]
        for t in data.get("tree", [])
        if t["path"].startswith(up["configs_dir"] + "/") and t["path"].endswith(".txt")
    ]
    return sorted(set(names), key=sort_key)


def sort_key(n: str):
    return [(0, int(x)) if x.isdigit() else (1, x) for x in re.split(r"[.\-]", n)]


def select_sources(all_names: list, sel: dict) -> list:
    inc = sel.get("include") or ["*"]
    exc = sel.get("exclude") or []
    out = []
    for n in all_names:
        if any(fnmatch.fnmatch(n, pat) for pat in exc):
            continue
        if any(fnmatch.fnmatch(n, pat) for pat in inc):
            out.append(n)
    return sorted(set(out), key=sort_key)


def load_local_sources(local_dir: str) -> dict:
    data = {}
    for fn in sorted(os.listdir(local_dir)):
        if fn.endswith(".txt"):
            with open(os.path.join(local_dir, fn), "r", encoding="utf-8", errors="replace") as f:
                data[fn[:-4]] = f.read()
    return data


def fetch_sources(names: list, conf: dict, jobs: int, timeout: int) -> dict:
    os.makedirs(CACHE_DIR, exist_ok=True)
    texts, failed, used_mirror = {}, [], {}

    def work(n: str):
        try:
            txt, url = http_get_any(mirror_urls(conf, n), timeout=timeout)
        except Exception as e:
            return n, None, str(e), None
        with open(os.path.join(CACHE_DIR, f"{n}.txt"), "w", encoding="utf-8") as f:
            f.write(txt)
        return n, txt, None, url

    with ThreadPoolExecutor(max_workers=jobs) as ex:
        for n, txt, err, url in ex.map(work, names):
            if txt is None:
                failed.append((n, err))
            else:
                texts[n] = txt
                used_mirror[n] = url
    if failed:
        log(f"  ! {len(failed)} 个源下载失败：")
        for n, err in failed[:8]:
            log(f"    - {n}: {err}")
    if used_mirror:
        hosts = {}
        for u in used_mirror.values():
            h = urllib.parse.urlsplit(u).netloc
            hosts[h] = hosts.get(h, 0) + 1
        log("  实际使用镜像：" + "，".join(f"{h}×{c}" for h, c in sorted(hosts.items(), key=lambda kv: -kv[1])))
    return texts


# --------------------------------------------------------------------------- #
# 写盘
# --------------------------------------------------------------------------- #
def write_if_changed(path: str, content: str) -> bool:
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                if f.read() == content:
                    return False
        except Exception:
            pass
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)
    os.replace(tmp, path)
    return True


def prune_output(out_dir: str, merged_file: str, keep_sources: set) -> list:
    """清掉本次不再产出的旧文件（源被上游删除、或从平铺目录切到 sources/ 时）。"""
    removed = []
    if not os.path.isdir(out_dir):
        return removed
    for fn in os.listdir(out_dir):
        if fn.endswith(".yaml") and fn != merged_file:
            try:
                os.remove(os.path.join(out_dir, fn))
                removed.append(fn)
            except OSError:
                pass
    src_dir = os.path.join(out_dir, "sources")
    if os.path.isdir(src_dir):
        for fn in os.listdir(src_dir):
            if fn.endswith(".yaml") and fn[:-5] not in keep_sources:
                try:
                    os.remove(os.path.join(src_dir, fn))
                    removed.append(f"sources/{fn}")
                except OSError:
                    pass
    return removed


# --------------------------------------------------------------------------- #
# 主流程
# --------------------------------------------------------------------------- #
def main() -> int:
    ap = argparse.ArgumentParser(description="txt 订阅 -> Clash.Meta 订阅")
    ap.add_argument("--config", default=CONFIG_PATH, help="配置文件路径")
    ap.add_argument("--local", default=None, help="从本地目录读取 txt（离线模式）")
    ap.add_argument("--only", default=None, help="只处理这些源，逗号分隔，如 1.1,5.1")
    ap.add_argument("--out", default=OUTPUT_DIR, help="输出目录")
    ap.add_argument("--no-merged", action="store_true", help="不生成合并订阅")
    ap.add_argument("--no-per-source", action="store_true", help="不生成分源订阅")
    ap.add_argument("--merged-limit", type=int, default=None, help="覆盖合并订阅节点上限")
    ap.add_argument("--jobs", type=int, default=12, help="并发下载数")
    ap.add_argument("--timeout", type=int, default=60, help="单次下载超时秒数")
    ap.add_argument("--xhttp", default=None, choices=["drop", "keep"], help="xhttp 节点处理方式")
    ap.add_argument("--proxy", default=None, help="指定代理，如 http://127.0.0.1:7890；填 no 强制直连")
    ap.add_argument("--mirror", default=None, help="只使用指定镜像，逗号分隔，如 jsdelivr,raw")
    args = ap.parse_args()

    with open(args.config, "r", encoding="utf-8") as f:
        conf = json.load(f)
    up = conf["upstream"]
    clash_cfg = conf.get("clash", {})
    conv = dict(conf.get("convert", {}))
    if args.xhttp:
        conv["xhttp_mode"] = args.xhttp
    if args.mirror:
        want = [x.strip() for x in args.mirror.split(",") if x.strip()]
        picked = [m for m in conf.get("mirrors", []) if m["name"] in want]
        if picked:
            conf["mirrors"] = picked
            log("镜像顺序：" + " -> ".join(m["name"] for m in picked))
    if args.proxy:
        if args.proxy.lower() in ("no", "none", "off", "direct"):
            urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({})))
            log("已禁用代理，强制直连")
        else:
            urllib.request.install_opener(
                urllib.request.build_opener(urllib.request.ProxyHandler({"http": args.proxy, "https": args.proxy}))
            )
            log(f"使用代理 {args.proxy}")

    # 1) 确定源清单
    if args.local:
        texts = load_local_sources(args.local)
        all_names = sorted(texts.keys(), key=sort_key)
        log(f"离线模式：从 {args.local} 读取到 {len(all_names)} 个源")
    else:
        try:
            all_names = list_remote_sources(up)
            log(f"远程发现 {len(all_names)} 个源")
        except Exception as e:
            log(f"! 远程列举失败（{e}），回退到配置文件清单")
            all_names = list(conf.get("sources", [])) or list(conf.get("merged", {}).get("sources", []))

    if args.only:
        want = [x.strip() for x in args.only.split(",") if x.strip()]
        all_names = [n for n in all_names if n in want] or want
    else:
        all_names = select_sources(all_names, conf.get("select", {}))

    if not all_names:
        log("没有可处理的源")
        return 1

    # 2) 下载
    if not args.local:
        log(f"开始下载 {len(all_names)} 个源（并发 {args.jobs}）...")
        t0 = time.time()
        texts = fetch_sources(all_names, conf, args.jobs, args.timeout)
        log(f"下载完成，成功 {len(texts)} / {len(all_names)}，耗时 {time.time() - t0:.1f}s")
        if not texts:
            log("! 没有任何源下载成功，检查网络或代理（可设置 HTTPS_PROXY 环境变量）")
            return 1

    os.makedirs(args.out, exist_ok=True)
    per_source_dir = os.path.join(args.out, "sources")
    if not args.no_per_source:
        os.makedirs(per_source_dir, exist_ok=True)
    counts, per_source_nodes = {}, {}

    # 3) 分源转换
    if not args.no_per_source:
        for name in all_names:
            txt = texts.get(name)
            if txt is None:
                continue
            nodes = parse_subscription_text(txt, conv, tag="")
            if not nodes:
                log(f"  - {name}: 0 节点（跳过）")
                continue
            per_source_nodes[name] = nodes
            cfg = build_config(nodes, clash_cfg, f"{name}.yaml", None)
            path = os.path.join(per_source_dir, f"{name}.yaml")
            changed = write_if_changed(path, render(cfg, f"订阅 {name}.txt -> Clash", len(nodes)))
            counts[name] = len(nodes)
            log(f"  - {name}: {len(nodes)} 节点 -> {os.path.relpath(path, ROOT)}{'' if changed else ' (未变化)'}")

    # 4) 合并订阅
    merged_cfg = conf.get("merged", {})
    if not args.no_merged and merged_cfg.get("enabled", True):
        merged_names = [n for n in merged_cfg.get("sources", []) if n in texts] or list(texts.keys())
        merged_names = [n for n in merged_names if n in per_source_nodes] or merged_names
        bucket, groups_by_tag = [], {}
        for n in merged_names:
            nodes = per_source_nodes.get(n)
            if nodes is None:
                txt = texts.get(n, "")
                nodes = parse_subscription_text(txt, conv, tag="")
            for p in nodes:
                q = dict(p)
                q["name"] = f"[{n}] {p['name']}"[: int(conv.get("max_name_len", 60))]
                bucket.append(q)
        bucket = dedupe_nodes(bucket)
        bucket = ensure_unique_names(bucket, int(conv.get("max_name_len", 60)))

        # 组内成员（按来源），名字需与去重后的名字对齐
        for p in bucket:
            m = re.match(r"^\[([^\]]+)\]", p["name"])
            if m:
                groups_by_tag.setdefault(m.group(1), []).append(p["name"])
        groups_by_tag = {k: v for k, v in groups_by_tag.items() if len(v) >= 2}

        limit = args.merged_limit or int(merged_cfg.get("max_nodes", 800))
        if limit and len(bucket) > limit:
            bucket = bucket[:limit]
            keep = {p["name"] for p in bucket}
            groups_by_tag = {k: [x for x in v if x in keep] for k, v in groups_by_tag.items()}
            groups_by_tag = {k: v for k, v in groups_by_tag.items() if len(v) >= 2}

        if bucket:
            cfg = build_config(bucket, clash_cfg, merged_cfg.get("file", "all.yaml"), groups_by_tag)
            path = os.path.join(args.out, merged_cfg.get("file", "all.yaml"))
            changed = write_if_changed(path, render(cfg, "合并订阅 -> Clash", len(bucket)))
            log(f"  ★ 合并订阅: {len(bucket)} 节点 / {len(merged_names)} 个来源 -> {os.path.relpath(path, ROOT)}{'' if changed else ' (未变化)'}")

    # 5) 清理过期文件（源被上游删除或输出结构变化时）
    removed = prune_output(args.out, merged_cfg.get("file", "all.yaml"), set(counts.keys()))
    if removed:
        log(f"  清理 {len(removed)} 个过期文件")

    # 6) 统计文件（同样不写时间戳，保证 CI 里内容稳定、不会空提交）
    stat = {
        "sources": len(counts),
        "total_nodes": sum(counts.values()),
        "counts": dict(sorted(counts.items(), key=lambda kv: sort_key(kv[0]))),
        "skipped": STATS["skipped"],
    }
    write_if_changed(os.path.join(args.out, "counts.json"), json.dumps(stat, ensure_ascii=False, indent=2) + "\n")
    log(f"完成：{stat['sources']} 个源，合计 {stat['total_nodes']} 节点")
    if STATS["skipped"]:
        top = sorted(STATS["skipped"].items(), key=lambda kv: -kv[1])[:6]
        log("跳过统计：" + "，".join(f"{k}×{v}" for k, v in top))
    return 0


if __name__ == "__main__":
    sys.exit(main())
