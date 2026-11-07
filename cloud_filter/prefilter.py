#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
V2Ray Cloud Pre-Filter Engine
Location: cloud_filter/prefilter.py
Author: Amir & Antigravity
"""

import os
import sys
import time
import json
import base64
import socket
import shutil
import tempfile
import subprocess
import threading
import concurrent.futures
from urllib.parse import urlparse, parse_qs, unquote
import requests
import urllib3

sys.stdout.reconfigure(line_buffering=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SUBS_FILE = os.path.join(BASE_DIR, "subscriptions.txt")
if not os.path.exists(SUBS_FILE):
    SUBS_FILE = "subscriptions.txt"

OUTPUT_FILE = "alive_configs.txt"

MAX_DL_WORKERS = 30
MAX_TCP_WORKERS = 400
MAX_CORE_WORKERS = 70
TCP_TIMEOUT = 1.5
CORE_TIMEOUT = 2.5
PROBE_URL = "https://www.gstatic.com/generate_204"

XRAY_BIN = "xray" if os.name != "nt" else "xray.exe"
SINGBOX_BIN = "sing-box" if os.name != "nt" else "sing-box.exe"

if not shutil.which(XRAY_BIN) and os.path.exists("/usr/local/bin/xray"):
    XRAY_BIN = "/usr/local/bin/xray"

if not shutil.which(SINGBOX_BIN) and os.path.exists("/usr/local/bin/sing-box"):
    SINGBOX_BIN = "/usr/local/bin/sing-box"

TEMP_DIR = os.path.join(tempfile.gettempdir(), "cloud_prefilter")
os.makedirs(TEMP_DIR, exist_ok=True)

write_lock = threading.Lock()
port_counter = 20000
port_lock = threading.Lock()

dns_cache = {}
dns_lock = threading.Lock()

# Global Live Status
status_lock = threading.Lock()
start_timestamp = time.time()
live_status = {
    "status": "running",
    "phase": "Downloading Subscriptions",
    "progress": "0%",
    "alive_count": 0,
    "total_raw": 0,
    "elapsed_sec": 0,
    "timestamp": int(time.time())
}

def update_status(phase=None, progress=None, alive_count=None, total_raw=None, status=None):
    with status_lock:
        if phase is not None: live_status["phase"] = phase
        if progress is not None: live_status["progress"] = progress
        if alive_count is not None: live_status["alive_count"] = alive_count
        if total_raw is not None: live_status["total_raw"] = total_raw
        if status is not None: live_status["status"] = status
        live_status["elapsed_sec"] = int(time.time() - start_timestamp)
        live_status["timestamp"] = int(time.time())

def publish_status_to_github():
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not token or not repo:
        return
    try:
        url = f"https://api.github.com/repos/{repo}/contents/cloud_status.json"
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3+json"}
        sha = None
        try:
            r_get = requests.get(url, headers=headers, timeout=5)
            if r_get.status_code == 200:
                sha = r_get.json().get("sha")
        except Exception:
            pass

        with status_lock:
            payload_str = json.dumps(live_status, indent=2)

        body = {
            "message": f"Cloud status: {live_status.get('phase', 'update')}",
            "content": base64.b64encode(payload_str.encode("utf-8")).decode("utf-8")
        }
        if sha:
            body["sha"] = sha
        requests.put(url, headers=headers, json=body, timeout=8)
    except Exception:
        pass

def status_publisher_daemon():
    """Publishes live status to cloud_status.json every 25 seconds"""
    while True:
        time.sleep(25)
        publish_status_to_github()
        with status_lock:
            if live_status["status"] in ["completed", "error"]:
                break

def get_next_port():
    global port_counter
    with port_lock:
        port_counter += 1
        if port_counter > 55000:
            port_counter = 20000
        return port_counter

def resolve_host_cached(host):
    with dns_lock:
        if host in dns_cache:
            return dns_cache[host]
    try:
        ip = socket.gethostbyname(host)
        with dns_lock:
            dns_cache[host] = ip
        return ip
    except Exception:
        with dns_lock:
            dns_cache[host] = None
        return None

def safe_b64decode(s):
    s = s.strip().replace(" ", "").replace("\n", "").replace("\r", "")
    rem = len(s) % 4
    if rem > 0:
        s += "=" * (4 - rem)
    try:
        return base64.b64decode(s).decode("utf-8", errors="ignore")
    except Exception:
        return ""

def clean_raw_uri(uri):
    uri = uri.strip().replace("&amp;", "&").replace("%26", "&")
    if "#" in uri:
        main_part, tag_part = uri.split("#", 1)
        uri = main_part.strip() + "#" + tag_part.strip()
    return uri

def get_real_proto(uri):
    u = uri.lower()
    for p in ["vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "tuic://"]:
        if u.startswith(p):
            return p.replace("://", "")
    return ""

def extract_config_key(uri):
    uri = clean_raw_uri(uri)
    proto = get_real_proto(uri)
    if not proto:
        return None
    try:
        if proto == "vmess":
            b64_part = uri.split("://")[1].split("#")[0].strip()
            raw_json = safe_b64decode(b64_part)
            data = json.loads(raw_json)
            host = str(data.get("add", "")).lower().strip()
            port = str(data.get("port", "")).strip()
            path = str(data.get("path", "/")).lower().strip()
            uid = str(data.get("id", "")).strip()
            if host and port and uid:
                return ("vmess", host, port, path, uid)
            return None
        else:
            clean_url = uri.split("#")[0].strip()
            parsed = urlparse(clean_url)
            if not parsed.hostname or not parsed.port:
                return None
            host = parsed.hostname.lower().strip()
            port = str(parsed.port).strip()
            uid = unquote(parsed.username or "").strip()
            q = parse_qs(parsed.query)
            path = unquote(q.get("path", ["/"])[0]).lower().strip()
            return (proto, host, port, path, uid)
    except Exception:
        return None

def download_single_sub(url):
    configs = []
    headers = {"User-Agent": "v2rayN/6.23 Mozilla/5.0"}
    try:
        r = requests.get(url, headers=headers, timeout=10, verify=False)
        if r.status_code == 200:
            text = r.text.strip()
            if "://" not in text[:50] and len(text) > 40:
                decoded = safe_b64decode(text)
                if "://" in decoded:
                    text = decoded
            for line in text.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    if get_real_proto(line):
                        configs.append(line)
    except Exception:
        pass
    return configs

def check_tcp_port(item):
    key, raw_uri = item
    proto, host, port_str, path, uid = key
    try:
        port = int(port_str)
        ip = resolve_host_cached(host)
        if not ip:
            return None
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TCP_TIMEOUT)
        s.connect((ip, port))
        s.close()
        return raw_uri
    except Exception:
        return None

def parse_uri_to_outbound(uri):
    uri = clean_raw_uri(uri)
    proto = get_real_proto(uri)
    tag_name = "proxy"
    try:
        if proto == "vmess":
            b64_part = uri.split("://")[1].split("#")[0].strip()
            data = json.loads(safe_b64decode(b64_part))
            if not data.get("id") or not data.get("add") or not data.get("port"):
                return None, None
            stream = {"network": str(data.get("net", "tcp")).lower()}
            sni = data.get("sni") or data.get("host", "")
            if str(data.get("tls", "")).lower() == "tls":
                stream["security"] = "tls"
                stream["tlsSettings"] = {
                    "serverName": sni,
                    "fingerprint": "chrome"
                }
            if stream["network"] == "ws":
                ws_host = data.get("host", "") or sni
                stream["wsSettings"] = {"path": data.get("path", "/")}
                if ws_host:
                    stream["wsSettings"]["headers"] = {"Host": ws_host}
            elif stream["network"] == "grpc":
                stream["grpcSettings"] = {"serviceName": data.get("path", "")}
            elif stream["network"] in ["xhttp", "httpupgrade"]:
                stream["xhttpSettings"] = {
                    "path": data.get("path", "/"),
                    "host": data.get("host", "") or sni,
                }
            return "xray", {
                "tag": tag_name,
                "protocol": "vmess",
                "settings": {
                    "vnext": [{
                        "address": str(data.get("add")).strip(),
                        "port": int(str(data.get("port")).strip()),
                        "users": [{
                            "id": str(data.get("id")).strip(),
                            "alterId": int(data.get("aid", 0)),
                            "security": data.get("scy", "auto"),
                        }],
                    }]
                },
                "streamSettings": stream,
            }

        clean_url = uri.split("#")[0].strip()
        parsed = urlparse(clean_url)
        if not parsed.hostname or not parsed.port:
            return None, None
        query = parse_qs(parsed.query)

        net = unquote(query.get("type", ["tcp"])[0]).lower().strip()
        sec = unquote(query.get("security", ["none"])[0]).lower().strip()
        sni_val = unquote(query.get("sni", [""])[0] or query.get("host", [""])[0] or parsed.hostname).strip()
        path_val = unquote(query.get("path", ["/"])[0]).strip()
        host_header = unquote(query.get("host", [""])[0]).strip() or sni_val
        flow_val = unquote(query.get("flow", [""])[0]).strip()

        if proto in ["hysteria2", "hy2"]:
            out_sb = {
                "type": "hysteria2",
                "tag": tag_name,
                "server": parsed.hostname,
                "server_port": int(parsed.port),
                "password": unquote(parsed.username).strip() if parsed.username else "",
                "tls": {"enabled": True, "server_name": sni_val, "insecure": True},
            }
            if query.get("obfs"):
                out_sb["obfs"] = {
                    "type": unquote(query.get("obfs")[0]).strip(),
                    "password": unquote(query.get("obfs-password", [""])[0]).strip(),
                }
            return "singbox", out_sb

        if proto == "vless":
            if not parsed.username:
                return None, None
            stream_settings = {"network": net}
            if net == "ws":
                stream_settings["wsSettings"] = {"path": path_val}
                if host_header:
                    stream_settings["wsSettings"]["headers"] = {"Host": host_header}
            elif net == "httpupgrade":
                stream_settings["httpupgradeSettings"] = {
                    "path": path_val,
                    "host": host_header,
                }
            elif net == "xhttp":
                stream_settings["xhttpSettings"] = {
                    "path": path_val,
                    "host": host_header,
                }
            elif net == "grpc":
                stream_settings["grpcSettings"] = {
                    "serviceName": unquote(query.get("serviceName", [""])[0]).strip()
                }

            if sec == "tls":
                stream_settings["security"] = "tls"
                stream_settings["tlsSettings"] = {
                    "serverName": sni_val,
                    "fingerprint": "chrome"
                }
            elif sec == "reality":
                pbk = unquote(query.get("pbk", [""])[0]).strip()
                if not pbk:
                    return None, None
                raw_sid = unquote(query.get("sid", [""])[0]).strip()
                stream_settings["security"] = "reality"
                stream_settings["realitySettings"] = {
                    "serverName": sni_val,
                    "fingerprint": "chrome",
                    "publicKey": pbk,
                    "shortId": raw_sid if raw_sid and raw_sid != "-" else "",
                }

            user_dict = {"id": unquote(parsed.username).strip(), "encryption": "none"}
            if flow_val:
                user_dict["flow"] = flow_val

            return "xray", {
                "tag": tag_name,
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": parsed.hostname,
                        "port": int(parsed.port),
                        "users": [user_dict],
                    }]
                },
                "streamSettings": stream_settings,
            }

        if proto == "trojan":
            if not parsed.username:
                return None, None
            stream_settings = {"network": net}
            if net == "ws":
                stream_settings["wsSettings"] = {"path": path_val}
                if host_header:
                    stream_settings["wsSettings"]["headers"] = {"Host": host_header}
            elif net == "grpc":
                stream_settings["grpcSettings"] = {
                    "serviceName": unquote(query.get("serviceName", [""])[0]).strip()
                }
            if sec == "tls" or not sec or sec == "none":
                stream_settings["security"] = "tls"
                stream_settings["tlsSettings"] = {
                    "serverName": sni_val,
                    "fingerprint": "chrome"
                }
            return "xray", {
                "tag": tag_name,
                "protocol": "trojan",
                "settings": {
                    "servers": [{
                        "address": parsed.hostname,
                        "port": int(parsed.port),
                        "password": unquote(parsed.username).strip(),
                    }]
                },
                "streamSettings": stream_settings,
            }

        if proto == "ss":
            clean_body = clean_url.replace("ss://", "").split("?")[0].strip()
            if "@" in clean_body:
                userinfo, server_part = clean_body.split("@", 1)
                userinfo = safe_b64decode(userinfo) if not (":" in userinfo) else userinfo
            else:
                decoded = safe_b64decode(clean_body)
                if "@" in decoded:
                    userinfo, server_part = decoded.split("@", 1)
                else:
                    return None, None
            if ":" not in userinfo or ":" not in server_part:
                return None, None
            method, pwd = userinfo.split(":", 1)
            host, port_s = server_part.split(":", 1)
            return "xray", {
                "tag": tag_name,
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [{
                        "address": host.strip(),
                        "port": int(port_s.strip()),
                        "method": method.strip(),
                        "password": pwd.strip(),
                    }]
                },
            }
    except Exception:
        pass
    return None, None

def spawn_and_probe(raw_uri, seen_outbound_ips):
    core_type, outbound = parse_uri_to_outbound(raw_uri)
    if not outbound:
        return None

    port = get_next_port()
    temp_file = os.path.join(TEMP_DIR, f"safe_{port}.json")

    if core_type == "singbox":
        config_dict = {
            "log": {"level": "panic"},
            "inbounds": [{
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": port,
            }],
            "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
        }
        cmd = [SINGBOX_BIN, "run", "-c", temp_file]
    else:
        stream = outbound.get("streamSettings", {})
        if isinstance(stream, dict) and isinstance(stream.get("tlsSettings"), dict):
            stream["tlsSettings"].pop("allowInsecure", None)

        config_dict = {
            "log": {"loglevel": "none"},
            "inbounds": [{
                "port": port,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"auth": "noauth"},
            }],
            "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
        }
        cmd = [XRAY_BIN, "run", "-c", temp_file]

    try:
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(config_dict, f)

        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        ready = False
        for _ in range(20):
            if proc.poll() is not None:
                break
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.06):
                    ready = True
                    break
            except OSError:
                time.sleep(0.04)

        if not ready:
            try:
                proc.kill()
                proc.wait(timeout=0.2)
            except Exception:
                pass
            if os.path.exists(temp_file):
                try: os.remove(temp_file)
                except Exception: pass
            return None

        proxies = {
            "http": f"socks5h://127.0.0.1:{port}",
            "https": f"socks5h://127.0.0.1:{port}",
        }

        t0 = time.time()
        res = requests.get(PROBE_URL, proxies=proxies, timeout=(1.5, CORE_TIMEOUT), verify=False, allow_redirects=False)
        ping_ms = int((time.time() - t0) * 1000)

        is_alive = (res.status_code == 204)
        outbound_ip = None

        if is_alive:
            try:
                r_ip = requests.get("https://api.ip.sb/geoip", proxies=proxies, timeout=1.8, verify=False)
                if r_ip.status_code == 200:
                    outbound_ip = r_ip.json().get("ip", "").strip()
            except Exception:
                pass

        try:
            proc.kill()
            proc.wait(timeout=0.2)
        except Exception:
            pass
        if os.path.exists(temp_file):
            try: os.remove(temp_file)
            except Exception: pass

        if is_alive:
            with write_lock:
                if outbound_ip:
                    if outbound_ip in seen_outbound_ips:
                        return None
                    seen_outbound_ips.add(outbound_ip)
            return raw_uri, ping_ms, outbound_ip
        return None

    except Exception:
        if os.path.exists(temp_file):
            try: os.remove(temp_file)
            except Exception: pass
        return None


def cleanup_zombies_and_temp():
    """Kills orphan xray/sing-box processes and cleans temp files between batches."""
    try:
        if os.name != "nt":
            subprocess.run(["pkill", "-9", "-f", "xray"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["pkill", "-9", "-f", "sing-box"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.run(["taskkill", "/F", "/IM", "xray.exe", "/T"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["taskkill", "/F", "/IM", "sing-box.exe", "/T"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

    try:
        if os.path.exists(TEMP_DIR):
            for fname in os.listdir(TEMP_DIR):
                fpath = os.path.join(TEMP_DIR, fname)
                try:
                    if os.path.isfile(fpath):
                        os.remove(fpath)
                except Exception:
                    pass
    except Exception:
        pass

def publish_alive_configs_to_github(confirmed_alive):
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not token or not repo:
        return
    try:
        url = f"https://api.github.com/repos/{repo}/contents/alive_configs.txt"
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3+json"}
        sha = None
        try:
            r_get = requests.get(url, headers=headers, timeout=5)
            if r_get.status_code == 200:
                sha = r_get.json().get("sha")
        except Exception:
            pass

        content_str = "\n".join(confirmed_alive) + "\n"
        body = {
            "message": f"Auto-update: fresh alive_configs.txt ({len(confirmed_alive)} alive)",
            "content": base64.b64encode(content_str.encode("utf-8")).decode("utf-8")
        }
        if sha:
            body["sha"] = sha
        res = requests.put(url, headers=headers, json=body, timeout=20)
        if res.status_code in [200, 201]:
            print(f"[+] Direct API push for alive_configs.txt succeeded ({len(confirmed_alive)} configs)", flush=True)
        else:
            print(f"[-] Direct API push status: {res.status_code}", flush=True)
    except Exception as e:
        print(f"[-] Direct API push failed: {e}", flush=True)

def main():
    print("=" * 65, flush=True)
    print("   V2RAY CLOUD PRE-FILTER (GITHUB ACTIONS ULTRA RUNNER)   ", flush=True)
    print("=" * 65, flush=True)

    # Start live status background publisher
    t_daemon = threading.Thread(target=status_publisher_daemon, daemon=True)
    t_daemon.start()

    update_status(phase="Reading Subscriptions", progress="0%")
    publish_status_to_github()

    if not os.path.exists(SUBS_FILE):
        print(f"Error: {SUBS_FILE} not found!", flush=True)
        update_status(status="error", phase=f"Error: {SUBS_FILE} missing")
        publish_status_to_github()
        sys.exit(1)

    with open(SUBS_FILE, "r", encoding="utf-8-sig") as f:
        sub_urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    print(f"[*] Loaded {len(sub_urls)} subscription URLs.", flush=True)
    update_status(phase=f"Downloading {len(sub_urls)} Subscriptions", progress="0%")
    publish_status_to_github()

    raw_configs = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_DL_WORKERS) as executor:
        futs = [executor.submit(download_single_sub, u) for u in sub_urls]
        for f in concurrent.futures.as_completed(futs):
            raw_configs.extend(f.result())

    print(f"[+] Downloaded {len(raw_configs):,} raw configs.", flush=True)
    update_status(total_raw=len(raw_configs), phase="Static Deduplication", progress="10%")
    publish_status_to_github()

    # Phase 1: Static Deduplication
    print("[*] Phase 1: Performing static deduplication (protocol, host, port, path, uuid)...", flush=True)
    unique_items = {}
    for uri in raw_configs:
        key = extract_config_key(uri)
        if key and key not in unique_items:
            unique_items[key] = uri

    print(f"[+] Unique configs after static dedup: {len(unique_items):,} (Dropped {len(raw_configs) - len(unique_items):,} duplicates!)", flush=True)

    # Phase 2: TCP Handshake Probe
    print(f"[*] Phase 2: High-speed TCP port handshake check (Workers: {MAX_TCP_WORKERS})...", flush=True)
    update_status(phase="Phase 2: TCP Handshake Check", progress="15%")
    publish_status_to_github()

    tcp_survivors = []
    t_tcp_start = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_TCP_WORKERS) as executor:
        items_list = list(unique_items.items())
        futs = [executor.submit(check_tcp_port, item) for item in items_list]
        done_tcp = 0
        total_tcp = len(items_list)
        for f in concurrent.futures.as_completed(futs):
            done_tcp += 1
            if done_tcp % 3000 == 0 or done_tcp == total_tcp:
                pct = done_tcp * 100 // total_tcp
                print(f"    -> TCP progress: {done_tcp}/{total_tcp} ({pct}%) | Responding: {len(tcp_survivors)}", flush=True)
                update_status(progress=f"TCP: {pct}% ({len(tcp_survivors)} active)")
            res = f.result()
            if res:
                tcp_survivors.append(res)

    tcp_elapsed = time.time() - t_tcp_start
    print(f"[+] Responding TCP ports: {len(tcp_survivors):,} in {tcp_elapsed:.1f}s", flush=True)

    # Phase 3: Core Probe via Xray/Sing-box (Chunked Batches with Automatic Process Cleanup)
    CHUNK_SIZE = 1200
    total_survivors = len(tcp_survivors)
    total_chunks = (total_survivors + CHUNK_SIZE - 1) // CHUNK_SIZE
    print(f"[*] Phase 3: Core Handshake & Google 204 Probe in {total_chunks} Batches of {CHUNK_SIZE} (Workers: {MAX_CORE_WORKERS})...", flush=True)
    update_status(phase=f"Phase 3: Core Probe (1/{total_chunks} Batches)", progress="50%")
    publish_status_to_github()

    confirmed_alive = []
    seen_outbound_ips = set()
    t_core_start = time.time()
    done_total = 0

    # Initialize empty output file for appending
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        pass

    for chunk_idx in range(total_chunks):
        chunk_start = chunk_idx * CHUNK_SIZE
        chunk_end = min(chunk_start + CHUNK_SIZE, total_survivors)
        current_chunk = tcp_survivors[chunk_start:chunk_end]
        
        print(f"\n--- [BATCH {chunk_idx + 1}/{total_chunks}] Testing nodes {chunk_start + 1:,} to {chunk_end:,} ({len(current_chunk):,} configs) ---", flush=True)
        update_status(phase=f"Phase 3: Batch {chunk_idx + 1}/{total_chunks}", progress=f"Batch {chunk_idx + 1}/{total_chunks} | Alive: {len(confirmed_alive)}")

        chunk_alive = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_CORE_WORKERS) as executor:
            futs = [executor.submit(spawn_and_probe, uri, seen_outbound_ips) for uri in current_chunk]
            chunk_done = 0
            for f in concurrent.futures.as_completed(futs):
                chunk_done += 1
                done_total += 1
                res = f.result()
                if res:
                    uri, ping, ip = res
                    confirmed_alive.append(uri)
                    chunk_alive.append(uri)
                    # Immediately append newly alive config to the single output file!
                    with open(OUTPUT_FILE, "a", encoding="utf-8") as f_out:
                        f_out.write(uri + "\n")

                if chunk_done % 200 == 0 or chunk_done == len(current_chunk):
                    pct = done_total * 100 // total_survivors
                    print(f"    -> Progress: {done_total}/{total_survivors} ({pct}%) | Batch Alive: +{len(chunk_alive)} | Total Alive: {len(confirmed_alive)}", flush=True)
                    update_status(progress=f"Core: {pct}% ({len(confirmed_alive)} alive)", alive_count=len(confirmed_alive))

        # End of batch: completely kill all lingering core processes and clean temp directory!
        cleanup_zombies_and_temp()
        time.sleep(0.5)

        # Incrementally publish current alive configs to GitHub every batch!
        if len(chunk_alive) > 0 or chunk_idx % 2 == 0 or chunk_idx == total_chunks - 1:
            publish_alive_configs_to_github(confirmed_alive)
            publish_status_to_github()

        print(f"[+] Batch {chunk_idx + 1} complete (+{len(chunk_alive)} alive). Processes & temp storage wiped. Total alive so far: {len(confirmed_alive):,}", flush=True)

    core_elapsed = time.time() - t_core_start
    file_size_kb = os.path.getsize(OUTPUT_FILE) / 1024 if os.path.exists(OUTPUT_FILE) else 0

    print("=" * 65, flush=True)
    print(f"✅ 100% COMPLETE: Scanned all {total_survivors:,} configs across {total_chunks} batches!", flush=True)
    print(f"   Total Fully Confirmed ALIVE & UNIQUE nodes: {len(confirmed_alive):,} ({file_size_kb:.1f} KB) in {core_elapsed:.1f}s", flush=True)
    print("=" * 65, flush=True)

    publish_alive_configs_to_github(confirmed_alive)
    update_status(status="completed", phase="Cloud Filter Complete", progress="100%", alive_count=len(confirmed_alive))
    publish_status_to_github()

if __name__ == "__main__":
    main()
