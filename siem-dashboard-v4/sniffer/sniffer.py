"""
AEGIS SIEM — Gateway Packet Sniffer v4
========================================
• Captures traffic for the ENTIRE gateway (all IPs on the network), not just localhost.
• Tracks sites visited per IP (DNS + HTTPS SNI + HTTP Host).
• Detects and reports attacks (SQLi, XSS, path traversal, shell injection, recon tools,
  brute force, port scans, malware C2).
• Smart alert de-duplication — no more high-traffic spam for normal browsing.

Run as:
  Linux/macOS: sudo python3 sniffer.py
  Windows:     python sniffer.py  (as Administrator)
"""

import sys
import time
import struct
import re
import requests
import socket
from datetime import datetime
from collections import defaultdict

BACKEND_URL    = "http://localhost:5000/logs"
BATCH_SIZE     = 10
BATCH_INTERVAL = 0.8

# Try scapy
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, get_if_list, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not found. Running in DEMO mode.")

# Attack signatures
SQL_PATTERNS = [
    r"(\bselect\b.*\bfrom\b)", r"(\bunion\b.*\bselect\b)",
    r"(--|#|/\*)", r"(\bor\b\s+\d+=\d+)",
    r"(\bdrop\b.*\btable\b)", r"(\bexec\b|\bexecute\b)",
    r"(\bsleep\b\s*\()", r"(\bbenchmark\b\s*\()",
    r"('.*'--)", r"(xp_cmdshell)",
]
XSS_PATTERNS = [
    r"(<script.*?>)", r"(javascript\s*:)",
    r"(on\w+\s*=)", r"(<iframe)", r"(alert\s*\()", r"(document\.cookie)",
    r"(eval\s*\()", r"(String\.fromCharCode)",
]
TRAVERSAL_PATTERNS = [
    r"(\.\.\/){2,}", r"(%2e%2e%2f){2,}",
    r"(/etc/passwd)", r"(/etc/shadow)",
    r"(\\windows\\system32)", r"(boot\.ini)",
    r"(/proc/self)", r"(php://)",
]
SHELL_PATTERNS = [
    r"(;\s*(ls|cat|id|whoami|wget|curl|bash|sh|cmd)[\s;|&])",
    r"(\|\s*(ls|cat|id|whoami|bash|sh))",
    r"(`[^`]+`)", r"(\$\(.*\))", r"(nc\s+-[el])",
    r"(python\s+-c)", r"(perl\s+-e)",
]
RECON_PATTERNS = [
    r"(nikto|nmap|masscan|sqlmap|dirb|gobuster|wfuzz)",
    r"(metasploit|msfvenom|meterpreter)",
    r"(burpsuite|zaproxy|acunetix)",
    r"(hydra|medusa|crowbar)",
]
MALWARE_DOMAINS = [
    r"\.(ru|cn|tk|ml|ga|cf)\b",
    r"(pastebin\.com|paste\.ee|hastebin)",
    r"(raw\.githubusercontent\.com.*\.(sh|py|ps1|bat))",
]
BAD_DOMAIN_KEYWORDS = ["malware", "botnet", "c2-", "-c2", "payload", "dropper", "ransom", "phish"]

def check_attack(text):
    s = text.lower()
    for p in SHELL_PATTERNS:
        if re.search(p, s, re.IGNORECASE):
            return ("shell_injection", "critical", f"Shell injection: {text[:100]}")
    for p in SQL_PATTERNS:
        if re.search(p, s, re.IGNORECASE):
            return ("sql_injection", "critical", f"SQL injection: {text[:100]}")
    for p in TRAVERSAL_PATTERNS:
        if re.search(p, s, re.IGNORECASE):
            return ("path_traversal", "high", f"Path traversal: {text[:100]}")
    for p in XSS_PATTERNS:
        if re.search(p, s, re.IGNORECASE):
            return ("xss_attempt", "high", f"XSS attempt: {text[:100]}")
    for p in RECON_PATTERNS:
        if re.search(p, s, re.IGNORECASE):
            return ("recon_tool", "medium", f"Recon tool: {text[:100]}")
    return None

def check_malware_c2(domain):
    for p in MALWARE_DOMAINS:
        if re.search(p, domain, re.IGNORECASE):
            return True
    for kw in BAD_DOMAIN_KEYWORDS:
        if kw in domain.lower():
            return True
    return False

def extract_sni(data):
    try:
        if len(data) < 6 or data[0] != 0x16 or data[5] != 0x01:
            return None
        pos = 9 + 32
        if pos >= len(data): return None
        session_len = data[pos]; pos += 1 + session_len
        if pos + 2 >= len(data): return None
        cipher_len = struct.unpack("!H", data[pos:pos+2])[0]; pos += 2 + cipher_len
        if pos >= len(data): return None
        comp_len = data[pos]; pos += 1 + comp_len
        if pos + 2 >= len(data): return None
        ext_total = struct.unpack("!H", data[pos:pos+2])[0]; pos += 2
        end = pos + ext_total
        while pos + 4 <= end and pos + 4 <= len(data):
            ext_type = struct.unpack("!H", data[pos:pos+2])[0]; pos += 2
            ext_len = struct.unpack("!H", data[pos:pos+2])[0]; pos += 2
            if ext_type == 0 and pos + 5 <= len(data):
                name_len = struct.unpack("!H", data[pos+3:pos+5])[0]
                if pos + 5 + name_len <= len(data):
                    return data[pos+5:pos+5+name_len].decode("utf-8", errors="ignore")
            pos += ext_len
    except Exception:
        pass
    return None

def parse_http(raw):
    try:
        text = raw.decode("utf-8", errors="ignore")
        lines = text.split("\r\n")
        first = lines[0].split()
        if len(first) < 2: return None
        method = first[0]
        if method not in ("GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS","CONNECT","TRACE"):
            return None
        path = first[1]
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()
        return method, headers.get("host",""), path, headers.get("user-agent",""), text
    except Exception:
        return None

# Batch sender
pending = []
last_flush = time.time()

def send(ip, event, extra=None):
    global pending
    payload = {"ip": ip, "event": event}
    if extra:
        payload.update(extra)
    pending.append(payload)
    print(f"  [{datetime.now().strftime('%H:%M:%S')}] {ip:>15} -> {event}")
    if len(pending) >= BATCH_SIZE or (time.time() - last_flush) >= BATCH_INTERVAL:
        flush_batch()

def flush_batch():
    global pending, last_flush
    if not pending: return
    batch = pending[:]
    pending = []
    last_flush = time.time()
    for e in batch:
        try:
            requests.post(BACKEND_URL, json=e, timeout=2)
        except Exception:
            pass

PORT_LABELS = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP",
    110:"POP3", 143:"IMAP", 3306:"MySQL", 3389:"RDP",
    445:"SMB", 1433:"MSSQL", 5432:"PostgreSQL",
    6379:"Redis", 27017:"MongoDB", 4444:"Metasploit-shell",
    6667:"IRC/Botnet", 8080:"HTTP-alt", 8443:"HTTPS-alt",
    2222:"SSH-alt", 5900:"VNC", 9200:"Elasticsearch", 11211:"Memcached",
}

def get_local_subnets():
    try:
        hostname = socket.gethostname()
        ips = socket.getaddrinfo(hostname, None)
        prefixes = set()
        for info in ips:
            ip = info[4][0]
            if "." in ip and not ip.startswith("127."):
                parts = ip.split(".")
                prefixes.add(".".join(parts[:3]) + ".")
        return list(prefixes) if prefixes else ["192.168.1.", "10.0.0.", "172.16."]
    except Exception:
        return ["192.168.1.", "10.0.0.", "172.16."]

LOCAL_SUBNETS = get_local_subnets()

# De-duplication: only log same site visit every N seconds per IP
_site_cache = defaultdict(dict)
SITE_REPEAT_SECS = 45

def should_send_site(ip, site):
    now = time.time()
    last = _site_cache[ip].get(site, 0)
    if now - last > SITE_REPEAT_SECS:
        _site_cache[ip][site] = now
        return True
    return False

def process_packet(pkt):
    try:
        if not pkt.haslayer(IP): return
        src = pkt[IP].src
        dst = pkt[IP].dst
        # Skip pure loopback
        if src.startswith("127.") and dst.startswith("127."): return

        # DNS queries only (qr=0), all IPs on network
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            try:
                if pkt[DNS].qr != 0: return
            except Exception:
                pass
            qname = pkt[DNSQR].qname
            if isinstance(qname, bytes):
                qname = qname.decode("utf-8", errors="ignore").rstrip(".")
            if qname and not qname.endswith(".local") and not qname.endswith(".arpa"):
                if check_malware_c2(qname):
                    send(src, f"[MALWARE-C2] DNS lookup: {qname}",
                         {"site": qname, "event_type": "malware_c2"})
                elif should_send_site(src, qname):
                    send(src, f"DNS lookup: {qname}",
                         {"site": qname, "event_type": "dns_lookup"})
            return

        if pkt.haslayer(TCP):
            dport = pkt[TCP].dport
            flags = pkt[TCP].flags
            raw = bytes(pkt[TCP].payload) if pkt[TCP].payload else b""

            # HTTPS
            if dport in (443, 8443) and raw:
                sni = extract_sni(raw)
                site = sni if sni else dst
                if sni and check_malware_c2(sni):
                    send(src, f"[MALWARE-C2] HTTPS to: {sni}",
                         {"site": sni, "event_type": "malware_c2"})
                elif should_send_site(src, site):
                    port_label = "" if dport == 443 else f":{dport}"
                    send(src, f"HTTPS visit: {site}{port_label}",
                         {"site": site, "event_type": "https_visit"})
                return

            # HTTP
            if dport in (80, 8080) and raw:
                parsed = parse_http(raw)
                if parsed:
                    method, host, path, ua, body = parsed
                    h = host or dst
                    attack = check_attack(path) or check_attack(ua) or check_attack(body[:500])
                    if attack:
                        atype, sev, desc = attack
                        send(src, f"[ATTACK:{atype.upper()}] {method} http://{h}{path[:80]}",
                             {"site": h, "event_type": "attack", "attack_type": atype, "severity_hint": sev})
                    elif should_send_site(src, h):
                        send(src, f"HTTP {method} http://{h}{path[:60]}",
                             {"site": h, "event_type": "http_visit"})
                elif should_send_site(src, dst):
                    send(src, f"HTTP connection to {dst}:{dport}",
                         {"event_type": "http_connection"})
                return

            # Auth attempts
            if dport in (22, 23, 3389, 21, 2222) and flags == 0x02:
                label = PORT_LABELS.get(dport, f"port {dport}")
                send(src, f"auth_attempt to {label} (port {dport}) on {dst}",
                     {"event_type": "auth_attempt"})
                return

            # Named sensitive ports
            if dport in PORT_LABELS:
                if flags == 0x02:
                    label = PORT_LABELS[dport]
                    send(src, f"TCP SYN -> {label} (port {dport}) on {dst}",
                         {"event_type": "port_access"})
                return

            # Generic SYN (port scan indicator)
            if flags == 0x02 and dport < 10000:
                send(src, f"TCP connection to port {dport} on {dst}",
                     {"event_type": "port_scan"})

        elif pkt.haslayer(UDP):
            dport = pkt[UDP].dport
            # Skip well-known benign UDP
            if dport not in (53, 5353, 67, 68, 123, 137, 138, 1900, 5355):
                send(src, f"UDP packet to port {dport} on {dst}",
                     {"event_type": "udp_traffic"})

        elif pkt.haslayer(ICMP):
            t = pkt[ICMP].type
            if t == 8: send(src, f"ICMP ping to {dst}", {"event_type": "icmp"})
            elif t == 0: send(dst, f"ICMP ping reply from {src}", {"event_type": "icmp"})

    except Exception as e:
        print(f"[!] Packet error: {e}")


# Demo mode
import random

DEMO_EVENTS = [
    # Normal browsing - multiple devices
    ("HTTPS visit: google.com",                                  "192.168.1.10", "google.com", "https_visit"),
    ("HTTPS visit: youtube.com",                                 "192.168.1.22", "youtube.com", "https_visit"),
    ("HTTPS visit: github.com",                                  "192.168.1.11", "github.com", "https_visit"),
    ("HTTPS visit: stackoverflow.com",                           "192.168.1.14", "stackoverflow.com", "https_visit"),
    ("DNS lookup: facebook.com",                                 "192.168.1.18", "facebook.com", "dns_lookup"),
    ("DNS lookup: api.openai.com",                               "192.168.1.12", "api.openai.com", "dns_lookup"),
    ("HTTP GET http://news.ycombinator.com/",                    "192.168.1.19", "news.ycombinator.com", "http_visit"),
    ("HTTPS visit: netflix.com",                                 "192.168.1.30", "netflix.com", "https_visit"),
    ("HTTPS visit: twitter.com",                                 "192.168.1.25", "twitter.com", "https_visit"),
    ("HTTPS visit: reddit.com",                                  "192.168.1.16", "reddit.com", "https_visit"),
    ("HTTPS visit: amazon.com",                                  "192.168.1.31", "amazon.com", "https_visit"),
    ("DNS lookup: zoom.us",                                      "192.168.1.20", "zoom.us", "dns_lookup"),
    ("HTTPS visit: slack.com",                                   "192.168.1.15", "slack.com", "https_visit"),
    ("HTTPS visit: office.com",                                  "192.168.1.23", "office.com", "https_visit"),
    ("HTTPS visit: drive.google.com",                            "192.168.1.24", "drive.google.com", "https_visit"),
    # Attack traffic
    ("[ATTACK:SQL_INJECTION] GET http://192.168.1.1/login?id=1'+OR+'1'='1", "10.0.0.5", "192.168.1.1", "attack"),
    ("[ATTACK:XSS_ATTEMPT] GET http://target.com/<script>alert(1)</script>", "10.0.0.5", "target.com", "attack"),
    ("[ATTACK:PATH_TRAVERSAL] GET http://target.com/../../../../etc/passwd", "10.0.0.5", "target.com", "attack"),
    ("[ATTACK:SHELL_INJECTION] GET http://target.com/cmd?exec=;whoami",      "10.0.0.5", "target.com", "attack"),
    ("[ATTACK:RECON_TOOL] User-Agent: sqlmap/1.7.8",                         "10.0.0.6", "target.com", "attack"),
    ("[MALWARE-C2] DNS lookup: malware-c2-server.ru",                        "192.168.1.14", "malware-c2-server.ru", "malware_c2"),
    ("TCP SYN -> Metasploit-shell (port 4444) on 10.0.0.1",                  "10.0.0.8", None, "port_access"),
    ("TCP connection to RDP (port 3389) on 192.168.1.1",                     "10.0.0.3", None, "port_access"),
    ("auth_attempt to SSH (port 22) on 192.168.1.1",                         "10.0.0.9", None, "auth_attempt"),
    ("[MALWARE-C2] HTTPS to: botnet-payload.tk",                             "192.168.1.18", "botnet-payload.tk", "malware_c2"),
]

def demo_mode():
    print("\nDEMO MODE — simulating multi-device gateway traffic + attacks")
    print("   Install scapy and run as root/admin for live gateway capture.\n")
    attacker_ips = ["10.0.0.5", "10.0.0.6", "185.220.101.45"]
    while True:
        if random.random() < 0.05:
            attacker = random.choice(attacker_ips)
            print(f"\nBrute force burst from {attacker}")
            for _ in range(random.randint(8, 20)):
                try:
                    requests.post(BACKEND_URL, json={
                        "ip": attacker,
                        "event": "auth_attempt to SSH (port 22) on 192.168.1.1",
                        "event_type": "auth_attempt"
                    }, timeout=2)
                    time.sleep(0.05)
                except Exception: pass

        if random.random() < 0.03:
            attacker = random.choice(attacker_ips)
            print(f"\nPort scan from {attacker}")
            for port in random.sample(range(1, 10000), 18):
                try:
                    requests.post(BACKEND_URL, json={
                        "ip": attacker,
                        "event": f"TCP connection to port {port} on 192.168.1.1",
                        "event_type": "port_scan"
                    }, timeout=2)
                    time.sleep(0.03)
                except Exception: pass

        ev = random.choice(DEMO_EVENTS)
        event, ip, site, etype = ev
        payload = {"ip": ip, "event": event, "event_type": etype}
        if site:
            payload["site"] = site
        try:
            requests.post(BACKEND_URL, json=payload, timeout=2)
            print(f"  [{datetime.now().strftime('%H:%M:%S')}] {ip:>15} -> {event}")
        except Exception as e:
            print(f"[!] Backend unreachable: {e}")
        time.sleep(random.uniform(0.5, 2.5))


if __name__ == "__main__":
    print("=" * 70)
    print("  AEGIS SIEM - Gateway Sniffer v4")
    print("  Scope   : Entire gateway (ALL IPs on your network)")
    print("  Detects : DNS / HTTP / HTTPS sites, SQLi, XSS, Path traversal,")
    print("            Shell injection, Recon tools, Brute force, Malware C2")
    print("=" * 70)

    if not SCAPY_AVAILABLE:
        demo_mode()
        sys.exit(0)

    iface_list = get_if_list()
    print(f"\nAvailable interfaces: {iface_list}")
    print(f"Local subnets: {LOCAL_SUBNETS}")
    print(f"\nCapturing ALL gateway traffic (promiscuous mode)\n")

    for iface in [None, "any"] + iface_list:
        try:
            if iface is None:
                print("Sniffing all interfaces...")
                conf.sniff_promisc = True
                sniff(prn=process_packet, store=False, filter="ip")
            elif iface == "any":
                print("Sniffing on 'any'...")
                sniff(iface="any", prn=process_packet, store=False, filter="ip")
            else:
                print(f"Trying: {iface}")
                conf.sniff_promisc = True
                sniff(iface=iface, prn=process_packet, store=False, filter="ip")
            break
        except KeyboardInterrupt:
            print("\nStopped.")
            flush_batch()
            sys.exit(0)
        except Exception as e:
            print(f"   Failed: {e}")
    else:
        print("\nNo interface available - demo mode.\n")
        demo_mode()
