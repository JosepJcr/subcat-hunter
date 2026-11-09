#!/usr/bin/env python3
"""
SubCat - Passive Login Hunter & Deep Dig + Active Enum v3.0
Reconocimiento pasivo multi-fuente, auditoria DNS profunda y enumeracion ACTIVA
(diccionario, permutaciones y fuzzing con deteccion de wildcard).
Fuentes: RapidDNS, CertSpotter, HackerTarget, URLScan, crt.sh, AlienVault OTX + Deep DoH/Dig.
"""

import concurrent.futures
import ipaddress
import json
import os
import random
import re
import socket
import string
import struct
import sys
import threading
import time
import urllib.parse
import urllib.request
from typing import Dict, Iterable, List, Set, Tuple

# Colores ANSI para la terminal
CYAN = "\033[96m"
MAGENTA = "\033[95m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


def get_current_user() -> str:
    """Detecta de forma dinamica el usuario del sistema (Linux/WSL/Windows)."""
    user = os.environ.get("USER") or os.environ.get("USERNAME")
    if not user:
        try:
            import getpass
            user = getpass.getuser()
        except Exception:
            user = "auditor"
    return user


def get_banner(username: str) -> str:
    """Genera la cabecera estilizada con saludo adaptado al usuario (sin emojis)."""
    return f"""{CYAN}
       /\\_/\\  
      ( {MAGENTA}o.o{CYAN} )   {BOLD}{MAGENTA}S U B C A T{RESET}{CYAN} :: {YELLOW}Passive Login Hunter & Deep Dig v3.0{RESET}
      {CYAN} > {MAGENTA}^{CYAN} <    {GREEN}>> Hello, {BOLD}{MAGENTA}{username}{RESET}{GREEN}! Passive reconnaissance & deep audit <<{RESET}
      {CYAN}(_|_|_)   {BOLD}[ Multi-Engine OSINT | Deep Dig | Passive + Active Enum ]{RESET}
"""

# Palabras clave ampliadas para identificar portales, logins, accesos y entornos sensibles
DEFAULT_KEYWORDS = [
    "admin", "login", "portal", "auth", "sso", "panel", "access",
    "vpn", "gateway", "dashboard", "intranet", "corp", "internal",
    "dev", "stage", "staging", "test", "qa", "cpanel", "webmail",
    "secure", "remote", "idp", "saml", "oauth", "identity",
    "keycloak", "okta", "manage", "control", "jira", "confluence",
    "jenkins", "grafana", "kibana", "vault", "git", "gitlab", "api-dev"
]

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"

MULTI_PART_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk",
    "com.es", "nom.es", "org.es", "gob.es", "edu.es",
    "com.mx", "org.mx", "gob.mx", "edu.mx",
    "com.ar", "org.ar", "gov.ar", "com.co", "com.br",
    "co.jp", "com.au", "com.pe", "com.ve", "com.uy"
}


def clean_domain(raw_domain: str) -> str:
    """Limpia el dominio introducido eliminando protocolos, barras y puertos."""
    domain = raw_domain.strip().lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0]
    domain = domain.split(":")[0]
    return domain.strip()


def extract_apex_domain(domain: str) -> str:
    """Obtiene el dominio raiz (apex) a partir de un subdominio."""
    parts = domain.split(".")
    if len(parts) <= 2:
        return domain
    two_tld = ".".join(parts[-2:])
    if two_tld in MULTI_PART_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def fetch_url(url: str, timeout: int = 8) -> str:
    """Peticion GET HTTP rapida con cabecera estandar de navegador."""
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/json,application/xhtml+xml,*/*",
        "Accept-Language": "en-US,en;q=0.9,es;q=0.8"
    }
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="ignore")


def normalize_subdomain(name: str, target: str) -> str:
    """Limpia y valida que el subdominio pertenezca al objetivo."""
    name = name.strip().lower()
    name = re.sub(r"^\*\.", "", name)
    name = re.sub(r"^https?://", "", name)
    name = name.split("/")[0].split(":")[0]
    if (name.endswith("." + target) or name == target) and len(name) > len(target):
        return name
    return ""


# --- Motores de busqueda pasiva ---

def query_rapiddns(domain: str) -> Tuple[str, Set[str]]:
    subdomains: Set[str] = set()
    try:
        url = f"https://rapiddns.io/subdomain/{urllib.parse.quote(domain)}?full=1"
        html = fetch_url(url, timeout=9)
        matches = re.findall(rf'[\w\.-]+\.{re.escape(domain)}', html)
        for m in matches:
            sub = normalize_subdomain(m, domain)
            if sub:
                subdomains.add(sub)
    except Exception:
        pass
    return "RapidDNS", subdomains


def query_certspotter(domain: str) -> Tuple[str, Set[str]]:
    subdomains: Set[str] = set()
    try:
        url = f"https://api.certspotter.com/v1/issuances?domain={urllib.parse.quote(domain)}&include_subdomains=true&expand=dns_names"
        content = fetch_url(url, timeout=9)
        data = json.loads(content)
        for entry in data:
            for name in entry.get("dns_names", []):
                sub = normalize_subdomain(name, domain)
                if sub:
                    subdomains.add(sub)
    except Exception:
        pass
    return "CertSpotter", subdomains


def query_hackertarget(domain: str) -> Tuple[str, Set[str]]:
    subdomains: Set[str] = set()
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(domain)}"
        content = fetch_url(url, timeout=8)
        for line in content.splitlines():
            parts = line.split(",")
            if parts:
                sub = normalize_subdomain(parts[0], domain)
                if sub:
                    subdomains.add(sub)
    except Exception:
        pass
    return "HackerTarget", subdomains


def query_urlscan(domain: str) -> Tuple[str, Set[str]]:
    subdomains: Set[str] = set()
    try:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{urllib.parse.quote(domain)}&size=100"
        content = fetch_url(url, timeout=9)
        data = json.loads(content)
        for result in data.get("results", []):
            page = result.get("page", {})
            host = page.get("domain", "")
            sub = normalize_subdomain(host, domain)
            if sub:
                subdomains.add(sub)
    except Exception:
        pass
    return "URLScan", subdomains


def query_crt_sh(domain: str) -> Tuple[str, Set[str]]:
    subdomains: Set[str] = set()
    try:
        url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
        content = fetch_url(url, timeout=10)
        data = json.loads(content)
        for entry in data:
            name_val = entry.get("name_value", "")
            for name in name_val.split("\n"):
                sub = normalize_subdomain(name, domain)
                if sub:
                    subdomains.add(sub)
    except Exception:
        pass
    return "crt.sh", subdomains


def query_alienvault(domain: str) -> Tuple[str, Set[str]]:
    subdomains: Set[str] = set()
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{urllib.parse.quote(domain)}/passive_dns"
        content = fetch_url(url, timeout=7)
        data = json.loads(content)
        for record in data.get("passive_dns", []):
            host = record.get("hostname", "")
            sub = normalize_subdomain(host, domain)
            if sub:
                subdomains.add(sub)
    except Exception:
        pass
    return "AlienVault", subdomains


def run_parallel_scan(domain: str) -> Set[str]:
    """Ejecuta los motores pasivos en paralelo."""
    engines = [query_rapiddns, query_certspotter, query_hackertarget, query_urlscan, query_crt_sh, query_alienvault]
    all_subs: Set[str] = set()
    print(f"\n{YELLOW}[*] Iniciando consultas pasivas en paralelo (Zero-Traffic)...{RESET}")
    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(engines)) as executor:
        futures = {executor.submit(e, domain): e for e in engines}
        for future in concurrent.futures.as_completed(futures):
            try:
                name, results = future.result()
                if results:
                    print(f"  {GREEN}[+]{RESET} {BOLD}{name:<13}{RESET}: {GREEN}{len(results):>3} subdominios{RESET}")
                    all_subs |= results
                else:
                    print(f"  {YELLOW}[-]{RESET} {name:<13}: Sin resultados o temporalmente inaccesible")
            except Exception as e:
                print(f"  {RED}[-]{RESET} Error en motor: {e}")

    elapsed = round(time.time() - start_time, 2)
    print(f"{CYAN}[OK] Escaneo completado en {elapsed}s | Total unicos: {BOLD}{len(all_subs)}{RESET}\n")
    return all_subs


# --- Motor de Dig Profundo (DNS over HTTPS / DoH Pasivo) ---

def doh_query(name: str, rtype: str, timeout: int = 5) -> List[str]:
    """Consulta DoH publica (Cloudflare / 1.1.1.1) para mantener trafico 100% pasivo."""
    url = f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(name)}&type={rtype}"
    headers = {"Accept": "application/dns-json", "User-Agent": USER_AGENT}
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
            answers = data.get("Answer", [])
            return [a.get("data", "").strip('"') for a in answers if "data" in a]
    except Exception:
        return []


def run_deep_dig(domain: str) -> Dict[str, List[str]]:
    """Ejecuta una auditoria DNS exhaustiva y pasiva del dominio objetivo."""
    print(f"\n{MAGENTA}============================================================{RESET}")
    print(f" {BOLD}DIG PROFUNDO: AUDITORIA DE INFRAESTRUCTURA DNS ({domain}){RESET}")
    print(f" (Consultas via DNS-over-HTTPS Cloudflare - Sin tocar authoritative DNS)")
    print(f"{MAGENTA}============================================================{RESET}")

    dns_report: Dict[str, List[str]] = {}
    record_types = ["NS", "MX", "A", "AAAA", "CNAME", "TXT", "SOA", "CAA"]

    for rtype in record_types:
        records = doh_query(domain, rtype)
        dns_report[rtype] = records
        if records:
            print(f"\n{BOLD}{CYAN}[+] Registros [{rtype}] ({len(records)}):{RESET}")
            for rec in records:
                rec_lower = rec.lower()
                highlight = ""
                if "v=spf1" in rec_lower:
                    highlight = f" {YELLOW}[SPF / Mail Delivery]{RESET}"
                elif "docusign" in rec_lower:
                    highlight = f" {MAGENTA}[DocuSign Cloud]{RESET}"
                elif "google" in rec_lower:
                    highlight = f" {GREEN}[Google Workspace / Cloud]{RESET}"
                elif "ms=" in rec_lower or "office" in rec_lower:
                    highlight = f" {CYAN}[Microsoft 365 / Azure]{RESET}"
                elif "atlassian" in rec_lower:
                    highlight = f" {YELLOW}[Atlassian / Jira]{RESET}"
                elif "okta" in rec_lower:
                    highlight = f" {RED}[Okta Identity SSO]{RESET}"
                elif "zoom" in rec_lower:
                    highlight = f" {CYAN}[Zoom Enterprise]{RESET}"

                print(f"   {rec}{highlight}")
        else:
            print(f"{YELLOW}[-] Registros [{rtype}]: (No configurado o privado){RESET}")

    dmarc_domain = f"_dmarc.{domain}"
    dmarc_records = doh_query(dmarc_domain, "TXT")
    dns_report["DMARC"] = dmarc_records
    print(f"\n{BOLD}{CYAN}[+] Politica de Seguridad DMARC ({dmarc_domain}):{RESET}")
    if dmarc_records:
        for d in dmarc_records:
            print(f"   {d} {GREEN}[Configurado]{RESET}")
    else:
        print(f"   {RED}[!] No se detecto registro DMARC publico{RESET}")

    return dns_report


def resolve_candidate_logins(candidates: List[Tuple[str, str]]):
    """Resuelve CNAME e IP para los subdominios de login detectados."""
    if not candidates:
        print(f"\n{YELLOW}[!] No hay candidatos para resolver.{RESET}")
        return

    print(f"\n{YELLOW}[*] Resolviendo CNAME e IPs activas para {len(candidates)} candidatos (via DoH)...{RESET}")
    print("-" * 64)

    for sub, tag in candidates:
        cnames = doh_query(sub, "CNAME", timeout=4)
        ips = doh_query(sub, "A", timeout=4)

        details = []
        if cnames:
            for c in cnames:
                c_clean = c.rstrip(".")
                cloud_tag = ""
                if "okta" in c_clean:
                    cloud_tag = f" {RED}[OKTA SSO]{RESET}"
                elif "cloudfront" in c_clean or "aws" in c_clean:
                    cloud_tag = f" {YELLOW}[AWS CloudFront]{RESET}"
                elif "azure" in c_clean or "trafficmanager" in c_clean:
                    cloud_tag = f" {CYAN}[Azure]{RESET}"
                elif "cloudflare" in c_clean:
                    cloud_tag = f" {YELLOW}[Cloudflare]{RESET}"
                elif "akamai" in c_clean or "edgekey" in c_clean:
                    cloud_tag = f" {MAGENTA}[Akamai Edge]{RESET}"
                details.append(f"CNAME -> {c_clean}{cloud_tag}")

        if ips:
            clean_ips = [ip for ip in ips if not ip.endswith(".")]
            if clean_ips:
                details.append(f"IP -> {', '.join(clean_ips[:2])}")

        status_str = " | ".join(details) if details else f"{YELLOW}(Sin resolucion publica directa){RESET}"
        print(f"  {RED}[*]{RESET} {BOLD}{sub:<35}{RESET} [{tag}]: {status_str}")


# --- Enumeracion ACTIVA: diccionario, permutaciones y fuzzing (DNS directo) ---

DEFAULT_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222"]
DNS_TIMEOUT = 2.5

BUILTIN_WORDLIST = """
www mail remote blog webmail server ns ns1 ns2 ns3 smtp secure vpn m shop ftp mail2 test portal
dev host support dev1 dev2 web web1 web2 admin mx mx1 mx2 cdn api exchange app apps gateway gw
mobile static media assets img images beta stage staging stage2 prod production qa uat demo
sandbox preprod pre-prod stg int internal intranet extranet corp corporate office login sso auth
oauth idp saml adfs identity accounts account id signin signup register panel cpanel whm plesk
dashboard console manage manager management control controlpanel backoffice back-office bo crm
erp hr helpdesk help tickets ticket jira confluence wiki docs doc kb git gitlab github bitbucket
svn repo repos code ci cd jenkins build bamboo teamcity sonar sonarqube nexus artifactory
registry docker harbor k8s kube kubernetes rancher argo argocd grafana kibana elk elastic
elasticsearch logstash splunk prometheus alertmanager zabbix nagios monitor monitoring status
metrics graphite influx vault consul nomad terraform ansible puppet chef salt db database mysql
mariadb postgres postgresql pgsql mongo mongodb redis memcached rabbitmq kafka mq queue sql mssql
oracle phpmyadmin pma adminer files file upload uploads download downloads share sharing storage
s3 bucket backup backups bak old new legacy archive tmp temp test1 test2 testing api2 api-dev
api-test api-stage v1 v2 v3 rest graphql ws websocket socket sip voip pbx webrtc meet chat im
conference zoom video stream live cam owa autodiscover lyncdiscover dialin sftp ssh rdp vnc
bastion jump jumpbox proxy proxy1 lb lb1 haproxy nginx apache tomcat origin edge cache varnish
waf firewall fw router sw switch nas san vmware vcenter esxi proxmox ilo idrac ipmi printer scan
cloud aws azure gcp okta ping pingfederate keycloak ldap ad dc dc1 dc2 radius mdm intune
endpoint soc siem sentry pay payment payments checkout billing invoice store cart orders order
catalog search solr data datalake bi analytics tableau powerbi report reports reporting lab labs
research training learn lms moodle students student partners partner vendor vendors supplier
suppliers client clients customer customers b2b b2c newsletter email mailer mta relay mailgw
imap pop pop3 es en fr de it pt us uk eu asia
""".split()

PERM_WORDS = [
    "dev", "test", "qa", "uat", "stage", "staging", "stg", "prod", "prd", "preprod", "demo",
    "beta", "sandbox", "int", "internal", "old", "new", "bak", "backup", "tmp", "admin", "api",
    "v1", "v2", "web", "app", "corp", "private", "secure", "cdn", "mgmt", "vpn", "auth",
]

ENV_TOKENS = [
    "dev", "test", "qa", "uat", "stage", "staging", "stg", "prod", "prd",
    "preprod", "demo", "beta", "sandbox", "int", "internal",
]

# (subcadena en el CNAME, etiqueta, color). Incluye proveedores propensos a subdomain takeover.
CLOUD_SIGNATURES = [
    ("okta", "OKTA SSO", RED), ("cloudfront", "AWS CloudFront", YELLOW),
    ("amazonaws", "AWS", YELLOW), ("azurewebsites", "Azure App Service", CYAN),
    ("trafficmanager", "Azure", CYAN), ("azure", "Azure", CYAN),
    ("cloudflare", "Cloudflare", YELLOW), ("akamai", "Akamai", MAGENTA),
    ("edgekey", "Akamai", MAGENTA), ("github.io", "GitHub Pages", MAGENTA),
    ("herokuapp", "Heroku", MAGENTA), ("netlify", "Netlify", MAGENTA),
    ("vercel", "Vercel", MAGENTA), ("fastly", "Fastly", MAGENTA),
    ("zendesk", "Zendesk", MAGENTA), ("shopify", "Shopify", MAGENTA),
]

_LABEL_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")


def is_valid_host(name: str) -> bool:
    """Valida longitud y caracteres de cada etiqueta DNS."""
    if not name or len(name) > 253:
        return False
    return all(_LABEL_RE.match(label) for label in name.split("."))


def cloud_tag(cname: str) -> str:
    c = cname.lower()
    for needle, label, color in CLOUD_SIGNATURES:
        if needle in c:
            return f" {color}[{label}]{RESET}"
    return ""


# --- Cliente DNS UDP minimo (solo stdlib) ---

def _encode_qname(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii")
        if not 0 < len(raw) < 64:
            raise ValueError("etiqueta invalida")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _read_name(data: bytes, off: int) -> Tuple[str, int]:
    """Lee un nombre DNS (con compresion por punteros). Devuelve (nombre, offset siguiente)."""
    labels: List[str] = []
    next_off = None
    hops = 0
    while True:
        length = data[off]
        if length == 0:
            off += 1
            break
        if length & 0xC0 == 0xC0:
            if next_off is None:
                next_off = off + 2
            off = ((length & 0x3F) << 8) | data[off + 1]
            hops += 1
            if hops > 20:
                raise ValueError("bucle de compresion")
            continue
        off += 1
        labels.append(data[off:off + length].decode("ascii", errors="ignore"))
        off += length
    return ".".join(labels), (next_off if next_off is not None else off)


def _parse_response(data: bytes, tid: int) -> Tuple[str, List[str], List[str]]:
    rid, flags, qd, an, _, _ = struct.unpack(">HHHHHH", data[:12])
    if rid != tid or not flags & 0x8000:
        raise ValueError("respuesta no valida")
    rcode = flags & 0xF
    off = 12
    for _ in range(qd):
        _, off = _read_name(data, off)
        off += 4
    ips: List[str] = []
    cnames: List[str] = []
    for _ in range(an):
        _, off = _read_name(data, off)
        rtype, _, _, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        if rtype == 1 and rdlen == 4:
            ips.append(".".join(str(b) for b in data[off:off + 4]))
        elif rtype == 5:
            target, _ = _read_name(data, off)
            cnames.append(target.lower())
        off += rdlen
    if ips or cnames:
        return "ok", ips, cnames
    if rcode == 3:
        return "nxdomain", [], []
    if rcode == 0:
        return "nodata", [], []
    return "fail", [], []


def dns_resolve(name: str, resolvers: List[str], timeout: float = DNS_TIMEOUT,
                retries: int = 2) -> Tuple[str, List[str], List[str]]:
    """Consulta A directa por UDP. Devuelve (estado, ips, cnames).
    Estados: ok | nxdomain | nodata | fail. Un CNAME sin IP cuenta como 'ok' (util para takeovers)."""
    try:
        qname = _encode_qname(name)
    except (UnicodeEncodeError, ValueError):
        return "fail", [], []

    for _ in range(retries + 1):
        resolver = random.choice(resolvers)
        tid = random.randint(0, 0xFFFF)
        packet = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", 1, 1)
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(packet, (resolver, 53))
            data, _ = sock.recvfrom(4096)
        except OSError:  # incluye socket.timeout
            continue
        finally:
            if sock is not None:
                sock.close()
        try:
            result = _parse_response(data, tid)
        except (ValueError, IndexError, struct.error):
            continue
        if result[0] == "fail":
            continue
        return result
    return "fail", [], []


class WildcardDetector:
    """Detecta wildcard DNS por zona (apex o subzona) y filtra falsos positivos."""

    def __init__(self, resolvers: List[str], timeout: float = DNS_TIMEOUT):
        self.resolvers = resolvers
        self.timeout = timeout
        self._cache: Dict[str, Tuple[Set[str], Set[str]]] = {}
        self._lock = threading.Lock()

    def profile(self, zone: str) -> Tuple[Set[str], Set[str]]:
        with self._lock:
            if zone in self._cache:
                return self._cache[zone]
        ips: Set[str] = set()
        cnames: Set[str] = set()
        for _ in range(3):
            rnd = "".join(random.choices(string.ascii_lowercase + string.digits, k=14))
            status, i, c = dns_resolve(f"{rnd}.{zone}", self.resolvers, self.timeout)
            if status == "ok":
                ips.update(i)
                cnames.update(c)
        with self._lock:
            self._cache[zone] = (ips, cnames)
        return ips, cnames

    def is_wildcard(self, name: str, ips: List[str], cnames: List[str]) -> bool:
        zone = name.split(".", 1)[1] if "." in name else name
        w_ips, w_cnames = self.profile(zone)
        if not w_ips and not w_cnames:
            return False
        if cnames and w_cnames:
            return set(cnames) <= w_cnames
        if not cnames and ips and w_ips and not w_cnames:
            return set(ips) <= w_ips
        return False


# --- Generadores de candidatos ---

def load_wordlist(path: str) -> List[str]:
    words: List[str] = []
    seen: Set[str] = set()
    try:
        with open(os.path.expanduser(path.strip().strip('"').strip("'")), "r",
                  encoding="utf-8", errors="ignore") as f:
            for line in f:
                w = line.strip().lower()
                if not w or w.startswith("#") or w in seen:
                    continue
                seen.add(w)
                words.append(w)
    except OSError as e:
        print(f"{RED}[-] No se pudo leer el diccionario: {e}{RESET}")
        return []
    return words


def dictionary_candidates(domain: str, words: Iterable[str]) -> Set[str]:
    cands = {f"{w}.{domain}" for w in words}
    return {c for c in cands if is_valid_host(c)}


def generate_permutations(seeds: Iterable[str], domain: str,
                          words: List[str] = None) -> Set[str]:
    """Permutaciones estilo altdns sobre subdominios conocidos:
    insercion de etiquetas, prefijo/sufijo con y sin guion, variaciones numericas
    e intercambio de tokens de entorno (dev <-> prod, etc.)."""
    words = words or PERM_WORDS
    suffix = "." + domain
    seed_set = set(seeds)
    out: Set[str] = set()

    for sub in seed_set:
        if not sub.endswith(suffix):
            continue
        labels = sub[:-len(suffix)].split(".")

        # 1) insertar una etiqueta nueva en cada posicion
        for i in range(len(labels) + 1):
            for w in words:
                out.add(".".join(labels[:i] + [w] + labels[i:]))

        for i, lab in enumerate(labels):
            head, tail = labels[:i], labels[i + 1:]

            def put(new_label: str):
                out.add(".".join(head + [new_label] + tail))

            # 2) prefijo / sufijo
            for w in words:
                put(f"{w}-{lab}")
                put(f"{lab}-{w}")
                put(f"{w}{lab}")
                put(f"{lab}{w}")

            # 3) variaciones numericas
            m = re.search(r"(\d+)$", lab)
            if m:
                base, num, width = lab[:m.start()], int(m.group(1)), len(m.group(1))
                for n in range(max(0, num - 3), num + 4):
                    put(f"{base}{str(n).zfill(width)}")
            else:
                for n in range(1, 4):
                    put(f"{lab}{n}")
                    put(f"{lab}-{n}")
                    put(f"{lab}0{n}")

            # 4) intercambio de tokens de entorno
            parts = lab.split("-")
            for idx, p in enumerate(parts):
                if p in ENV_TOKENS:
                    for env in ENV_TOKENS:
                        if env != p:
                            put("-".join(parts[:idx] + [env] + parts[idx + 1:]))

    result = {c + suffix for c in out}
    result = {c for c in result if is_valid_host(c) and c not in seed_set}
    return result


def expand_fuzz_template(template: str, domain: str, words: Iterable[str]) -> Set[str]:
    """Expande plantillas con FUZZ (palabras del diccionario) y NUM (0-99 y 00-09).
    Ejemplos: api-FUZZ | FUZZ.dev | app-NUM | FUZZ-NUM.internal"""
    template = template.strip()
    if "FUZZ" not in template and "NUM" not in template:
        return set()
    if not template.lower().endswith("." + domain):
        template = f"{template.rstrip('.')}.{domain}"

    variants = {template}
    if "FUZZ" in template:
        word_list = list(words)
        variants = {v.replace("FUZZ", w) for v in variants for w in word_list}
    if "NUM" in template:
        nums = [str(n) for n in range(100)] + [f"{n:02d}" for n in range(10)]
        variants = {v.replace("NUM", n) for v in variants for n in nums}
    return {v.lower() for v in variants if is_valid_host(v.lower())}


# --- Motor de resolucion concurrente ---

def format_hit(name: str, ips: List[str], cnames: List[str]) -> str:
    parts = []
    if cnames:
        chain = " > ".join(cnames)
        parts.append(f"CNAME -> {chain}{cloud_tag(cnames[-1])}")
    if ips:
        parts.append(f"IP -> {', '.join(ips[:2])}")
    elif cnames:
        parts.append(f"{RED}[CNAME sin IP: revisar dangling / takeover]{RESET}")
    return f"  {GREEN}[+]{RESET} {BOLD}{name:<42}{RESET} {' | '.join(parts)}"


def run_active_resolution(candidates: Iterable[str], domain: str, resolvers: List[str],
                          threads: int, label: str) -> Dict[str, Dict[str, List[str]]]:
    """Resuelve candidatos en paralelo, filtra wildcards y muestra hallazgos en vivo."""
    cands = sorted(set(candidates))
    total = len(cands)
    found: Dict[str, Dict[str, List[str]]] = {}
    if not total:
        print(f"{YELLOW}[i] {label}: no hay candidatos que probar.{RESET}")
        return found

    print(f"\n{YELLOW}[*] {label}: probando {total} candidatos con {threads} hilos...{RESET}")
    wild = WildcardDetector(resolvers)
    w_ips, w_cnames = wild.profile(domain)
    if w_ips or w_cnames:
        print(f"{YELLOW}[!] Wildcard DNS detectado en {domain}: se filtraran respuestas "
              f"identicas al wildcard.{RESET}")

    def work(name: str):
        status, ips, cnames = dns_resolve(name, resolvers)
        if status != "ok":
            return None
        return name, ips, cnames, wild.is_wildcard(name, ips, cnames)

    start = time.time()
    done = 0
    filtered = 0
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=threads)
    batch_size = threads * 20
    try:
        for i in range(0, total, batch_size):
            futures = [executor.submit(work, n) for n in cands[i:i + batch_size]]
            for fut in concurrent.futures.as_completed(futures):
                res = fut.result()
                done += 1
                if res:
                    name, ips, cnames, is_wild = res
                    if is_wild:
                        filtered += 1
                    else:
                        found[name] = {"ips": ips, "cnames": cnames}
                        sys.stdout.write("\r" + " " * 78 + "\r")
                        print(format_hit(name, ips, cnames))
                if done % 50 == 0 or done == total:
                    rate = done / max(time.time() - start, 0.001)
                    sys.stdout.write(f"\r  progreso: {done}/{total} ({rate:.0f} q/s) | "
                                     f"hallazgos: {len(found)}   ")
                    sys.stdout.flush()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Interrumpido por el usuario; se conservan los resultados parciales.{RESET}")
    finally:
        try:
            executor.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            executor.shutdown(wait=False)

    elapsed = round(time.time() - start, 1)
    print(f"\n{CYAN}[OK] {label} terminado en {elapsed}s | nuevos: {BOLD}{len(found)}{RESET}"
          f"{CYAN} | filtrados por wildcard: {filtered}{RESET}")
    return found


def _ask_int(prompt: str, default: int, lo: int, hi: int) -> int:
    raw = input(f"{BOLD}{prompt} [{default}]: {RESET}").strip()
    if not raw:
        return default
    try:
        return max(lo, min(hi, int(raw)))
    except ValueError:
        return default


def run_active_enum(domain: str, known: Set[str]) -> Dict[str, Dict[str, List[str]]]:
    """Menu interactivo de enumeracion activa. Devuelve {subdominio: {ips, cnames}}."""
    print(f"\n{MAGENTA}============================================================{RESET}")
    print(f" {BOLD}ENUMERACION ACTIVA: diccionario + permutaciones + fuzzing ({domain}){RESET}")
    print(f" {YELLOW}Envia consultas DNS directas a los resolvers; NO es trafico pasivo.{RESET}")
    print(f"{MAGENTA}============================================================{RESET}")

    print(f"\n{RED}{BOLD}[ AVISO ]{RESET} {RED}Esta seccion es ACTIVA: genera trafico DNS real y masivo "
          f"hacia los resolvers y el dominio objetivo.{RESET}")
    print(f"{RED}          Usala solo sobre dominios propios o con autorizacion expresa. "
          f"El uso es responsabilidad del auditor.{RESET}")

    print(f"\n {BOLD}1.{RESET} Diccionario (bruteforce de subdominios)")
    print(f" {BOLD}2.{RESET} Permutaciones (sobre subdominios conocidos / hallados)")
    print(f" {BOLD}3.{RESET} Fuzzing con plantilla (FUZZ / NUM)")
    print(f" {BOLD}4.{RESET} Todo (1 + 2 + 3)")
    choice = input(f"\n{BOLD}Selecciona tecnica (1-4) [4]: {RESET}").strip() or "4"
    if choice not in ("1", "2", "3", "4"):
        print(f"{RED}[!] Opcion invalida.{RESET}")
        return {}
    do_dict = choice in ("1", "4")
    do_perm = choice in ("2", "4")
    do_fuzz = choice in ("3", "4")

    words = list(dict.fromkeys(BUILTIN_WORDLIST))
    if do_dict or do_fuzz:
        path = input(f"{BOLD}Ruta a diccionario propio (Enter = integrado, {len(words)} palabras): {RESET}").strip()
        if path:
            loaded = load_wordlist(path)
            if loaded:
                words = loaded
                print(f"{GREEN}[+] Diccionario cargado: {len(words)} palabras.{RESET}")
            else:
                print(f"{YELLOW}[i] Se usara el diccionario integrado.{RESET}")

    threads = _ask_int("Hilos concurrentes", 100, 1, 500)
    raw_res = input(f"{BOLD}Resolvers DNS (IPv4, separados por comas; Enter = {', '.join(DEFAULT_RESOLVERS)}): {RESET}").strip()
    resolvers: List[str] = []
    for r in raw_res.split(",") if raw_res else []:
        try:
            ip = ipaddress.ip_address(r.strip())
            if ip.version == 4:
                resolvers.append(str(ip))
        except ValueError:
            pass
    resolvers = resolvers or list(DEFAULT_RESOLVERS)

    results: Dict[str, Dict[str, List[str]]] = {}
    seeds: Set[str] = set(known)

    if do_dict:
        cands = dictionary_candidates(domain, words) - known
        hits = run_active_resolution(cands, domain, resolvers, threads, "Diccionario")
        results.update(hits)
        seeds |= set(hits)

    if do_perm:
        if not seeds:
            print(f"\n{YELLOW}[i] No hay subdominios semilla. Ejecuta antes el escaneo pasivo "
                  f"o la tecnica de diccionario para poder permutar.{RESET}")
        else:
            perms = generate_permutations(seeds, domain) - set(results) - known
            print(f"\n{CYAN}[i] {len(perms)} permutaciones generadas a partir de {len(seeds)} semillas.{RESET}")
            if perms:
                cap = _ask_int("Maximo de permutaciones a probar (las mas cortas primero)",
                               min(len(perms), 100000), 1, len(perms))
                chosen = sorted(perms, key=lambda x: (len(x), x))[:cap]
                hits = run_active_resolution(chosen, domain, resolvers, threads, "Permutaciones")
                results.update(hits)

    if do_fuzz:
        print(f"\n{CYAN}Plantilla: FUZZ = palabra del diccionario, NUM = 0-99 (y 00-09).{RESET}")
        print(f"{CYAN}Ejemplos: api-FUZZ | FUZZ.dev | app-NUM | FUZZ-NUM.internal{RESET}")
        template = input(f"{BOLD}Plantilla (se añade .{domain} si falta; Enter = omitir): {RESET}").strip()
        if template:
            cands = expand_fuzz_template(template, domain, words) - known - set(results)
            if cands:
                hits = run_active_resolution(cands, domain, resolvers, threads, "Fuzzing")
                results.update(hits)
            else:
                print(f"{YELLOW}[!] La plantilla no genero candidatos validos (usa FUZZ y/o NUM).{RESET}")

    print(f"\n{BOLD}{GREEN}[+] Enumeracion activa: {len(results)} subdominios nuevos.{RESET}")
    return results


def filter_by_keywords(subdomains: Set[str], keywords: List[str]) -> List[Tuple[str, str]]:
    """Encuentra subdominios que contienen indicios de logins/paneles y su etiqueta."""
    matches = []
    for sub in sorted(subdomains):
        prefix = sub.split(".")[0]
        full_sub = sub.lower()
        matched_kw = None
        for kw in keywords:
            if kw in prefix:
                matched_kw = kw
                break
        if not matched_kw:
            for kw in keywords:
                if kw in full_sub:
                    matched_kw = kw
                    break
        if matched_kw:
            matches.append((sub, matched_kw))
    return matches


def save_results(domain: str, matches: List[Tuple[str, str]], all_subs: Set[str], dns_info: Dict = None,
                 active_results: Dict = None):
    """Exporta el reporte consolidado a archivo de texto."""
    filename = f"{domain}_subcat_report.txt"
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"============================================================\n")
            f.write(f"   SUBCAT PASSIVE RECON & DEEP DIG REPORT: {domain}\n")
            f.write(f"   Auditor: {get_current_user()} | Fecha: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"============================================================\n\n")

            if dns_info:
                f.write(f"[+] AUDITORIA DNS PROFUNDA (DoH):\n")
                for rtype, records in dns_info.items():
                    if records:
                        f.write(f"  [{rtype}]:\n")
                        for r in records:
                            f.write(f"     -> {r}\n")
                f.write("\n")

            f.write(f"[+] CANDIDATOS A PANELES / LOGINS / INTERFACES ({len(matches)}):\n")
            for sub, tag in matches:
                f.write(f"  - {sub}  (tag: {tag})\n")

            if active_results:
                f.write(f"\n[+] ENUMERACION ACTIVA - SUBDOMINIOS NUEVOS ({len(active_results)}):\n")
                for host, info in sorted(active_results.items()):
                    ip_s = ", ".join(info["ips"]) or "-"
                    cn_s = ", ".join(info["cnames"]) or "-"
                    f.write(f"  - {host}  IP: {ip_s}  CNAME: {cn_s}\n")

            f.write(f"\n[+] TODOS LOS SUBDOMINIOS DESCUBIERTOS ({len(all_subs)}):\n")
            for s in sorted(all_subs):
                f.write(f"  - {s}\n")

        print(f"\n{GREEN}[+] Reporte completo guardado con exito en: {BOLD}{filename}{RESET}")
    except IOError as e:
        print(f"\n{RED}[-] Error al escribir archivo: {e}{RESET}")


def main():
    username = get_current_user()
    keywords = list(DEFAULT_KEYWORDS)

    # Mostrar Banner con saludo dinamico
    print(get_banner(username))
    print(f"  {CYAN}[+] Hello, {BOLD}{MAGENTA}{username}{RESET}{CYAN}! Session initialized. Ready to audit.{RESET}\n")

    # 1. Entrada de dominio
    raw_domain = input(f"{BOLD}Introduce el dominio a analizar (ej: stats.wnba.com o ejemplo.com): {RESET}")
    domain = clean_domain(raw_domain)

    if not domain or "." not in domain:
        print(f"{RED}[!] Dominio no valido. Saliendo.{RESET}")
        sys.exit(1)

    # Deteccion inteligente de dominio raiz
    apex = extract_apex_domain(domain)
    target_domain = domain

    if apex != domain:
        print(f"\n{YELLOW}[i] Se ha introducido un subdominio:{RESET} {BOLD}{domain}{RESET}")
        print(f"    Dominio raiz detectado:         {BOLD}{GREEN}{apex}{RESET}")
        print(f"\n¿Que alcance prefieres analizar?")
        print(f" {BOLD}1.{RESET} {GREEN}Dominio raiz completo '{apex}'{RESET} {YELLOW}(Recomendado: audita toda la organizacion){RESET}")
        print(f" {BOLD}2.{RESET} Estrictamente el subdominio '{domain}'")

        scope_choice = input(f"\n{BOLD}Selecciona opcion (1-2) [Defecto: 1]: {RESET}").strip()
        if scope_choice != "2":
            target_domain = apex

    all_discovered: Set[str] = set()
    candidate_logins: List[Tuple[str, str]] = []
    dns_audit: Dict = {}
    active_results: Dict = {}

    # Menu interactivo por pasos
    while True:
        print(f"\n{CYAN}--- {BOLD}Objetivo fijado: {YELLOW}{target_domain}{RESET}{CYAN} ---{RESET}")
        print(f" {BOLD}1.{RESET} {GREEN}Escaneo Turbo Multi-Fuente{RESET} (Encontrar logins y paneles pasivos)")
        print(f" {BOLD}2.{RESET} {MAGENTA}Dig Profundo DNS{RESET} (Auditoria DNS, SaaS Cloud, SPF/DMARC)")
        print(f" {BOLD}3.{RESET} {BOLD}Escaneo Completo + Dig Profundo{RESET} (Busqueda + Auditoria total)")
        print(f" {BOLD}4.{RESET} Resolver CNAME e IPs de los logins encontrados (Descubrir Okta, AWS, etc.)")
        print(f" {BOLD}5.{RESET} Ver / Añadir palabras clave de filtrado")
        print(f" {BOLD}6.{RESET} {RED}Enumeracion ACTIVA{RESET} (Diccionario + Permutaciones + Fuzzing)")
        print(f" {BOLD}7.{RESET} Salir")

        opcion = input(f"\n{BOLD}Selecciona una opcion (1-7): {RESET}").strip()

        if opcion == "1":
            all_discovered = run_parallel_scan(target_domain)
            candidate_logins = filter_by_keywords(all_discovered, keywords)
            break
        elif opcion == "2":
            dns_audit = run_deep_dig(target_domain)
            cont = input(f"\n{BOLD}¿Deseas buscar tambien subdominios y logins ahora? (s/n): {RESET}").strip().lower()
            if cont in ["s", "si", "y", "yes"]:
                all_discovered = run_parallel_scan(target_domain)
                candidate_logins = filter_by_keywords(all_discovered, keywords)
            break
        elif opcion == "3":
            dns_audit = run_deep_dig(target_domain)
            all_discovered = run_parallel_scan(target_domain)
            candidate_logins = filter_by_keywords(all_discovered, keywords)
            break
        elif opcion == "4":
            if not candidate_logins:
                print(f"\n{YELLOW}[i] Ejecutando primero busqueda pasiva para obtener candidatos...{RESET}")
                all_discovered = run_parallel_scan(target_domain)
                candidate_logins = filter_by_keywords(all_discovered, keywords)
            resolve_candidate_logins(candidate_logins)
            continue
        elif opcion == "5":
            print(f"\n{YELLOW}Palabras clave configuradas ({len(keywords)}):{RESET}")
            print(", ".join(keywords))
            extra = input(f"\nIntroduce nuevas palabras separadas por comas (o Enter para mantener): ").strip()
            if extra:
                for w in extra.split(","):
                    w_clean = w.strip().lower()
                    if w_clean and w_clean not in keywords:
                        keywords.append(w_clean)
                print(f"{GREEN}[+] Palabras clave actualizadas.{RESET}")
        elif opcion == "6":
            if not all_discovered:
                pre = input(f"\n{BOLD}¿Ejecutar antes el escaneo pasivo para obtener semillas de permutacion? (s/n) [s]: {RESET}").strip().lower()
                if pre in ["", "s", "si", "y", "yes"]:
                    all_discovered = run_parallel_scan(target_domain)
            active_results = run_active_enum(target_domain, all_discovered)
            all_discovered = set(all_discovered) | set(active_results)
            candidate_logins = filter_by_keywords(all_discovered, keywords)
            break
        elif opcion == "7":
            print(f"{YELLOW}Operacion finalizada.{RESET}")
            sys.exit(0)
        else:
            print(f"{RED}[!] Opcion invalida. Elige un numero del 1 al 7.{RESET}")

    # Mostrar resultados de logins
    if all_discovered:
        print("=" * 64)
        print(f" {BOLD}{MAGENTA}SUBDOMINIOS CANDIDATOS A PANELES / LOGINS ({len(candidate_logins)}){RESET}")
        print("=" * 64)

        if candidate_logins:
            for sub, tag in candidate_logins:
                print(f"  {RED}[!] {BOLD}{sub:<40}{RESET} {CYAN}[tag: {tag}]{RESET}")
        else:
            print(f"  {YELLOW}(No se encontraron coincidencias con las palabras clave de acceso){RESET}")

        if candidate_logins:
            check_cname = input(f"\n{BOLD}¿Deseas resolver CNAME/IP de estos {len(candidate_logins)} accesos para ver que nubes usan? (s/n): {RESET}").strip().lower()
            if check_cname in ["s", "si", "y", "yes"]:
                resolve_candidate_logins(candidate_logins)

    # Ofrecer exportacion
    print("\n" + "-" * 64)
    guardar = input(f"{BOLD}¿Deseas exportar el reporte consolidado a un archivo? (s/n): {RESET}").strip().lower()
    if guardar in ["s", "si", "y", "yes"]:
        save_results(target_domain, candidate_logins, all_discovered, dns_audit, active_results)


if __name__ == "__main__":
    main()
