#!/usr/bin/env python3
"""
SubCat - Passive Login Hunter & Deep Dig v2.5
Reconocimiento pasivo multi-fuente en paralelo y auditoria DNS profunda (Zero-Traffic).
Fuentes: RapidDNS, CertSpotter, HackerTarget, URLScan, crt.sh, AlienVault OTX + Deep DoH/Dig.
"""

import concurrent.futures
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from typing import Dict, List, Set, Tuple

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
      ( {MAGENTA}o.o{CYAN} )   {BOLD}{MAGENTA}S U B C A T{RESET}{CYAN} :: {YELLOW}Passive Login Hunter & Deep Dig v2.5{RESET}
      {CYAN} > {MAGENTA}^{CYAN} <    {GREEN}>> Hello, {BOLD}{MAGENTA}{username}{RESET}{GREEN}! Passive reconnaissance & deep audit <<{RESET}
      {CYAN}(_|_|_)   {BOLD}[ Multi-Engine OSINT | Deep Dig | Zero-Traffic Target ]{RESET}
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


def save_results(domain: str, matches: List[Tuple[str, str]], all_subs: Set[str], dns_info: Dict = None):
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

    # Menu interactivo por pasos
    while True:
        print(f"\n{CYAN}--- {BOLD}Objetivo fijado: {YELLOW}{target_domain}{RESET}{CYAN} ---{RESET}")
        print(f" {BOLD}1.{RESET} {GREEN}Escaneo Turbo Multi-Fuente{RESET} (Encontrar logins y paneles pasivos)")
        print(f" {BOLD}2.{RESET} {MAGENTA}Dig Profundo DNS{RESET} (Auditoria DNS, SaaS Cloud, SPF/DMARC)")
        print(f" {BOLD}3.{RESET} {BOLD}Escaneo Completo + Dig Profundo{RESET} (Busqueda + Auditoria total)")
        print(f" {BOLD}4.{RESET} Resolver CNAME e IPs de los logins encontrados (Descubrir Okta, AWS, etc.)")
        print(f" {BOLD}5.{RESET} Ver / Añadir palabras clave de filtrado")
        print(f" {BOLD}6.{RESET} Salir")

        opcion = input(f"\n{BOLD}Selecciona una opcion (1-6): {RESET}").strip()

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
            print(f"{YELLOW}Operacion finalizada.{RESET}")
            sys.exit(0)
        else:
            print(f"{RED}[!] Opcion invalida. Elige un numero del 1 al 6.{RESET}")

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
        save_results(target_domain, candidate_logins, all_discovered, dns_audit)


if __name__ == "__main__":
    main()
