# SubCat Hunter - Attack Surface & Hidden Login Hunter

```text
       /\_/\  
      ( o.o )   S U B C A T   H U N T E R :: Passive Login Hunter & Deep Dig v3.0
       > ^ <    [ Multi-Engine OSINT | Deep Dig | Passive + Active Enum ]
      (_|_|_)   
```

An interactive reconnaissance tool to discover hidden administrative interfaces, single sign-on (SSO) portals, staging environments, and corporate logins. Its core workflow is **passive** (no packets sent to the target). It also includes clearly labeled **active** modules (dictionary, permutation and fuzzing enumeration, wildcard DNS analysis, and TCP port scanning) for use when you are authorized to query the target directly.

Everything runs from a numbered CLI menu, with no flags to remember. The prompts are in Spanish.

---

## Attribution & Relationship to Subcat

> **Important Note**: **[Subcat](https://github.com/duty1g/subcat)** is an independent, standalone open-source project created by its respective authors.
>
> This project is **not** the original Subcat repository. SubCat Hunter has its own passive engines and can additionally call the external `subcat` binary (if it is in your `PATH`) as one more source of subdomains in the full pipeline. It adds:
> - A guided, numbered CLI menu.
> - Apex/root scope detection.
> - Passive DNS-over-HTTPS (DoH) infrastructure auditing (Deep Dig).
> - Keyword classification and cloud-provider mapping for candidate login interfaces.
> - Active enumeration, wildcard analysis, port scanning and consolidated reporting.

All credit for the original Subcat tool belongs to its developers.

---

## Passive vs. Active

| Options | Mode | Traffic |
|---|---|---|
| `1`, `2`, `3`, `4`, `5` | Passive | Queries to public third-party services and Cloudflare DoH. Nothing is sent to the target's own servers or nameservers. |
| `9` (mode 1) | Passive | Certificate transparency logs and DoH probing. |
| `6`, `8`, `9` (modes 2 and 3), `10` | **Active** | Direct DNS queries and/or TCP connections against the target and its resolvers. |

### What "passive" means here

1. No HTTP/HTTPS connections to the target domain or its IPs.
2. No DNS queries to the target's authoritative nameservers.
3. Intelligence comes from public Certificate Transparency logs, passive DNS databases and web scan archives.
4. DNS lookups go through Cloudflare's public DoH resolver.

The domain name you analyze is still sent to those third parties (RapidDNS, CertSpotter, HackerTarget, URLScan, crt.sh, AlienVault OTX and Cloudflare). Passive mode is suited to Attack Surface Management (ASM), shadow IT auditing and external risk assessments.

> **Warning**: Options `6`, `8`, `9` (active modes) and `10` generate real, direct and potentially massive traffic. Use them only on domains you own or are explicitly authorized to test.

---

## Features

### Passive
- **Parallel multi-engine search** (`ThreadPoolExecutor`):
  - **RapidDNS**, **CertSpotter (SSLMate)**, **HackerTarget**, **URLScan.io**, **crt.sh**, **AlienVault OTX**.
  - Each engine fails silently on timeouts or rate limits, so one outage does not stop the scan.
- **Deep Dig DNS audit** via DoH:
  - Queries `NS`, `MX`, `A`, `AAAA`, `CNAME`, `TXT`, `SOA`, `CAA` and `_dmarc` records.
  - Flags SPF records and TXT tokens for Google Workspace, Microsoft 365, Okta, Atlassian, DocuSign and Zoom.
  - Warns when no public DMARC record exists.
- **Keyword classification**: flags subdomains matching login and admin tags (`admin`, `sso`, `login`, `vpn`, `portal`, `identity`, `jenkins`, `grafana`, `dev`, `stage`, `qa`, ...). You can add your own keywords (option `5`). The root domain is excluded from matching, so a domain like `digital.com` does not match `git` on every host.
- **Apex domain detection**: if you enter `stats.example.com`, the tool detects `example.com` (including multi-part TLDs such as `co.uk` or `com.mx`) and lets you scan the whole organization or only that host.
- **Cloud provider resolution**: resolves CNAME and A records of flagged portals and tags Okta, AWS CloudFront, Azure, Cloudflare and Akamai.

### Active
- **Active enumeration (option `6`)**:
  - **Dictionary**: brute-forces subdomains with the built-in wordlist (several hundred entries) or your own file.
  - **Permutations**: altdns-style mutation of known subdomains (label insertion, prefix/suffix with and without hyphen, numeric variations, environment-token swaps such as `dev` <-> `prod`). You can cap how many to test; the shortest are tried first.
  - **Fuzzing**: templates with `FUZZ` (wordlist words) and `NUM` (0-99 and 00-09), e.g. `api-FUZZ`, `FUZZ.dev`, `app-NUM`.
  - **Resolution engine**: uses the external [`dnsx`](https://github.com/projectdiscovery/dnsx) binary when available. If `dnsx` is missing, fails, or returns no output, the tool falls back to its own pure-Python UDP DNS resolver.
  - **Wildcard filtering**: each zone is profiled with random-name lookups, and hits identical to the wildcard response are discarded.
  - **Takeover hints**: a CNAME with no IP is flagged as a possible dangling record (GitHub Pages, Heroku, Netlify, Vercel, Fastly, Zendesk, Shopify, Azure App Service, AWS, etc.).
- **Wildcard DNS enumeration (option `9`)**:
  - Finds `*.zone` certificates in crt.sh and CertSpotter, and probes the apex, those zones and the parent zones of known subdomains.
  - Modes: passive (DoH), active (direct DNS) or both. Active modes also brute-force inside each wildcard zone, filtering wildcard responses.
- **TCP port scanning (option `10`)**:
  - Targets: the domain only, the domain plus all discovered subdomains, or a manual host list.
  - Ports: `top` (43 common ports), `full` (1-65535) or a custom list/range such as `22,80,8000-8100`.
  - Engine: `nmap` if installed (SYN scan as root, connect scan otherwise, optional `-sV` service detection), or a built-in threaded TCP connect scanner.
  - Hosts are grouped by IP so the same machine is never scanned twice.
- **Full pipeline (option `8`)**: runs the external `subcat` binary (if present), the passive scan, Deep Dig, and dictionary, permutation and fuzzing enumeration non-interactively, then saves the report automatically. You must type the target domain to confirm authorization before it starts.

### General
- **Consolidated report**: exports `<domain>_subcat_report.txt` with execution stats, subdomains, login candidates, DNS records, active findings, wildcard info and open ports.
- **Dynamic session awareness**: greetings and report authorship use the active system user.
- **Graceful interruption**: `Ctrl+C` during an active run keeps the partial results.

---

## Prerequisites

- **Python 3.8+**
- No external Python dependencies (standard library only).
- **Optional external tools**:
  - [`dnsx`](https://github.com/projectdiscovery/dnsx) for faster active resolution (options `6`, `8`, `9`):
    ```bash
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
    ```
  - [`subcat`](https://github.com/duty1g/subcat) as an extra source in the full pipeline (option `8`):
    ```bash
    go install github.com/duty1g/subcat/cmd/subcat@latest
    ```
  - [`nmap`](https://nmap.org/download) for port scanning with service detection (option `10`).

Without any of them the tool still works: it uses its own DNS resolver and socket scanner and skips `subcat`.

---

## Installation

```bash
git clone https://github.com/your-username/subcat-hunter
cd subcat-hunter
chmod +x subcat-hunter.py
```

---

## Usage

```bash
python3 subcat-hunter.py
```

Run the built-in self-tests (port parsing, local TCP scan, nmap parsing, keyword filter):

```bash
python3 subcat-hunter.py --selftest
```

### Workflow

1. **Enter target**: e.g. `example.com` or `dev.example.com`.
2. **Scope selection**: if you entered a subdomain, choose the whole organization (recommended) or just that host.
3. **Menu option**:

| Option | Description | Mode |
|---|---|---|
| `1` | Turbo multi-engine scan: passive subdomains and candidate logins | Passive |
| `2` | Deep Dig DNS: infrastructure, SaaS tokens, SPF/DMARC (offers a follow-up subdomain scan) | Passive |
| `3` | Full scan + Deep Dig | Passive |
| `4` | Resolve CNAME/IP of the login candidates (maps them to cloud providers) | Passive |
| `5` | View / add filter keywords | - |
| `6` | Active enumeration: dictionary + permutations + fuzzing | **Active** |
| `7` | Exit (goes through report export if there are unsaved results) | - |
| `8` | **Full pipeline**: subcat + passive + Dig + active + automatic report | **Active** |
| `9` | Wildcard DNS enumeration: certificates, probing and filtered brute force | Passive / **Active** |
| `10` | TCP port scan: top / full / custom, domain and subdomains | **Active** |

4. **Results and report**: candidate logins are listed, with an optional CNAME/IP resolution. You are then asked whether to export the report. Option `8` saves it automatically.

Options `4`, `5` and `9` return to the menu. Options `1`, `2`, `3`, `6` and `10` run once and then move on to the results and export step.

---

## Example Output

```text
       /\_/\  
      ( o.o )   S U B C A T :: Passive Login Hunter & Deep Dig v3.0
       > ^ <    >> Hello, auditor! Passive reconnaissance & deep audit <<
      (_|_|_)   [ Multi-Engine OSINT | Deep Dig | Passive + Active Enum ]

  [+] Hello, auditor! Session initialized. Ready to audit.

Introduce el dominio a analizar: example.com

--- Objetivo fijado: example.com ---
 1. Escaneo Turbo Multi-Fuente (Encontrar logins y paneles pasivos)
 2. Dig Profundo DNS (Auditoria DNS, SaaS Cloud, SPF/DMARC)
 3. Escaneo Completo + Dig Profundo (Busqueda + Auditoria total)
 4. Resolver CNAME e IPs de los logins encontrados (Descubrir Okta, AWS, etc.)
 5. Ver / Añadir palabras clave de filtrado
 6. Enumeracion ACTIVA (Diccionario + Permutaciones + Fuzzing)
 7. Salir
 8. PIPELINE COMPLETO (subcat + pasivo + Dig + activa + informe automatico)
 9. Enumeracion WILDCARD (pasiva o activa: certificados *., sondeo y bruteforce filtrado)
 10. Escaneo de PUERTOS (top / completo / especifico, dominio y subdominios)

Selecciona una opcion (1-10): 1

[*] Iniciando consultas pasivas en paralelo (Zero-Traffic)...
  [+] URLScan      :  13 subdominios
  [+] HackerTarget :  50 subdominios
  [+] CertSpotter  :  34 subdominios
  [+] RapidDNS     :  85 subdominios
  [+] crt.sh       :  99 subdominios
[OK] Escaneo completado en 6.42s | Total unicos: 147

================================================================
 SUBDOMINIOS CANDIDATOS A PANELES / LOGINS (8)
================================================================
  [!] login.example.com                    [tag: login]
  [!] identity.example.com                 [tag: identity]
  [!] vpn-gateway.example.com              [tag: vpn]
  [!] admin-portal.example.com             [tag: admin]
  [!] auth-sso.example.com                 [tag: sso]
  [!] dev.stats.example.com                [tag: dev]
  [!] securemail.example.com               [tag: secure]
  [!] staging.example.com                  [tag: staging]
```

---

## Report Contents

The exported `<domain>_subcat_report.txt` can include:

- Execution summary per technique (engine, candidates, hits, wildcard-filtered, time)
- Subdomains found by the external `subcat` tool
- Deep DNS audit records
- Login/panel/interface candidates with their matched tag
- Active enumeration results grouped by technique (Dictionary, Permutations, Fuzzing, Wildcard), with IPs and CNAMEs
- Wildcard DNS findings (certificate zones and active wildcards)
- Open ports and detected services per IP
- Full list of discovered subdomains

---

## Defensive Applications

- **Shadow IT discovery**: finds forgotten staging or pre-production hosts (`stage-admin`, `dev-login`) exposed to the internet.
- **Credential surface management**: maps public authentication gateways (Okta, Azure AD, custom login forms).
- **Subdomain takeover detection**: spots dangling CNAMEs pointing to third-party services.
- **Certificate hygiene**: reviews wildcard and per-host certificates in public CT logs.
- **DNS & mail security verification**: checks SPF, DMARC policy and third-party SaaS verification footprints.
- **Exposure checks**: identifies unexpectedly open services on discovered hosts.

---

## Disclaimer

This software is intended for authorized security auditing, defensive asset management, and educational purposes. The passive options only use publicly available data sources. The active options (`6`, `8`, `9` in active modes, and `10`) interact directly with the target's infrastructure and with DNS resolvers, and may be illegal or violate policies if used without written authorization. You are solely responsible for how you use this tool.

---

## License

MIT License. See `LICENSE` for details.
