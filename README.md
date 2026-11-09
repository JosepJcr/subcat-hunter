# SubCat Hunter - Passive Attack Surface & Hidden Login Hunter

```text
       /\_/\  
      ( o.o )   S U B C A T   H U N T E R :: Passive Login Hunter & Deep Dig v3.0
       > ^ <    [ Multi-Engine OSINT | Deep Dig | Passive + Active Enum (dnsx) ]
      (_|_|_)   
```

An automated, interactive wrapper and reconnaissance interface designed to discover hidden administrative interfaces, single sign-on (SSO) portals, staging environments, and corporate logins. Its core workflow is passive (zero packets to the target), with an optional, clearly-labeled **active enumeration** mode for dictionary, permutation, and fuzzing-based discovery when you have authorization to query the target directly.

---

## Attribution & Relationship to Subcat

> **Important Note**: **[Subcat](https://github.com/skat/subcat)** is an independent, standalone open-source project created by its respective authors. 
>
> This project is **not** the original Subcat repository. This tool serves as an **automated interactive wrapper and workflow manager** that utilizes Subcat and compatible passive discovery methodologies as its underlying engine. It adds:
> - A guided, step-by-step numbered CLI menu (no manual flags required).
> - Interactive domain and apex/root scope detection.
> - Passive DNS-over-HTTPS (DoH) infrastructure auditing (Deep Dig).
> - Automated keyword classification and cloud-provider mapping for candidate login interfaces.

All credit for the original Subcat tool and its passive data collection concepts belongs to the original Subcat developers.

---

## Zero-Traffic Philosophy (Passive Mode)

By default, options 1-5 of SubCat Hunter operate on a strict **zero-contact model**:

1. **No direct HTTP/HTTPS connections** to the target domain or its IP infrastructure.
2. **No direct DNS queries** to the target's authoritative nameservers.
3. **Public data only**: All intelligence is gathered by querying public Certificate Transparency (CT) logs, historical web search caches, and public passive DNS databases.
4. **Cloudflare DNS-over-HTTPS (DoH)**: All DNS and deep infrastructure queries are routed securely through Cloudflare's public resolver (`1.1.1.1`), ensuring zero interaction with the target's network.

This makes passive mode safe for Attack Surface Management (ASM), shadow IT auditing, external risk assessments, and defensive perimeter evaluations.

> **Note**: Option `6` (Active Enumeration) is the one exception to this model — see below. It is opt-in, clearly labeled, and requires explicit confirmation of scope before it runs.

---

## Features

- **Automated Workflow & Wrapper**: Replaces manual flag entry with an interactive numbered interface (1, 2, 3...).
- **Parallel Multi-Engine Search**: Concurrently queries public intelligence sources using Python's `ThreadPoolExecutor`:
  - **RapidDNS**: Comprehensive passive DNS dataset.
  - **CertSpotter (SSLMate)**: Real-time Certificate Transparency logs.
  - **HackerTarget**: Historical DNS host search.
  - **URLScan.io**: Public internet scan database.
  - **crt.sh**: Sectigo Certificate Transparency archive with built-in timeout handling.
  - **AlienVault OTX**: Passive DNS indicator records with rate-limit tolerance.
- **Deep Dig DNS Audit**:
  - Automatically queries `NS`, `MX`, `A`, `AAAA`, `CNAME`, `TXT`, `SOA`, `CAA`, and `_dmarc` records via encrypted DoH.
  - Parses `TXT` verification tokens to detect third-party SaaS platforms (Google Workspace, Microsoft 365, Okta, Atlassian, Zoom, DocuSign, Proofpoint, Zendesk).
- **Targeted Keyword Classification**:
  - Flags subdomains matching login and administrative tags (`admin`, `sso`, `login`, `vpn`, `portal`, `identity`, `dev`, `stage`, `qa`, etc.).
  - Displays the specific matched tag alongside the domain.
- **Apex Domain Intelligence**:
  - If a user inputs a subdomain (e.g., `stats.example.com`), the tool detects the apex domain (`example.com`) and offers to scan the entire organization or limit scope to the specific host.
- **Cloud Provider Resolution**:
  - Resolves CNAME and A records of flagged login portals to identify underlying cloud providers (Okta, AWS CloudFront, Akamai Edge, Azure Traffic Manager, Cloudflare).
- **Active Enumeration (opt-in, option `6`)**:
  - **Dictionary**: brute-forces subdomains against a large built-in wordlist (500+ entries) or your own custom wordlist file.
  - **Permutations**: altdns-style mutation of already-discovered subdomains (label insertion, prefix/suffix, numeric variations, environment-token swaps like `dev` ↔ `prod`).
  - **Fuzzing**: template-based expansion using `FUZZ` (dictionary words) and `NUM` (0-99) placeholders, e.g. `api-FUZZ`, `app-NUM`.
  - **Resolution engine**: queries are resolved via the external [`dnsx`](https://github.com/projectdiscovery/dnsx) tool (ProjectDiscovery) when available, with its native wildcard filter (`-wd`) applied automatically. If `dnsx` is not installed, the tool transparently falls back to its own pure-Python DNS resolver.
  - **Wildcard detection**: profiles each zone with randomized lookups to filter out wildcard DNS false positives before reporting a hit.
  - Requires an explicit on-screen acknowledgment that this mode sends real, direct DNS traffic to the target before it runs.
- **Dynamic Session Awareness**:
  - Adapts greetings and report authorship to the active system user.

---

## Prerequisites

- **Python 3.8+**
- No external Python dependencies required for passive mode (pure standard library).
- **Optional** — for Active Enumeration (option `6`): [`dnsx`](https://github.com/projectdiscovery/dnsx) in your `PATH`.
  ```bash
  go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
  ```
  Without it, option `6` still works, using the built-in fallback resolver instead.

---

## Installation

Clone the repository and set execution permissions:

```bash
git clone https://github.com/your-username/subcat-hunter
cd subcat-hunter
chmod +x subcat-hunter.py
```

---

## Usage

Run the script interactively:

```bash
python3 subcat-hunter.py
```

### Workflow

1. **Enter Target**: Input the domain when prompted (e.g., `example.com` or `dev.example.com`).
2. **Scope Selection**: If a subdomain is entered, choose whether to scan the whole organization or just the subdomain.
3. **Menu Option**:
   - `1`: Turbo Multi-Engine Scan (Find passive subdomains and candidate logins).
   - `2`: Deep Dig DNS (Audit infrastructure, SaaS tokens, and DMARC).
   - `3`: Full Scan + Deep Dig (Execute both concurrently).
   - `4`: Resolve CNAME/IP (Map candidate logins to cloud providers).
   - `5`: View / Add custom keywords.
   - `6`: **Active Enumeration** (dictionary + permutations + fuzzing, resolved via `dnsx`). Sends real DNS traffic — use only on domains you own or are authorized to test.
   - `7`: Exit.
4. **Report Export**: Choose whether to save the consolidated report to `<domain>_subcat_report.txt`.

---

## Example Output

```text
       /\_/\  
      ( o.o )   S U B C A T :: Passive Login Hunter & Deep Dig v3.0
       > ^ <    >> Hello, auditor! Passive reconnaissance & deep audit <<
      (_|_|_)   [ Multi-Engine OSINT | Deep Dig | Passive + Active Enum (dnsx) ]

  [+] Hello, auditor! Session initialized. Ready to audit.

Introduce el dominio a analizar: example.com

--- Objetivo fijado: example.com ---
 1. Escaneo Turbo Multi-Fuente (Encontrar logins y paneles pasivos)
 2. Dig Profundo DNS (Auditoria DNS, SaaS Cloud, SPF/DMARC)
 3. Escaneo Completo + Dig Profundo (Busqueda + Auditoria total)
 4. Resolver CNAME e IPs de los logins encontrados (Descubrir Okta, AWS, etc.)
 5. Ver / Anadir palabras clave de filtrado
 6. Enumeracion ACTIVA (Diccionario + Permutaciones + Fuzzing)
 7. Salir

Selecciona una opcion (1-7): 1

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

## Defensive Applications

- **Shadow IT Discovery**: Identifies abandoned staging or pre-production hosts (`stage-admin`, `dev-login`) exposed to the public internet.
- **Credential Surface Management**: Maps public-facing authentication gateways (Okta, Azure AD, custom login forms) before adversaries do.
- **Certificate Hygiene**: Audits valid and expired certificates across all public log monitors.
- **DNS & Mail Security Verification**: Validates SPF include limits, DMARC enforcement policies (`p=reject` vs `p=none`), and third-party SaaS verification footprints.

---

## Disclaimer

This software is intended for authorized security auditing, defensive asset management, and educational purposes. It gathers publicly available data without interacting directly with the target infrastructure. Always ensure compliance with applicable laws and corporate security policies.

---

## License

MIT License. See `LICENSE` for details.
