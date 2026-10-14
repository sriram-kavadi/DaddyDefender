"""
URL Threat Analyzer for Threat Check.

Performs passive, heuristic-based analysis of URLs to identify phishing,
brand impersonation, and other suspicious indicators. Never visits or
follows the submitted URL.

Ported from the client-side analyzer.js with enhancements for server-side
use including PSL-aware domain parsing via tldextract.
"""
import re
from urllib.parse import urlparse, unquote
from typing import Optional

try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False

from backend.models import Finding, FindingSeverity, FindingSource


# ──────────────────────────────────────────────────────────────────────
# Reference data
# ──────────────────────────────────────────────────────────────────────

BRANDS = [
    {"name": "paypal", "display": "PayPal", "terms": ["paypal"], "domains": ["paypal.com", "paypal.me"]},
    {"name": "amazon", "display": "Amazon", "terms": ["amazon"], "domains": ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.ca", "amazon.com.au", "amazonaws.com", "amazon.jobs"]},
    {"name": "google", "display": "Google", "terms": ["google"], "domains": ["google.com", "google.co.in", "google.co.uk", "googleapis.com", "gstatic.com", "googleusercontent.com", "youtube.com", "goo.gl"]},
    {"name": "microsoft", "display": "Microsoft", "terms": ["microsoft"], "domains": ["microsoft.com", "live.com", "outlook.com", "office.com", "office365.com", "microsoftonline.com", "windows.com", "azure.com", "sharepoint.com", "bing.com", "skype.com"]},
    {"name": "apple", "display": "Apple", "terms": ["apple", "icloud"], "domains": ["apple.com", "icloud.com"]},
    {"name": "netflix", "display": "Netflix", "terms": ["netflix"], "domains": ["netflix.com"]},
    {"name": "facebook", "display": "Facebook", "terms": ["facebook"], "domains": ["facebook.com", "fb.com", "messenger.com"]},
    {"name": "instagram", "display": "Instagram", "terms": ["instagram"], "domains": ["instagram.com"]},
    {"name": "whatsapp", "display": "WhatsApp", "terms": ["whatsapp"], "domains": ["whatsapp.com", "whatsapp.net"]},
    {"name": "linkedin", "display": "LinkedIn", "terms": ["linkedin"], "domains": ["linkedin.com", "lnkd.in"]},
    {"name": "dropbox", "display": "Dropbox", "terms": ["dropbox"], "domains": ["dropbox.com"]},
    {"name": "docusign", "display": "DocuSign", "terms": ["docusign"], "domains": ["docusign.com", "docusign.net"]},
    {"name": "adobe", "display": "Adobe", "terms": ["adobe"], "domains": ["adobe.com"]},
    {"name": "chase", "display": "Chase", "terms": ["chase bank", "chase"], "domains": ["chase.com"]},
    {"name": "wellsfargo", "display": "Wells Fargo", "terms": ["wells fargo", "wellsfargo"], "domains": ["wellsfargo.com"]},
    {"name": "bankofamerica", "display": "Bank of America", "terms": ["bank of america", "bankofamerica"], "domains": ["bankofamerica.com"]},
    {"name": "citibank", "display": "Citibank", "terms": ["citibank"], "domains": ["citibank.com", "citi.com"]},
    {"name": "hdfcbank", "display": "HDFC Bank", "terms": ["hdfc bank", "hdfcbank"], "domains": ["hdfcbank.com"]},
    {"name": "icicibank", "display": "ICICI Bank", "terms": ["icici bank", "icicibank"], "domains": ["icicibank.com"]},
    {"name": "paytm", "display": "Paytm", "terms": ["paytm"], "domains": ["paytm.com"]},
    {"name": "phonepe", "display": "PhonePe", "terms": ["phonepe"], "domains": ["phonepe.com"]},
    {"name": "flipkart", "display": "Flipkart", "terms": ["flipkart"], "domains": ["flipkart.com"]},
    {"name": "fedex", "display": "FedEx", "terms": ["fedex"], "domains": ["fedex.com"]},
    {"name": "dhl", "display": "DHL", "terms": ["dhl"], "domains": ["dhl.com"]},
    {"name": "usps", "display": "USPS", "terms": ["usps"], "domains": ["usps.com"]},
    {"name": "coinbase", "display": "Coinbase", "terms": ["coinbase"], "domains": ["coinbase.com"]},
    {"name": "binance", "display": "Binance", "terms": ["binance"], "domains": ["binance.com"]},
    {"name": "spotify", "display": "Spotify", "terms": ["spotify"], "domains": ["spotify.com"]},
]

OFFICIAL_DOMAINS: dict[str, str] = {}
for brand in BRANDS:
    for domain in brand["domains"]:
        OFFICIAL_DOMAINS[domain] = brand["name"]

SHORTENERS = frozenset([
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc",
    "rb.gy", "bit.do", "lnkd.in", "s.id", "t.ly",
])

RISKY_TLDS = frozenset([
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "zip", "mov",
    "work", "support", "country", "loan", "rest", "icu", "cyou", "buzz",
    "monster", "sbs", "cfd",
])

MULTI_PART_TLDS = frozenset([
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.in", "net.in", "org.in", "ac.in", "gov.in", "co.jp", "co.nz",
    "com.br", "com.cn", "com.mx", "co.za", "com.sg", "com.hk", "com.tr",
    "com.pk", "com.bd", "com.ng",
])

URL_KEYWORDS = frozenset([
    "login", "log-in", "signin", "sign-in", "verify", "verification",
    "secure", "account", "update", "confirm", "password", "wallet",
    "billing", "banking", "suspend", "unlock", "recover", "invoice",
    "payment", "support",
])

BRAND_KEYWORDS = frozenset([
    "secure", "login", "verify", "support", "account", "update", "help",
    "service", "services", "pay", "billing", "wallet", "id", "online",
    "alert", "security", "care", "team", "customer",
])

EXECUTABLE_EXT = re.compile(
    r"\.(exe|apk|scr|msi|bat|cmd|js|jar|vbs|iso|dmg|zip|rar|ps1)$", re.IGNORECASE
)

DANGEROUS_SCHEMES = re.compile(r"^(javascript|data|vbscript):", re.IGNORECASE)
SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.IGNORECASE)
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
ENCODED_CHARS_RE = re.compile(r"%[0-9a-f]{2}", re.IGNORECASE)


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────

def levenshtein(a: str, b: str) -> int:
    """Compute the Levenshtein edit distance between two strings."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i]
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost))
        prev = cur
    return prev[len(b)]


def registrable_domain(host: str) -> str:
    """
    Extract the registrable domain from a hostname.
    Uses tldextract if available for PSL-aware parsing, falls back to
    the multi-part TLD list from the original analyzer.
    """
    if HAS_TLDEXTRACT:
        try:
            ext = tldextract.extract(host)
            if ext.registered_domain:
                return ext.registered_domain
            return host
        except Exception:
            pass

    labels = host.split(".")
    if len(labels) <= 2:
        return host
    last_two = ".".join(labels[-2:])
    if last_two in MULTI_PART_TLDS:
        return ".".join(labels[-3:])
    return last_two


def lookalike_variants(label: str) -> list[str]:
    """
    Generate candidate 'what the attacker meant' strings for a domain label
    by applying common character substitution patterns.
    """
    out: list[str] = []

    def push(s: str):
        if s not in out:
            out.append(s)

    def digits(s: str, one_char: str) -> str:
        return (
            s.replace("0", "o")
            .replace("3", "e")
            .replace("4", "a")
            .replace("5", "s")
            .replace("1", one_char)
        )

    for s in [label, digits(label, "l"), digits(label, "i")]:
        push(s)
        push(s.replace("rn", "m").replace("vv", "w"))

    return out


def safe_unquote(s: str) -> str:
    """URL-decode a string, returning the original on failure."""
    try:
        return unquote(s)
    except Exception:
        return s


def severity_for_points(points: int) -> FindingSeverity:
    """Map a finding's point value to a severity level."""
    if points >= 30:
        return FindingSeverity.HIGH
    if points >= 15:
        return FindingSeverity.MODERATE
    if points >= 8:
        return FindingSeverity.LOW
    return FindingSeverity.INFO


def make_finding(
    indicator: str,
    points: int,
    title: str,
    detail: str,
    tip: Optional[str] = None,
) -> Finding:
    """Create a structured Finding from the analysis parameters."""
    return Finding(
        indicator=indicator,
        severity=severity_for_points(points),
        evidence=title,
        explanation=detail,
        points=points,
        source=FindingSource.HEURISTIC,
        tip=tip,
    )


# ──────────────────────────────────────────────────────────────────────
# Brand checks
# ──────────────────────────────────────────────────────────────────────

def brand_checks(host: str, registrable: str) -> Optional[Finding]:
    """
    Check whether the domain impersonates a known brand using:
    - Exact name on unrecognized domain
    - Character swap lookalikes (e.g., paypa1)
    - Typosquatting (e.g., amazom)
    - Brand + keyword combos (e.g., paypal-secure)
    - Brand in subdomain with different registrable domain
    """
    labels = host.split(".")
    reg_labels = registrable.split(".")
    sub_labels = labels[: len(labels) - len(reg_labels)]
    label = reg_labels[0]
    variants = lookalike_variants(label)
    best: Optional[Finding] = None

    def consider(points: int, title: str, detail: str, tip: Optional[str]):
        nonlocal best
        if best is None or points > best.points:
            best = make_finding("brand", points, title, detail, tip)

    for brand in BRANDS:
        b = brand["name"]
        shown = brand["display"]

        # Exact brand name on unrecognized domain
        if label == b:
            consider(
                25,
                f"Uses the {shown} name on a domain that is not recognized as official",
                f'The domain "{registrable}" contains the name {shown}, but it is not one of the domains we know {shown} uses.',
                f"Go to {shown} by typing its official address yourself instead of following the link.",
            )
            continue

        # Character swap lookalikes (e.g., paypa1 → paypal)
        swapped = any(v != label and v == b for v in variants)
        if swapped:
            consider(
                40,
                f"Imitates {shown} with swapped characters",
                f'The domain "{registrable}" looks like "{b}" with look-alike characters substituted.',
                "Check the address letter by letter. Scammers swap characters such as 1 for l or rn for m.",
            )
            continue

        # Typosquatting (small edit distance)
        max_dist = 2 if len(b) >= 9 else (1 if len(b) >= 6 else 0)
        if max_dist > 0 and abs(len(label) - len(b)) <= max_dist and levenshtein(label, b) <= max_dist:
            consider(
                35,
                f"Looks like a misspelling of {shown}",
                f'The domain name "{label}" is only a character or two away from "{b}".',
                "Check the address letter by letter before trusting it.",
            )
            continue

        # Brand + keyword combo (e.g., paypal-secure)
        if len(b) >= 5:
            embedded = any(
                b in v.split("-")
                or any(v == b + k or v == k + b for k in BRAND_KEYWORDS)
                for v in variants
            )
            if embedded:
                consider(
                    30,
                    f"Combines the {shown} name with extra words",
                    f'The domain "{registrable}" builds on the name {shown} but is not a domain {shown} uses.',
                    'Real companies rarely put words like "secure" or "login" into a separate domain. Go to the official site directly.',
                )
                continue

        # Brand in subdomain
        in_sub = any(
            l == b or (len(b) >= 5 and b in l) for l in sub_labels
        )
        if in_sub:
            consider(
                35,
                f"Puts the {shown} name in front of a different domain",
                f"The address starts with {shown} but the real domain is \"{registrable}\". Only the last part of the host decides where the link goes.",
                "Read the host from right to left. The part just before the domain ending is the real owner.",
            )

    return best


# ──────────────────────────────────────────────────────────────────────
# URL analysis
# ──────────────────────────────────────────────────────────────────────

def parse_url(raw: str) -> Optional[dict]:
    """
    Parse a raw URL string, adding a scheme if missing.
    Returns dict with 'parsed' (ParseResult), 'assumed_scheme', and 'source'.
    Returns None if parsing fails.
    """
    s = raw.strip()
    has_scheme = bool(SCHEME_RE.match(s))
    is_dangerous = bool(DANGEROUS_SCHEMES.match(s))
    with_scheme = s if (has_scheme or is_dangerous) else f"https://{s}"

    try:
        parsed = urlparse(with_scheme)
        if not parsed.hostname:
            return None
        return {
            "parsed": parsed,
            "assumed_scheme": not (has_scheme or is_dangerous),
            "source": with_scheme,
        }
    except Exception:
        return None


def analyze_url(raw_input: str) -> dict:
    """
    Analyze a URL for threat indicators.

    Returns a dict with:
    - input: the original input
    - normalized: the normalized URL
    - host: the hostname
    - score: the risk score (0-100)
    - findings: list of Finding objects
    - error: error string if parsing failed

    Does NOT visit or follow the URL.
    """
    result = parse_url(raw_input)
    if result is None:
        return {"error": "invalid-url"}

    u = result["parsed"]
    findings: list[Finding] = []
    proto = u.scheme.lower()

    # Dangerous schemes (javascript:, data:, vbscript:)
    if proto in ("javascript", "data", "vbscript"):
        findings.append(make_finding(
            "scheme", 70,
            f'Uses a "{proto}" address instead of a website',
            "This is not a normal web address. It can run code or show content that is built into the link itself.",
            f'Never open links that begin with "{proto}:".',
        ))
        return {
            "input": raw_input,
            "normalized": u.geturl(),
            "host": "",
            "score": 70,
            "findings": findings,
        }

    # Unusual scheme
    if proto not in ("http", "https"):
        findings.append(make_finding(
            "scheme", 15,
            f"Uses an unusual address type ({proto})",
            "Most legitimate links start with http or https.",
        ))

    host = (u.hostname or "").lower()
    is_ipv4 = bool(IPV4_RE.match(host))
    is_ipv6 = host.startswith("[")
    is_ip = is_ipv4 or is_ipv6
    registrable = host if is_ip else registrable_domain(host)
    official = (not is_ip) and registrable in OFFICIAL_DOMAINS

    # HTTP without encryption
    if proto == "http" and not result["assumed_scheme"]:
        findings.append(make_finding(
            "http", 10,
            "Does not use HTTPS",
            "The address starts with http, so the connection is not encrypted. Login pages on such addresses are a warning sign.",
        ))

    # IP address instead of domain
    if is_ip:
        findings.append(make_finding(
            "ip", 35,
            "Uses an IP address instead of a domain name",
            f'The address points to "{host}" directly. Legitimate services almost always use a named domain.',
            "Do not enter any details on a page reached through a raw IP address.",
        ))
        # Check for disguised IP
        after_scheme = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", result["source"], flags=re.IGNORECASE)
        authority = after_scheme.split("/")[0].split("?")[0].split("#")[0]
        authority = authority[authority.rfind("@") + 1 :]
        authority = re.sub(r":\d+$", "", authority).lower()
        if is_ipv4 and authority != host:
            findings.append(make_finding(
                "ip-hidden", 10,
                "The IP address is written in a disguised form",
                f'The address was written as "{authority}" but resolves to {host}. Disguised numbers are used to get past quick visual checks.',
            ))

    # @ sign trick (userinfo in URL)
    if u.username:
        domain_like = "." in u.username
        findings.append(make_finding(
            "userinfo", 30 if domain_like else 15,
            "Has a username section before the real address",
            f'Everything before the "@" is ignored when the link is opened. The real destination is "{host}".',
            'Read what comes after the "@". That is where the link really goes.',
        ))

    # Punycode / internationalized domain names
    if any(l.startswith("xn--") for l in host.split(".")):
        findings.append(make_finding(
            "punycode", 25,
            "Uses look-alike (internationalized) characters",
            "The domain contains characters from other alphabets that can look identical to ordinary letters.",
            "Type the site's address yourself instead of following the link.",
        ))

    # Link shortener
    if not is_ip and (host in SHORTENERS or registrable in SHORTENERS):
        findings.append(make_finding(
            "shortener", 15,
            "Uses a link shortener",
            f'"{registrable}" hides the real destination behind a short code.',
            "Expand the link with a preview feature, or ask the sender for the full address.",
        ))

    if not is_ip:
        # Excessive subdomains
        label_count = len(host.split("."))
        reg_count = len(registrable.split("."))
        if label_count - reg_count >= 3:
            findings.append(make_finding(
                "subdomains", 10,
                "Has many subdomains",
                f'The host "{host}" has {label_count - reg_count} parts in front of the main domain, which can be used to bury the real name.',
            ))

        # Many hyphens
        hyphen_count = host.count("-")
        if hyphen_count >= 2:
            findings.append(make_finding(
                "hyphens", 8,
                "Has several hyphens in the domain",
                "Domains with several hyphens are common in throwaway scam sites.",
            ))

        # Risky TLD
        tld = registrable.split(".", 1)[1] if "." in registrable else ""
        if not official and tld in RISKY_TLDS:
            findings.append(make_finding(
                "tld", 12,
                "Uses a domain ending often seen in scams",
                f'The ending ".{tld}" is cheap or free to register and is overrepresented in phishing campaigns.',
            ))

        # Brand impersonation
        if not official:
            brand_finding = brand_checks(host, registrable)
            if brand_finding:
                findings.append(brand_finding)

    # Unusual port
    port = u.port
    if port and port not in (80, 443):
        findings.append(make_finding(
            "port", 8,
            "Uses an unusual port number",
            f"The address connects on port {port}, which ordinary websites do not need to show.",
        ))

    # Sensitive keywords in URL
    if not official:
        path_decoded = safe_unquote(u.path or "")
        haystack = f"{host} {path_decoded}".lower()
        hits = [k for k in URL_KEYWORDS if k in haystack]
        if hits:
            shown = hits[:4]
            findings.append(make_finding(
                "keywords", min(12, len(hits) * 6),
                "Contains sensitive words in the address",
                f'Found: {", ".join(shown)}. Scam pages often use words like these to look official.',
            ))

    # Redirect parameter
    has_redirect = False
    query = u.query or ""
    for part in query.split("&"):
        if "=" in part:
            val = part.split("=", 1)[1]
            decoded_val = safe_unquote(val)
            if re.match(r"^https?://", decoded_val, re.IGNORECASE) or decoded_val.startswith("//"):
                has_redirect = True
                break
    if has_redirect:
        findings.append(make_finding(
            "redirect-param", 10,
            "Contains another web address inside it",
            "A second address is passed as a parameter. This pattern is used to bounce visitors to a different site.",
        ))

    # Very long URL
    if len(raw_input.strip()) > 100:
        findings.append(make_finding(
            "long", 5,
            "Is unusually long",
            "Very long addresses can hide the important part from a quick glance.",
        ))

    # Heavy percent-encoding
    encoded_count = len(ENCODED_CHARS_RE.findall(raw_input))
    if encoded_count > 5:
        findings.append(make_finding(
            "encoded", 5,
            "Contains many encoded characters",
            "Heavy percent-encoding can be used to disguise what the address contains.",
        ))

    # Executable file download
    if EXECUTABLE_EXT.search(u.path or ""):
        findings.append(make_finding(
            "download", 20,
            "Points to a file that can run or install software",
            "The address ends in a file type commonly used to deliver malware.",
            "Do not download or open files from links you did not expect.",
        ))

    score = min(100, sum(f.points for f in findings))
    return {
        "input": raw_input,
        "normalized": u.geturl(),
        "host": host,
        "score": score,
        "findings": findings,
    }
