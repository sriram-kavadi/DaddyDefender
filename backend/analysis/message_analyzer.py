"""
Suspicious Message Analyzer for Threat Check.

Analyzes emails, SMS, chat messages and other text for phishing,
scam, and social engineering indicators. Extracts and individually
analyzes any URLs found within the message.
"""
import re
from typing import Optional

from backend.models import Finding, FindingSeverity, FindingSource, LinkAnalysis, RiskLevel
from backend.analysis.url_analyzer import (
    analyze_url,
    registrable_domain,
    BRANDS,
    OFFICIAL_DOMAINS,
    make_finding,
)


# ──────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────

MAX_LINKS = 10

# TLDs used for bare-domain extraction from message text
LINK_TLDS = frozenset([
    "com", "net", "org", "info", "biz", "io", "co", "in", "us", "uk",
    "de", "ru", "cn", "ly", "gl", "cc", "ws", "xyz", "top", "tk", "ml",
    "ga", "cf", "gq", "click", "link", "site", "online", "shop", "store",
    "support", "help", "live", "app", "dev", "icu", "buzz", "work", "zip",
    "mov", "loan", "country", "rest", "cyou", "page", "cloud", "tech",
    "vip", "fun", "club", "monster", "sbs", "cfd",
])

# Negation pattern to avoid flagging security advice like "never share your OTP"
NEGATION_BEFORE = re.compile(
    r"(never|not|n't|no one should)\s+(\w+\s+)?(share|give|disclose|reveal|send|provide|tell|ask)\b",
    re.IGNORECASE,
)


# ──────────────────────────────────────────────────────────────────────
# Message analysis rules
# ──────────────────────────────────────────────────────────────────────

MESSAGE_RULES = [
    {
        "id": "urgency",
        "points": 10,
        "title": "Pressures you to act quickly",
        "detail": "Scams create a deadline so you act before thinking.",
        "tip": "Pause. Real organizations do not require instant action through a link or message.",
        "negatable": False,
        "re": re.compile(
            r"\b(urgent(?:ly)?|immediately|right away|act now|final notice|last (?:chance|warning)|"
            r"expires? (?:today|soon|in \d+)|within \d+ ?(?:hours?|hrs?|minutes?|mins?|days?)|"
            r"as soon as possible|asap|time[- ]sensitive)(?!\w)",
            re.IGNORECASE,
        ),
    },
    {
        "id": "threat",
        "points": 12,
        "title": "Threatens consequences such as a locked account",
        "detail": "Fear of losing access or facing penalties is a common way to push people into acting.",
        "tip": "Log in to the service by typing its address yourself to check whether anything is actually wrong.",
        "negatable": False,
        "re": re.compile(
            r"\b(account (?:has been |was |will be |is )?(?:suspended|locked|closed|limited|disabled|blocked|"
            r"compromised|terminated|deactivated)|unusual (?:sign[- ]?in|login|activity)|"
            r"suspicious (?:activity|login|sign[- ]?in|transaction)|"
            r"unauthori[sz]ed (?:access|transaction|login|activity)|legal action|"
            r"will be (?:arrested|prosecuted)|arrest warrant|you will lose access)(?!\w)",
            re.IGNORECASE,
        ),
    },
    {
        "id": "credentials",
        "points": 20,
        "title": "Asks for passwords, codes, or personal details",
        "detail": "Legitimate organizations do not ask for these by message or through a link.",
        "tip": "Never share one-time codes, PINs, passwords, or card details with anyone who contacts you.",
        "negatable": True,
        "re": re.compile(
            r"\b(passwords?|passcode|your pin|pin (?:number|code)|otp|"
            r"one[- ]time (?:password|passcode|code)|cvv|cvc|card (?:number|details)|"
            r"security code|ssn|social security|aadhaar|pan card|"
            r"bank (?:account )?details|login (?:details|credentials)|"
            r"verify your (?:account|identity|details|information)|"
            r"confirm your (?:account|identity|details|information|password)|"
            r"update your (?:payment|billing|account|card) (?:details|information|info))(?!\w)",
            re.IGNORECASE,
        ),
    },
    {
        "id": "prize",
        "points": 15,
        "title": "Promises a prize, reward, or refund",
        "detail": "Unexpected winnings and refunds are used as bait.",
        "tip": "If you did not enter a contest or expect a refund, assume it is not real.",
        "negatable": False,
        "re": re.compile(
            r"\b(you(?:'ve| have)? (?:won|been selected|are a winner)|congratulations[,!]? you|"
            r"lottery|claim your (?:prize|reward|gift|refund)|"
            r"free (?:gift|iphone|prize|money)|cash prize|jackpot|"
            r"refund (?:is )?(?:pending|waiting|available))(?!\w)",
            re.IGNORECASE,
        ),
    },
    {
        "id": "payment",
        "points": 15,
        "title": "Mentions hard-to-trace payment or upfront fees",
        "detail": "Gift cards, crypto, wire transfers and 'small fees' are favored because the money cannot be recovered.",
        "tip": "Never pay a fee or send gift cards or crypto to claim something or to resolve a problem.",
        "negatable": False,
        "re": re.compile(
            r"\b(gift cards?|itunes card|google play card|wire transfer|western union|moneygram|"
            r"bitcoin|btc|crypto(?:currency)?|usdt|processing fee|customs fee|delivery fee|"
            r"release fee|advance fee|upfront fee|transfer (?:the )?(?:money|funds)|"
            r"pay (?:a |the )?(?:small )?fee)(?!\w)",
            re.IGNORECASE,
        ),
    },
    {
        "id": "greeting",
        "points": 6,
        "title": "Uses a generic greeting",
        "detail": "Messages from a service you use usually address you by name.",
        "tip": None,
        "negatable": False,
        "re": re.compile(
            r"\bdear (?:customer|user|member|client|account holder|"
            r"valued (?:customer|member)|sir\/madam|sir or madam|beneficiary)(?!\w)",
            re.IGNORECASE,
        ),
    },
    {
        "id": "click",
        "points": 8,
        "title": "Tells you to click a link or open an attachment",
        "detail": "Phishing messages push you toward a link or file.",
        "tip": "Type the website address yourself instead of clicking.",
        "negatable": False,
        "re": re.compile(
            r"\b(click (?:here|the link|below|on the link)|tap (?:here|the link|below)|"
            r"follow (?:this|the) link|open (?:the )?(?:attachment|link)|log ?in (?:here|now))(?!\w)",
            re.IGNORECASE,
        ),
    },
    {
        "id": "secrecy",
        "points": 10,
        "title": "Asks you to keep it secret",
        "detail": "Secrecy stops you from checking with someone who might spot the scam.",
        "tip": "Talk to a friend, family member, or the organization directly before acting.",
        "negatable": False,
        "re": re.compile(
            r"\b(do not tell|don'?t tell|keep (?:this|it) (?:secret|confidential|private)|"
            r"tell no one|do not (?:share|discuss) this)(?!\w)",
            re.IGNORECASE,
        ),
    },
    {
        "id": "remote",
        "points": 15,
        "title": "Mentions remote access or installing software",
        "detail": "Scammers ask you to install tools that give them control of your device.",
        "tip": "Never install software or give remote access because of an unsolicited message or call.",
        "negatable": False,
        "re": re.compile(
            r"\b(anydesk|teamviewer|ultraviewer|quick ?support|remote (?:access|desktop)|"
            r"install (?:the )?(?:app|software|apk))(?!\w)",
            re.IGNORECASE,
        ),
    },
    {
        "id": "authority",
        "points": 8,
        "title": "Claims to be an authority or a delivery problem",
        "detail": "Police, tax, customs and courier messages are often imitated.",
        "tip": None,
        "negatable": False,
        "re": re.compile(
            r"\b(irs|income tax department|customs|police|cbi|social security administration|"
            r"tax refund|undelivered (?:package|parcel)|missed delivery|delivery attempt|"
            r"your (?:package|parcel) (?:is|has been) (?:held|on hold))(?!\w)",
            re.IGNORECASE,
        ),
    },
    {
        "id": "callback",
        "points": 8,
        "title": "Asks you to call or message a number",
        "detail": "Callback numbers in unexpected messages lead to scam call centers.",
        "tip": "Look up the organization's number from its official site or a card you already have.",
        "negatable": False,
        "re": re.compile(
            r"\b(call|contact|whatsapp|text|message)\b[^.\n]{0,25}\+?\d[\d\s\-()]{8,}\d",
            re.IGNORECASE,
        ),
    },
]


# ──────────────────────────────────────────────────────────────────────
# Link extraction
# ──────────────────────────────────────────────────────────────────────

def _trim_trailing(s: str) -> str:
    """Remove trailing punctuation that's likely not part of the URL."""
    return re.sub(r"[.,;:!?)\]}'\"]+$", "", s)


def extract_urls(text: str) -> list[str]:
    """
    Extract URLs from message text.
    Handles explicit http(s):// URLs, www. URLs, and bare domain-like strings.
    Avoids extracting email addresses as URLs.
    """
    urls: list[str] = []
    ranges: list[tuple[int, int]] = []

    # First pass: explicit URLs
    for m in re.finditer(r"\b(?:https?://|www\.)[^\s<>\"'`]+", text, re.IGNORECASE):
        ranges.append((m.start(), m.end()))
        urls.append(_trim_trailing(m.group()))

    # Second pass: bare domains
    for m in re.finditer(r"\b(?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+([a-z]{2,24})(?:/[^\s<>\"'`]*)?", text, re.IGNORECASE):
        start = m.start()
        # Skip if overlaps with explicit URL
        if any(start >= r[0] and start < r[1] for r in ranges):
            continue
        # Skip email addresses
        if start > 0 and text[start - 1] == "@":
            continue
        candidate = _trim_trailing(m.group())
        tld = m.group(1).lower()
        if tld not in LINK_TLDS:
            continue
        urls.append(candidate)

    # Deduplicate
    seen: set[str] = set()
    unique: list[str] = []
    for u in urls:
        k = u.lower()
        if k not in seen:
            seen.add(k)
            unique.append(u)
    return unique


# ──────────────────────────────────────────────────────────────────────
# Message analysis
# ──────────────────────────────────────────────────────────────────────

def _find_matches(text: str, rule: dict) -> list[str]:
    """Find all matches for a rule's regex, respecting negation context."""
    phrases: list[str] = []
    for m in rule["re"].finditer(text):
        if not m.group():
            continue
        # Check for negation context
        if rule.get("negatable"):
            before = text[max(0, m.start() - 40) : m.start()].lower()
            if NEGATION_BEFORE.search(before):
                continue
        phrase = re.sub(r"\s+", " ", m.group().lower())
        if phrase not in phrases:
            phrases.append(phrase)
        if len(phrases) >= 4:
            break
    return phrases


def analyze_message(text: str) -> dict:
    """
    Analyze a message for phishing, scam, and social engineering indicators.

    Returns a dict with:
    - score: risk score (0-100)
    - findings: list of Finding objects from message text analysis
    - links: list of LinkAnalysis objects for URLs found in the message
    - max_link_score: highest risk score among extracted links
    """
    findings: list[Finding] = []
    matched: set[str] = set()

    # Apply all message rules
    for rule in MESSAGE_RULES:
        phrases = _find_matches(text, rule)
        if phrases:
            matched.add(rule["id"])
            quoted = ", ".join(f'"{p}"' for p in phrases)
            findings.append(make_finding(
                rule["id"],
                rule["points"],
                rule["title"],
                f'{rule["detail"]} Found: {quoted}.',
                rule["tip"],
            ))

    # Shouting detection (excessive caps or exclamation marks)
    letters = re.sub(r"[^A-Za-z]", "", text)
    upper = re.sub(r"[^A-Z]", "", text)
    if (len(letters) >= 20 and len(upper) / len(letters) > 0.4) or re.search(r"!{3,}", text):
        findings.append(make_finding(
            "shouting", 6,
            "Uses shouting or heavy emphasis",
            "Long stretches of capitals or repeated exclamation marks are used to create alarm.",
        ))

    # Extract and analyze links
    raw_urls = extract_urls(text)[:MAX_LINKS]
    links: list[LinkAnalysis] = []
    for raw in raw_urls:
        result = analyze_url(raw)
        if "error" in result:
            continue
        level = _level_for(result["score"])
        links.append(LinkAnalysis(
            url=raw,
            host=result["host"],
            risk_score=result["score"],
            risk_level=level,
            findings=result["findings"],
        ))

    # Combination bonus: pressure + request + link
    if links and "urgency" in matched and (
        "credentials" in matched or "payment" in matched or "threat" in matched
    ):
        findings.append(make_finding(
            "combo", 10,
            "Combines pressure, a request, and a link",
            "Urgency, a demand for action or details, and a link together are the typical shape of a phishing message.",
        ))

    # Brand/link mismatch: message names a brand but link goes elsewhere
    lower = text.lower()
    mismatch_finding = _check_brand_mismatch(lower, links)
    if mismatch_finding:
        findings.append(mismatch_finding)

    # Calculate score
    max_link_score = max((l.risk_score for l in links), default=0)
    score = min(100, sum(f.points for f in findings) + max_link_score)

    return {
        "score": score,
        "findings": findings,
        "links": links,
        "max_link_score": max_link_score,
    }


def _check_brand_mismatch(lower_text: str, links: list[LinkAnalysis]) -> Optional[Finding]:
    """Check if the message mentions a brand but links go to a different domain."""
    for brand in BRANDS:
        mentioned = any(
            re.search(r"\b" + t.replace(" ", r"\s+") + r"\b", lower_text, re.IGNORECASE)
            for t in brand["terms"]
        )
        if not mentioned:
            continue
        for link in links:
            host = link.host
            if not host or re.match(r"^\d", host) or host.startswith("["):
                return make_finding(
                    "brand-mismatch", 15,
                    f"Names {brand['display']} but links somewhere else",
                    f"The message mentions {brand['display']}, but the link goes to \"{link.url}\".",
                    f"Go to {brand['display']} by typing its official address yourself.",
                )
            reg = registrable_domain(host)
            if reg not in brand["domains"] and reg not in OFFICIAL_DOMAINS:
                return make_finding(
                    "brand-mismatch", 15,
                    f"Names {brand['display']} but links somewhere else",
                    f"The message mentions {brand['display']}, but the link goes to \"{host}\".",
                    f"Go to {brand['display']} by typing its official address yourself.",
                )
    return None


def _level_for(score: int) -> RiskLevel:
    """Map a numeric score to a risk level."""
    if score >= 75:
        return RiskLevel.CRITICAL
    if score >= 50:
        return RiskLevel.HIGH
    if score >= 25:
        return RiskLevel.MODERATE
    return RiskLevel.LOW
