"""
Cyber Sentinel — Flask Backend
Multi-layer phishing detection API.
No personal data is stored. Anonymous feedback signals may be used to improve detection accuracy.
"""
from __future__ import annotations
import re
import io
import os
import sys
import json
import base64
import hashlib
import logging
import threading
import time
from datetime import datetime
from urllib.parse import urlparse, unquote, quote

import requests
import tldextract
from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# ---------------------------------------------------------------------------
# Try optional imports — graceful fallback if unavailable
# ---------------------------------------------------------------------------
try:
    import whois as python_whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    from PIL import Image
    import pytesseract
    pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
    OCR_AVAILABLE = True
except (ImportError, Exception):
    OCR_AVAILABLE = False

# ---------------------------------------------------------------------------
# Logging setup — colored console output
# ---------------------------------------------------------------------------
class ColorFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[35m',  # Magenta
    }
    RESET = '\033[0m'
    BOLD = '\033[1m'

    def format(self, record):
        color = self.COLORS.get(record.levelname, self.RESET)
        record.msg = f"{color}{self.BOLD}[{record.levelname}]{self.RESET} {record.msg}"
        return super().format(record)

logger = logging.getLogger("cybersentinel")
logger.setLevel(logging.DEBUG)
# Fix Windows console encoding for emoji in log messages
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(ColorFormatter('%(asctime)s %(message)s', datefmt='%H:%M:%S'))
logger.addHandler(handler)

# ---------------------------------------------------------------------------
# Flask App
# ---------------------------------------------------------------------------
app = Flask(__name__)
CORS(app, supports_credentials=True)

# Serve index.html from the same folder
@app.route("/")
def serve_index():
    return app.send_static_file("index.html")

app.static_folder = "."
app.static_url_path = ""
app.config['SECRET_KEY'] = 'cyber-sentinel-secret-key-12345'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cyber_sentinel.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ---------------------------------------------------------------------------
# MODELS
# ---------------------------------------------------------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scans = db.relationship('ScanHistory', backref='user', lazy=True)
    feedbacks = db.relationship('FeedbackLog', backref='user', lazy=True)
    trusted_domains = db.relationship('TrustedDomain', backref='user', lazy=True)

class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    verdict = db.Column(db.String(20), nullable=False)
    risk_score = db.Column(db.Integer, nullable=False)
    signals_json = db.Column(db.Text, nullable=True)  # Store summary of flags for "Explain Result"
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class TrustedDomain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    domain = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class FeedbackLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    original_verdict = db.Column(db.String(20), nullable=False)
    corrected_verdict = db.Column(db.String(20), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------------------------------------------------------------------------
# LEARNING MEMORY — persistent store for feedback corrections
# ---------------------------------------------------------------------------
MEMORY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "learned_memory.json")
_memory_lock = threading.Lock()

# In-memory cache of learned data
_learned_memory = {
    "known_scam_urls": {},      # url -> {reason, reported_at, original_rank}
    "known_safe_urls": {},      # url -> {reason, reported_at, original_rank}
    "known_scam_patterns": {},  # text_hash -> {preview, reason, reported_at}
    "known_safe_patterns": {},  # text_hash -> {preview, reason, reported_at}
    "learned_signatures": [],   # list of extracted scam signature dicts
    "stats": {"total_feedback": 0, "corrections": 0}
}

def _load_memory():
    """Load learned memory from disk."""
    global _learned_memory
    if os.path.exists(MEMORY_FILE):
        try:
            with open(MEMORY_FILE, "r", encoding="utf-8") as f:
                _learned_memory = json.load(f)
            logger.info(f"🧠 Loaded learning memory: "
                        f"{len(_learned_memory.get('known_scam_urls', {}))} scam URLs, "
                        f"{len(_learned_memory.get('known_safe_urls', {}))} safe URLs, "
                        f"{len(_learned_memory.get('known_scam_patterns', {}))} scam patterns, "
                        f"{len(_learned_memory.get('known_safe_patterns', {}))} safe patterns")
        except Exception as e:
            logger.warning(f"⚠️ Could not load memory file: {e}")
    else:
        logger.info("🧠 No existing memory file — starting fresh")

def _save_memory():
    """Persist learned memory to disk."""
    try:
        with open(MEMORY_FILE, "w", encoding="utf-8") as f:
            json.dump(_learned_memory, f, indent=2, ensure_ascii=False)
        logger.info("💾 Learning memory saved to disk")
    except Exception as e:
        logger.error(f"❌ Failed to save memory: {e}")

def _text_fingerprint(text: str) -> str:
    """Create a normalized fingerprint hash of text content."""
    normalized = re.sub(r'\s+', ' ', text.lower().strip())
    return hashlib.sha256(normalized.encode('utf-8')).hexdigest()[:16]

def _extract_urls_from_text(text: str) -> list[str]:
    """Extract all URLs from text."""
    return re.findall(r'https?://[^\s<>"\')]+', text)

def _extract_scam_signatures(content: str, content_type: str) -> dict:
    """
    Analyze content to extract unique identifying scam signatures.
    Extracts: domains, suspicious keywords, TLDs, phone numbers, brand names,
    and behavioral pattern matches that make this content a scam.
    """
    signatures = {
        "domains": [],
        "domain_keywords": [],
        "tlds": [],
        "phishing_keywords": [],
        "phone_numbers": [],
        "brand_targets": [],
        "url_patterns": [],
        "behavioral_flags": []
    }

    content_lower = content.lower()

    # Extract domains from URLs
    urls = [content.strip()] if content_type == "url" else _extract_urls_from_text(content)
    for url in urls:
        try:
            extracted = tldextract.extract(url)
            if extracted.domain:
                reg_domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
                signatures["domains"].append(reg_domain.lower())
                if extracted.suffix:
                    signatures["tlds"].append(extracted.suffix.lower())
                # Extract keywords from domain parts
                parts = re.split(r'[-_.]', extracted.domain.lower())
                for part in parts:
                    if part in PHISHING_DOMAIN_KEYWORDS:
                        signatures["domain_keywords"].append(part)
            # Extract path keywords
            parsed = urlparse(url)
            path_parts = re.split(r'[/\-_?&=.]', parsed.path.lower())
            for part in path_parts:
                if part in PHISHING_DOMAIN_KEYWORDS:
                    signatures["phishing_keywords"].append(part)
        except Exception:
            pass

    # Extract brand impersonation targets
    _brand_targets = [
        "paypal", "apple", "google", "microsoft", "amazon", "netflix",
        "facebook", "instagram", "whatsapp", "paytm", "phonepe", "gpay",
        "sbi", "hdfc", "icici", "axis", "wells fargo", "chase", "citi",
        "bank of america", "usps", "fedex", "dhl", "ups"
    ]
    for brand in _brand_targets:
        if brand in content_lower:
            signatures["brand_targets"].append(brand)

    # Extract phone numbers
    phones = re.findall(r'\+?\d[\d\s\-]{8,15}\d', content)
    if phones:
        signatures["phone_numbers"] = [p.strip() for p in phones[:5]]

    # Detect which behavioral pattern categories triggered
    all_pattern_sets = [
        ("urgency", URGENCY_PATTERNS),
        ("smishing", SMISHING_PATTERNS),
    ]
    for name, patterns in all_pattern_sets:
        for p in patterns:
            try:
                if re.search(p, content_lower):
                    signatures["behavioral_flags"].append(name)
                    break
            except Exception:
                pass

    # Dedupe all lists
    for k in signatures:
        if isinstance(signatures[k], list):
            signatures[k] = list(dict.fromkeys(signatures[k]))

    return signatures


def memory_learn(content: str, content_type: str, correct_verdict: str, original_rank: str, original_score, comment: str = ""):
    """
    Learn from a wrong detection. Stores URLs, text patterns, AND extracts
    unique scam signatures (domains, keywords, TLDs, brands) so that similar
    future content is caught even if it's not an exact match.
    """
    with _memory_lock:
        now = datetime.utcnow().isoformat()
        urls_found = []

        # Extract URLs from content
        if content_type == "url":
            urls_found = [content.strip()]
        else:
            urls_found = _extract_urls_from_text(content)

        # Store URL corrections
        for url in urls_found:
            url_lower = url.lower().strip().rstrip('/')
            entry = {
                "reason": comment or f"User corrected from {original_rank}",
                "reported_at": now,
                "original_rank": original_rank,
                "original_score": original_score
            }
            if correct_verdict == "scam":
                _learned_memory["known_scam_urls"][url_lower] = entry
                _learned_memory["known_safe_urls"].pop(url_lower, None)
                logger.info(f"🧠 LEARNED: URL marked as SCAM → {url_lower}")
            elif correct_verdict == "safe":
                _learned_memory["known_safe_urls"][url_lower] = entry
                _learned_memory["known_scam_urls"].pop(url_lower, None)
                logger.info(f"🧠 LEARNED: URL marked as SAFE → {url_lower}")

        # Store text pattern fingerprint (for non-URL text content)
        if content_type in ("text", "image_base64_extracted") and len(content) > 20:
            fp = _text_fingerprint(content)
            entry = {
                "preview": content[:200],
                "reason": comment or f"User corrected from {original_rank}",
                "reported_at": now,
                "original_rank": original_rank
            }
            if correct_verdict == "scam":
                _learned_memory["known_scam_patterns"][fp] = entry
                _learned_memory["known_safe_patterns"].pop(fp, None)
                logger.info(f"🧠 LEARNED: Text pattern marked as SCAM (hash: {fp})")
            elif correct_verdict == "safe":
                _learned_memory["known_safe_patterns"][fp] = entry
                _learned_memory["known_scam_patterns"].pop(fp, None)
                logger.info(f"🧠 LEARNED: Text pattern marked as SAFE (hash: {fp})")

        # ── SIGNATURE EXTRACTION (New!) ──
        # When content is reported as scam, extract unique scam signatures
        # so we can catch similar (but not identical) scams in the future
        if correct_verdict == "scam":
            sigs = _extract_scam_signatures(content, content_type)
            # Only store if we found meaningful signatures
            has_meaningful = any([
                sigs.get("domains"),
                sigs.get("domain_keywords"),
                sigs.get("brand_targets"),
                sigs.get("phishing_keywords"),
            ])
            if has_meaningful:
                sig_entry = {
                    "extracted_at": now,
                    "content_type": content_type,
                    "original_rank": original_rank,
                    "correct_verdict": correct_verdict,
                    "signatures": sigs,
                    "reason": comment or f"Extracted from user correction"
                }
                _learned_memory.setdefault("learned_signatures", []).append(sig_entry)
                logger.info(f"🧠 SIGNATURE EXTRACTED: domains={sigs['domains']}, "
                           f"keywords={sigs['domain_keywords']}, "
                           f"brands={sigs['brand_targets']}")

        _learned_memory["stats"]["corrections"] = _learned_memory["stats"].get("corrections", 0) + 1
        _save_memory()

def memory_check(urls: list[str], text: str) -> dict:
    """
    Check content against learned memory.
    First checks exact URL/text matches, then performs signature-based fuzzy matching
    against learned scam signatures to catch similar (not identical) content.
    Returns: {matched: bool, verdict: str|None, source: str, detail: str, signature_boost: int}
    """
    with _memory_lock:
        # ── Exact URL match ──
        for url in urls:
            url_lower = url.lower().strip().rstrip('/')
            if url_lower in _learned_memory.get("known_scam_urls", {}):
                entry = _learned_memory["known_scam_urls"][url_lower]
                return {
                    "matched": True,
                    "verdict": "Scam",
                    "source": "Learning Memory",
                    "detail": f"Previously reported as scam: {entry.get('reason', 'User feedback')}",
                    "signature_boost": 0
                }
            if url_lower in _learned_memory.get("known_safe_urls", {}):
                entry = _learned_memory["known_safe_urls"][url_lower]
                return {
                    "matched": True,
                    "verdict": "Safe",
                    "source": "Learning Memory",
                    "detail": f"Previously confirmed safe: {entry.get('reason', 'User feedback')}",
                    "signature_boost": 0
                }

        # ── Exact text pattern match ──
        if text and len(text) > 20:
            fp = _text_fingerprint(text)
            if fp in _learned_memory.get("known_scam_patterns", {}):
                entry = _learned_memory["known_scam_patterns"][fp]
                return {
                    "matched": True,
                    "verdict": "Scam",
                    "source": "Learning Memory",
                    "detail": f"Text pattern previously reported as scam: {entry.get('reason', 'User feedback')}",
                    "signature_boost": 0
                }
            if fp in _learned_memory.get("known_safe_patterns", {}):
                entry = _learned_memory["known_safe_patterns"][fp]
                return {
                    "matched": True,
                    "verdict": "Safe",
                    "source": "Learning Memory",
                    "detail": f"Text pattern previously confirmed safe: {entry.get('reason', 'User feedback')}",
                    "signature_boost": 0
                }

        # ── Signature-based fuzzy matching (New!) ──
        # Even if the exact URL/text is new, check if it shares signatures
        # with previously reported scams (similar domain, same brand target, etc.)
        learned_sigs = _learned_memory.get("learned_signatures", [])
        if learned_sigs and isinstance(learned_sigs, list):
            # Determine content for signature extraction
            combined_content = ""
            current_type = "text"
            if urls:
                combined_content = urls[0]
                current_type = "url"
            elif text:
                combined_content = text

            if combined_content:
                current_sigs = _extract_scam_signatures(combined_content, current_type)
                best_match_score = 0
                best_match_detail = ""

                for stored in learned_sigs:
                    if not isinstance(stored, dict):
                        continue
                    stored_sigs = stored.get("signatures", {})
                    if not isinstance(stored_sigs, dict):
                        continue
                    match_score = 0
                    match_reasons = []

                    # Domain match (strongest signal — same registered domain)
                    for d in current_sigs.get("domains", []):
                        if d in stored_sigs.get("domains", []):
                            match_score += 40
                            match_reasons.append(f"Known scam domain: {d}")

                    # Domain keyword overlap (2+ shared keywords)
                    current_dkw = set(current_sigs.get("domain_keywords", []))
                    stored_dkw = set(stored_sigs.get("domain_keywords", []))
                    kw_overlap = current_dkw & stored_dkw
                    if len(kw_overlap) >= 2:
                        match_score += 20
                        match_reasons.append(f"Matching scam keywords: {', '.join(kw_overlap)}")

                    # Brand impersonation match (same brand being targeted)
                    current_brands = set(current_sigs.get("brand_targets", []))
                    stored_brands = set(stored_sigs.get("brand_targets", []))
                    brand_overlap = current_brands & stored_brands
                    if brand_overlap:
                        match_score += 25
                        match_reasons.append(f"Same brand target: {', '.join(brand_overlap)}")

                    # Behavioral flag overlap
                    current_flags = set(current_sigs.get("behavioral_flags", []))
                    stored_flags = set(stored_sigs.get("behavioral_flags", []))
                    if current_flags & stored_flags:
                        match_score += 10

                    if match_score > best_match_score:
                        best_match_score = match_score
                        best_match_detail = "; ".join(match_reasons)

                # If signature match is strong enough, boost detection
                if best_match_score >= 35:
                    return {
                        "matched": True,
                        "verdict": "Scam",
                        "source": "Signature Memory",
                        "detail": f"Matches learned scam signatures: {best_match_detail}",
                        "signature_boost": best_match_score
                    }
                elif best_match_score >= 20:
                    return {
                        "matched": True,
                        "verdict": "Suspicious",
                        "source": "Signature Memory",
                        "detail": f"Partially matches learned scam signatures: {best_match_detail}",
                        "signature_boost": best_match_score
                    }

    return {"matched": False, "verdict": None, "source": None, "detail": "No match in learning memory", "signature_boost": 0}

# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------
TRUSTED_BRANDS = [
    "google", "facebook", "apple", "microsoft", "amazon", "paypal",
    "netflix", "instagram", "whatsapp", "twitter", "linkedin", "youtube",
    "gmail", "outlook", "yahoo", "ebay", "dropbox", "chase", "wellsfargo",
    "bankofamerica", "citibank", "irs", "gov", "fedex", "dhl", "ups",
    "usps", "spotify", "snapchat", "tiktok", "pinterest", "uber",
    "airbnb", "coinbase", "binance", "stripe", "venmo", "zelle"
]

TRUSTED_DOMAINS = [
    "google.com", "facebook.com", "apple.com", "microsoft.com", "amazon.com",
    "paypal.com", "netflix.com", "instagram.com", "whatsapp.com", "twitter.com",
    "linkedin.com", "youtube.com", "gmail.com", "outlook.com", "yahoo.com",
    "ebay.com", "dropbox.com", "chase.com", "wellsfargo.com",
    "bankofamerica.com", "citibank.com", "fedex.com", "dhl.com", "ups.com",
    "github.com", "stackoverflow.com", "reddit.com", "wikipedia.org",
    "spotify.com", "uber.com", "airbnb.com", "stripe.com", "x.com"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".club", ".work", ".click", ".link", ".gq", ".ml",
    ".cf", ".tk", ".ga", ".pw", ".cc", ".info", ".biz", ".online",
    ".site", ".website", ".space", ".fun", ".icu", ".vip", ".live",
    ".stream", ".download", ".win", ".racing", ".date", ".review",
    ".loan", ".trade", ".bid", ".accountant", ".science", ".party",
    ".cricket", ".faith", ".zip", ".mov", ".buzz", ".rest", ".sbs"
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc",
    "rb.gy", "v.gd", "qr.ae", "yourls.org"
]

CHAR_SUBS = {"a": "@", "o": "0", "i": "1", "l": "1", "e": "3", "s": "5"}

# Unicode homoglyphs — Cyrillic / Greek letters that look identical to Latin
HOMOGLYPH_MAP = {
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p', '\u0441': 'c',
    '\u0445': 'x', '\u0443': 'y', '\u0456': 'i', '\u0458': 'j', '\u04bb': 'h',
    '\u0501': 'd', '\u051b': 'q', '\u0455': 's', '\u0442': 't', '\u057d': 's',
    '\u0410': 'A', '\u0412': 'B', '\u0415': 'E', '\u041a': 'K', '\u041c': 'M',
    '\u041d': 'H', '\u041e': 'O', '\u0420': 'P', '\u0421': 'C', '\u0422': 'T',
    '\u0425': 'X', '\u0427': 'Y',
    # Greek confusables
    '\u03b1': 'a', '\u03bf': 'o', '\u03c1': 'p', '\u03b5': 'e', '\u03b9': 'i',
    '\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u0397': 'H', '\u039a': 'K',
    '\u039c': 'M', '\u039d': 'N', '\u039f': 'O', '\u03a1': 'P', '\u03a4': 'T',
    '\u03a7': 'X', '\u0396': 'Z',
}

# Dangerous URI schemes (near-100% malicious in phishing context)
DANGEROUS_URI_SCHEMES = ["data:", "javascript:", "blob:", "vbscript:"]

# Double-extension / executable masquerade in URLs
DANGEROUS_DOUBLE_EXTENSIONS = re.compile(
    r'\.(pdf|doc|docx|xls|xlsx|jpg|png|gif|mp3|mp4|txt|csv|zip|rar)'
    r'\.(exe|scr|bat|cmd|com|pif|vbs|js|msi|ps1|wsf|hta)',
    re.IGNORECASE
)

import math

def _domain_entropy(domain: str) -> float:
    """Shannon entropy of a domain label — random domains have entropy > 3.5."""
    if not domain:
        return 0.0
    freq = {}
    for c in domain:
        freq[c] = freq.get(c, 0) + 1
    length = len(domain)
    return -sum((cnt / length) * math.log2(cnt / length) for cnt in freq.values())

def _normalize_homoglyphs(text: str) -> tuple[str, bool]:
    """Replace homoglyphs with ASCII equivalents. Returns (normalized, had_homoglyphs)."""
    result = []
    found = False
    for ch in text:
        if ch in HOMOGLYPH_MAP:
            result.append(HOMOGLYPH_MAP[ch])
            found = True
        else:
            result.append(ch)
    return ''.join(result), found

def _is_dangerous_uri(url: str) -> bool:
    """Check if URL uses a dangerous scheme like data: or javascript:."""
    lower = url.strip().lower()
    return any(lower.startswith(scheme) for scheme in DANGEROUS_URI_SCHEMES)

def _has_double_extension(url: str) -> bool:
    """Detect double-extension tricks like invoice.pdf.exe in URL path."""
    try:
        path = urlparse(url).path
        return bool(DANGEROUS_DOUBLE_EXTENSIONS.search(path))
    except Exception:
        return False

def _is_punycode(hostname: str) -> bool:
    """Detect punycode / internationalized domain names (xn-- prefix)."""
    if not hostname:
        return False
    return any(part.startswith("xn--") for part in hostname.lower().split("."))

# Phishing keywords commonly found in malicious URL paths
PHISHING_PATH_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "confirm", "secure", "security", "update", "account", "password",
    "reset", "unlock", "restore", "billing", "payment", "wallet",
    "authenticate", "validate", "suspended", "reactivate", "recover",
    "banking", "credential", "identity", "ssn", "webscr", "cmd=login"
]

# ---------------------------------------------------------------------------
# LAYER 1 — Live Threat Intelligence
# ---------------------------------------------------------------------------
OPENPHISH_FEED: list[str] = []
_openphish_lock = threading.Lock()


def _load_openphish():
    """Background loader for OpenPhish feed (refreshes every 30 min)."""
    global OPENPHISH_FEED
    while True:
        try:
            r = requests.get("https://openphish.com/feed.txt", timeout=8)
            if r.status_code == 200:
                with _openphish_lock:
                    OPENPHISH_FEED = r.text.strip().splitlines()
                logger.info(f"OpenPhish feed loaded: {len(OPENPHISH_FEED)} entries")
        except Exception as exc:
            logger.warning(f"OpenPhish fetch failed: {exc}")
        time.sleep(1800)  # 30 minutes


def check_urlhaus(url: str):
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=5
        )
        data = r.json()
        if data.get("query_status") == "is_blacklisted":
            return True, "URLhaus", "Known malicious URL (blacklisted)"
    except Exception:
        pass
    return False, None, None


def check_phishtank(url: str):
    try:
        encoded = quote(url, safe="")
        r = requests.get(
            f"https://checkurl.phishtank.com/checkurl/?url={encoded}&format=json",
            timeout=5
        )
        data = r.json()
        results = data.get("results", {})
        if results.get("in_database") and results.get("valid"):
            return True, "PhishTank", "Confirmed phishing page in PhishTank database"
    except Exception:
        pass
    return False, None, None


def check_openphish(url: str):
    with _openphish_lock:
        feed = list(OPENPHISH_FEED)
    for entry in feed:
        entry = entry.strip()
        if entry and (entry in url or url in entry):
            return True, "OpenPhish", "URL found in OpenPhish live feed"
    return False, None, None


def check_urlscan(url: str):
    """Check URLScan.io community API for known malicious URLs."""
    try:
        r = requests.get(
            f"https://urlscan.io/api/v1/search/?q=page.url:\"{url}\"&size=1",
            timeout=5,
            headers={"User-Agent": "CyberSentinel/3.0"}
        )
        if r.status_code == 200:
            data = r.json()
            results = data.get("results", [])
            if results:
                verdicts = results[0].get("verdicts", {})
                overall = verdicts.get("overall", {})
                if overall.get("malicious"):
                    return True, "URLScan.io", "URL flagged as malicious by URLScan.io"
    except Exception:
        pass
    return False, None, None


def resolve_redirects(url: str, max_hops: int = 5) -> str:
    """Follow URL redirects to find the final destination. Returns final URL."""
    try:
        r = requests.head(url, allow_redirects=True, timeout=3,
                          headers={"User-Agent": "Mozilla/5.0"},
                          verify=False)
        final_url = r.url
        if final_url != url:
            logger.info(f"  🔗 Redirect chain: {url} → {final_url}")
        return final_url
    except Exception:
        return url


def run_threat_intel(url: str):
    """Check all threat-intel feeds. Returns dict with results."""
    sources_checked = []
    for checker in [check_urlhaus, check_phishtank, check_openphish, check_urlscan]:
        hit, source, detail = checker(url)
        if hit:
            logger.info(f"  ⚡ Threat intel HIT: {source} — {detail}")
            return {
                "triggered": True,
                "source": source,
                "detail": detail,
                "sources_checked": sources_checked + [source]
            }
        if source:
            sources_checked.append(source)
    return {
        "triggered": False,
        "source": None,
        "detail": "Not found in any threat intelligence feed",
        "sources_checked": ["URLhaus", "PhishTank", "OpenPhish", "URLScan.io"]
    }


# ---------------------------------------------------------------------------
# LAYER 2 — Domain Risk Analysis
# ---------------------------------------------------------------------------
def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            cost = 0 if c1 == c2 else 1
            curr_row.append(min(
                curr_row[j] + 1,
                prev_row[j + 1] + 1,
                prev_row[j] + cost
            ))
        prev_row = curr_row
    return prev_row[-1]


def check_typosquatting(domain: str) -> tuple[bool, list[str]]:
    signals = []
    domain_lower = domain.lower()

    # Build all normalized variants of the domain
    normalised = domain_lower
    for orig, sub in CHAR_SUBS.items():
        normalised = normalised.replace(sub, orig)

    dehyphenated = domain_lower.replace("-", "")

    dehy_normalised = dehyphenated
    for orig, sub in CHAR_SUBS.items():
        dehy_normalised = dehy_normalised.replace(sub, orig)

    # Homoglyph-normalized variant
    homo_normalised, had_homoglyphs = _normalize_homoglyphs(domain_lower)

    variants = set([domain_lower, normalised, dehyphenated, dehy_normalised, homo_normalised])

    for brand in TRUSTED_BRANDS:
        if domain_lower == brand:
            continue

        for v in variants:
            # Exact or near-exact match
            dist = _levenshtein(v, brand)
            if dist <= 2:
                if had_homoglyphs and v == homo_normalised:
                    signals.append(f"Unicode homoglyph attack detected — impersonates '{brand}' using look-alike characters")
                elif v != domain_lower:
                    signals.append(f"Character/formatting trick detected — impersonates '{brand}'")
                else:
                    signals.append(f"Domain '{domain_lower}' looks like '{brand}' (typosquatting)")
                break

            # Brand used as prefix (e.g. amaz0n-secure, paypal-verify)
            if v.startswith(brand) or (len(brand) >= 4 and brand in v):
                signals.append(f"Domain contains brand name '{brand}' — possible impersonation")
                break

        if signals:
            break

    return bool(signals), signals


def check_subdomain_abuse(parsed_url) -> tuple[bool, list[str]]:
    signals = []
    hostname = parsed_url.hostname or ""
    ext = tldextract.extract(hostname)
    subdomain_parts = ext.subdomain.split(".") if ext.subdomain else []
    for brand in TRUSTED_BRANDS:
        for part in subdomain_parts:
            if brand in part.lower() and ext.domain.lower() != brand:
                signals.append(
                    f"Brand '{brand}' used as subdomain on '{ext.registered_domain}' — likely abuse"
                )
    return bool(signals), signals


def is_ip_url(url: str) -> bool:
    return bool(re.search(r'https?://\d{1,3}(\.\d{1,3}){3}', url))


def get_domain_age_days(domain: str):
    if not WHOIS_AVAILABLE:
        return None
    try:
        w = python_whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            return (datetime.now() - creation).days
    except Exception:
        pass
    return None


def count_phishing_path_keywords(url: str) -> tuple[int, list[str]]:
    """Count phishing-related keywords in the URL path/query."""
    try:
        parsed = urlparse(url)
        path_query = (parsed.path + "?" + (parsed.query or "")).lower()
    except Exception:
        return 0, []
    found = []
    for kw in PHISHING_PATH_KEYWORDS:
        if kw in path_query:
            found.append(kw)
    return len(found), found


def run_domain_analysis(url: str):
    """Analyse domain-level risk factors. Returns dict of signals."""
    signals = {}
    signal_details: list[str] = []

    # 0 — Dangerous URI scheme (data:, javascript:, etc.)
    if _is_dangerous_uri(url):
        signals["dangerous_uri"] = True
        signal_details.append(f"Dangerous URI scheme detected — likely malicious payload")
        # Short-circuit: dangerous URIs score extremely high by themselves
        return {"signals": signal_details, "flags": signals}

    try:
        parsed = urlparse(url)
    except Exception:
        return {"signals": signal_details, "flags": signals}

    ext = tldextract.extract(url)
    domain = ext.domain
    registered = ext.registered_domain
    hostname = parsed.hostname or ""

    # 2a — Typosquatting
    hit, msgs = check_typosquatting(domain)
    if hit:
        signals["typosquatting"] = True
        signal_details.extend(msgs)

    # Subdomain abuse
    hit, msgs = check_subdomain_abuse(parsed)
    if hit:
        signals["typosquatting"] = True
        signal_details.extend(msgs)

    # 2b — Suspicious TLD
    suffix = f".{ext.suffix}" if ext.suffix else ""
    if suffix.lower() in SUSPICIOUS_TLDS:
        signals["suspicious_tld"] = True
        signal_details.append(f"Suspicious TLD detected: {suffix}")

    # 2c — IP-based URL
    if is_ip_url(url):
        signals["ip_url"] = True
        signal_details.append("URL uses a raw IP address instead of a domain name")

    # 2d — Excessive subdomains
    subdomain_parts = ext.subdomain.split(".") if ext.subdomain else []
    subdomain_parts = [p for p in subdomain_parts if p]
    if len(subdomain_parts) > 3:
        signals["excessive_subdomains"] = True
        signal_details.append(
            f"Excessive subdomains ({len(subdomain_parts)}) — may be obfuscation"
        )

    # 2e — URL length / obfuscation
    if len(url) > 120:
        signals["url_length_extreme"] = True
        signal_details.append(f"Extremely long URL ({len(url)} chars)")
    elif len(url) > 75:
        signals["url_length_long"] = True
        signal_details.append(f"Unusually long URL ({len(url)} chars)")

    if "@" in url:
        signals["at_symbol"] = True
        signal_details.append("URL contains @ symbol — possible redirect trick")

    # URL shortener
    for shortener in URL_SHORTENERS:
        if shortener in hostname:
            signals["url_shortener"] = True
            signal_details.append(f"URL uses shortener ({shortener})")
            break

    # Encoded characters
    if re.search(r'%[0-9A-Fa-f]{2}', url):
        decoded = unquote(url)
        if decoded != url:
            signals["encoded_chars"] = True
            signal_details.append("URL contains encoded/obfuscated characters")

    # 2f — HTTPS check
    if parsed.scheme == "http":
        signals["no_https"] = True
        signal_details.append("No HTTPS — connection is not encrypted")

    # 2g — Domain age
    if registered and not signals.get("url_shortener"):
        age = get_domain_age_days(registered)
        if age is not None:
            signals["domain_age_days"] = age
            if age < 30:
                signal_details.append(f"Very new domain (registered {age} days ago)")
            elif age < 90:
                signal_details.append(f"Recently registered domain ({age} days ago)")

    # 2h — Trusted domain check
    if registered:
        if registered.lower() in TRUSTED_DOMAINS:
            signals["trusted_domain"] = True
        else:
            signals["trusted_domain"] = False

    # 2i — Phishing keywords in URL path
    kw_count, kw_list = count_phishing_path_keywords(url)
    if kw_count >= 1:
        signals["phishing_path_keywords"] = kw_count
        signal_details.append(
            f"Phishing keywords in URL path: {', '.join(kw_list[:5])}"
        )

    # 2j — Punycode / IDN detection
    if _is_punycode(hostname):
        signals["punycode_idn"] = True
        signal_details.append("Internationalized domain name (punycode) — may disguise real domain")

    # 2k — Domain entropy (random domain detection)
    if domain and not signals.get("trusted_domain"):
        entropy = _domain_entropy(domain)
        if entropy > 3.8 and len(domain) >= 6:
            signals["high_entropy_domain"] = True
            signal_details.append(f"Randomized domain name detected (entropy={entropy:.2f})")

    # 2l — Double-extension / executable masquerade in URL
    if _has_double_extension(url):
        signals["double_extension"] = True
        signal_details.append("Double-extension trick detected in URL (e.g. .pdf.exe)")

    # 2m — Phishing keywords in domain name itself
    if domain and not signals.get("trusted_domain"):
        domain_parts = re.split(r'[-_.]', domain.lower())
        domain_kw_found = [kw for kw in PHISHING_DOMAIN_KEYWORDS if kw in domain_parts]
        if len(domain_kw_found) >= 2:
            signals["phishing_domain_keywords"] = len(domain_kw_found)
            signal_details.append(
                f"Multiple phishing keywords in domain name: {', '.join(domain_kw_found)}"
            )
        elif len(domain_kw_found) == 1:
            # Single keyword in domain + other risk signals = still worth flagging
            if hostname and len(re.split(r'[-_.]', hostname)) >= 3:
                signals["phishing_domain_keywords"] = 1
                signal_details.append(
                    f"Phishing keyword in domain name: {domain_kw_found[0]}"
                )

    return {"signals": signal_details, "flags": signals}


# ---------------------------------------------------------------------------
# LAYER 3 — Behavioral / NLP Signal Analysis
# ---------------------------------------------------------------------------
URGENCY_PATTERNS = [
    r'\bact now\b', r'\bimmediate(ly)?\b', r'\burgent(ly)?\b', r'\bexpires?\b',
    r'\bwithin \d+ hours?\b', r'\bwithin \d+ minutes?\b', r'\bdeadline\b',
    r'\blast chance\b', r'\btime.?sensitive\b', r'\bverify now\b',
    r'\brespond immediately\b', r'\baction required\b', r'\blimited time\b',
    r'\bdo (it|this) (now|today|immediately)\b', r'\bhurry\b',
    r'\bbefore (it\'?s? )?too late\b', r'\bdon\'?t (wait|delay|ignore)\b',
    r'\bfinal (notice|warning|reminder)\b', r'\btoday only\b',
    r'\b(only|just) \d+ (hours?|minutes?|days?) (left|remaining)\b',
    r'\bexpir(e|es|ed|ing) (soon|today|tomorrow)\b',
    r'\brequires? (your )?(immediate|urgent)\b',
    r'\bfailure to (respond|act|verify|comply)\b',
    r'\bwithout delay\b', r'\bas soon as possible\b', r'\basap\b',
    r'\b(must|need to) (act|respond|verify|confirm|update)\b',
    r'\bexpir(e|es|ed|ing) (within|in) \d+\b',
    r'\btime is running out\b', r'\bdo not delay\b'
]

THREAT_PATTERNS = [
    r'\baccount.{0,20}(suspend|terminat|block|disabl|clos|restrict|lock|compromis|breach|hack)(?:ed|ing|ion|ment)?\b',
    r'\b(suspend|terminat|block|disabl|restrict|lock)(?:ed|ing|ion)?.{0,20}account\b',
    r'\b(legal action|lawsuit|prosecut|warrant|arrest)\b',
    r'\b(unusual|unauthorized|suspicious|fraudulent).{0,20}(activit|access|login|transaction|charge|sign.?in)\b',
    r'\byour (account|access|service|subscription|membership).{0,20}(has been|will be|is being|was)\b',
    r'\bverify your identity\b',
    r'\bconfirm your (details|information|account|identity)\b',
    r'\b(permanent(ly)?|immediate(ly)?) (clos|delet|suspend|terminat|block|lock|restrict)\w*\b',
    r'\bif you (don\'?t|do not|fail to)\b',
    r'\bwe (detected|noticed|found|identified).{0,30}(unusual|suspicious|unauthorized|breach|fraud)\b',
    r'\b(breach|compromis|hack|unauthorized access).{0,20}(your|the|this)\b',
    r'\bsecurity (alert|warning|breach|incident|violation)\b',
    r'\b(risk|danger) of.{0,20}(los|clos|delet|suspend)\b',
    r'\byou (must|need to|have to|are required to) (verify|confirm|update|validate)\b',
    r'\byour.{0,20}(at risk|in danger|compromised|breached)\b',
    r'\b(restrict|limit|suspend|freeze).{0,15}(access|service|account)\b',
    r'\b(unusual|unrecognized) (device|location|ip|sign.?in|login)\b'
]

REWARD_PATTERNS = [
    r'\b(you (have |\'? ?ve )?(won|been selected|been chosen))\b',
    r'\b(congratulations?|congrats?).{0,30}(won|winner|prize|reward|gift|selected|chosen)\b',
    r'\b(free|complimentary).{0,20}(iphone|gift.?card|voucher|reward|prize|cash|money|laptop|ipad|android|samsung)\b',
    r'\bclaim your (prize|reward|gift|winning|bonus|cash)\b',
    r'\b\$\d+[\.,]?\d* (reward|bonus|credit|prize|cash|gift)\b',
    r'\blottery\b', r'\bsweepstakes\b', r'\bjackpot\b',
    r'\b(lucky|chosen|selected) (winner|person|user|customer|visitor)\b',
    r'\bexclusive (offer|deal|reward|bonus|gift)\b',
    r'\b(win|earn|get|receive) (up to )?\$\d+\b',
    r'\b(cash|money|funds?) (prize|reward|bonus|waiting)\b',
    r'\bno (cost|charge|fee|purchase)\b',
    r'\b(100|completely|totally|absolutely) free\b',
    r'\bgift.?card\b', r'\bvoucher\b', r'\bcoupon\b',
    r'\byou.{0,10}(eligible|qualify|qualified)\b',
    r'\b(million|thousand) (dollar|pound|euro)\b'
]

CREDENTIAL_PATTERNS = [
    r'\b(enter|provide|submit|update|confirm|input|type|send).{0,30}(password|credential|login|username|ssn|social security|pin|passcode)\b',
    r'\b(click|tap|press|follow).{0,20}(here|link|below|button).{0,30}(to|and) (verify|confirm|update|login|sign|restore|unlock|secure)\b',
    r'\bsign.?in (to|with|at) your\b',
    r'\byour (password|pin|otp|code).{0,20}(expire|reset|verif|change|update)\b',
    r'\blog.?in (to |at |with )?your\b',
    r'\b(reset|change|update) (your )?(password|credentials|pin)\b',
    r'\benter.{0,15}(below|here|form)\b',
    r'\b(user.?name|email|phone).{0,15}(and|&).{0,15}password\b',
    r'\bsecure (your |the )?(account|login|access)\b',
    r'\b(confirm|verify) (your )?(account|identity|email|phone)\b',
    r'\bclick (the )?(link|button|here) (below|above|to)\b',
    r'\b(re.?enter|retype) (your )?(password|credentials)\b'
]

IMPERSONATION_PATTERNS = [
    r'\b(apple|google|microsoft|amazon|paypal|netflix|irs|fbi|interpol|dhl|fedex|ups|usps|chase|wells.?fargo|citibank|bank of america|venmo|zelle|coinbase|binance).{0,30}(support|team|security|service|alert|notification|department|center|helpdesk)\b',
    r'\bofficial (notice|message|alert|warning|communication|notification)\b',
    r'\b(we are|this is|from the).{0,20}(apple|google|microsoft|amazon|paypal|netflix|irs|fbi)\b',
    r'\bdear (valued |loyal )?(customer|user|member|client|account.?holder)\b',
    r'\b(customer|technical|account) (support|service|department|team)\b',
    r'\b(authorized|official|verified) (representative|agent|department|notice)\b',
    r'\bon behalf of\b',
    r'\b(help.?desk|service.?desk|it department|admin(istration)?)\b',
    r'\bno.?reply@\b'
]

SENSITIVE_PATTERNS = [
    r'\b(social security|ssn|national id|passport|date of birth|dob|driver.?s? licen[sc]e)\b',
    r'\b(credit card|debit card|card number|cvv|expir(y|ation) date|cvc|card.?holder)\b',
    r'\b(bank account|routing number|iban|swift|account number|sort code)\b',
    r'\b(otp|one.?time.?password|verification code|security code|auth(entication)? code)\b',
    r'\b(billing|payment) (info|information|details|address)\b',
    r'\b(mother.?s? maiden|security question|secret answer)\b',
    r'\btax.?(id|number|return|filing)\b',
    r'\b(personal|private|sensitive|confidential) (info|information|data|details)\b',
    r'\b(wire transfer|money transfer|western union|moneygram)\b'
]

# ── NEW CATEGORIES ───────────────────────────────────────────────────

INVOICE_PATTERNS = [
    r'\b(invoice|receipt|bill|statement).{0,20}(attach|enclosed|below|overdue|unpaid|pending|past.?due)\b',
    r'\b(overdue|outstanding|unpaid|past.?due).{0,20}(payment|balance|amount|invoice|bill)\b',
    r'\b(pay|remit|transfer|wire|send).{0,20}(immediately|now|today|asap|urgently)\b',
    r'\b(payment|invoice) (is )?(overdue|past.?due|required|needed|pending)\b',
    r'\b(attach(ed)?|enclosed|see) (invoice|receipt|bill|statement|document)\b',
    r'\b(outstanding|remaining|unpaid) (balance|amount|sum|fee)\b',
    r'\bfinal (payment|invoice|bill|reminder)\b',
    r'\b(late|overdue|penalty) (fee|charge|payment)\b',
    r'\bremittance (advice|details|information)\b',
    r'\bpurchase order\b'
]

CRYPTO_SCAM_PATTERNS = [
    r'\b(bitcoin|ethereum|crypto|btc|eth|wallet|blockchain).{0,20}(verify|validate|confirm|recover|restore|unlock|secure)\b',
    r'\b(verify|validate|confirm|recover|restore|unlock|secure).{0,20}(bitcoin|ethereum|crypto|btc|eth|wallet|blockchain)\b',
    r'\b(guaranteed|double|triple).{0,20}(return|profit|investment|your money|earnings)\b',
    r'\b(airdrop|mining|staking).{0,20}(reward|bonus|free|earn)\b',
    r'\b(seed phrase|private key|recovery phrase|wallet key).{0,20}(enter|provide|confirm|verify|share)\b',
    r'\b(enter|provide|confirm|verify|share).{0,20}(seed phrase|private key|recovery phrase|wallet key)\b',
    r'\b(crypto|bitcoin|ethereum) (giveaway|bonus|reward|doubling)\b',
    r'\b(invest|deposit).{0,20}(guaranteed|risk.?free|100%)\b',
    r'\b(nft|token|coin).{0,20}(free|claim|mint|airdrop)\b',
    r'\b(decentralized|defi).{0,20}(earn|profit|yield|reward)\b',
    r'\bsend .{0,10}(btc|eth|crypto|bitcoin).{0,15}(receive|get back|double)\b',
    r'\b(wallet|crypto|blockchain).{0,15}(locked|suspended|compromised|frozen)\b',
    r'\b(recover|restore|unlock).{0,10}(your )?(funds|assets|balance|wallet)\b',
]

BEC_PATTERNS = [
    r'\b(wire transfer|send funds|transfer money|bank transfer).{0,30}(urgent|asap|immediately|today|right away)\b',
    r'\b(ceo|cfo|director|manager|boss|president|executive).{0,20}(instructed|asked|requested|wants|needs|authorized)\b',
    r'\b(keep this|don.?t tell|between us|confidential|private).{0,20}(quiet|secret|private|discreet|between)\b',
    r'\b(change|update|new).{0,15}(bank|account|wire|routing).{0,15}(details|information|number)\b',
    r'\b(vendor|supplier|partner).{0,20}(payment|account|details).{0,15}(changed|updated|new)\b',
    r'\bdo not (discuss|share|mention|tell)\b',
    r'\btime.?sensitive.{0,20}(payment|transfer|transaction)\b',
    r'\b(handle|process) this (personally|directly|quietly|discreetly)\b',
    r'\b(w-?2|w-?9|tax form|employee list|payroll)\b'
]

JOB_SCAM_PATTERNS = [
    r'\b(job|position|employment|work from home|remote work|part.?time).{0,20}(offer|opportunity|opening|available)\b',
    r'\b(earn|make|salary|income).{0,10}\$\d{3,}\s*(per|a|each|every)\s*(day|hour|week|month)\b',
    r'\b(earn|make|salary|income).{0,10}\d{3,}\s*(per|a|each|every)\s*(day|hour|week|month)\b',
    r'\b(no experience|no interview|no resume|no degree).{0,10}(needed|required|necessary)\b',
    r'\b(hiring|recruiting).{0,20}(immediately|now|today|urgently)\b',
    r'\b(payment|fee|deposit).{0,15}(required|needed).{0,15}(before|to start|to begin)\b',
    r'\b(easy|simple) (money|income|cash|earnings)\b',
    r'\b(work|earn).{0,10}(from home|from anywhere|remotely).{0,15}\$?\d+\b',
    r'\b(secret|mystery) shopper\b',
    r'\b(data entry|envelope.?stuffing|paid survey)\b',
    r'\bget paid (to|for) (click|like|share|review|watch)\b',
    r'\bstart earning (today|now|immediately)\b'
]

SMISHING_PATTERNS = [
    r'\b(parcel|package|delivery|shipment|courier).{0,25}(confirm|verify|update|check|validate).{0,20}(address|otp|details|identity|info)\b',
    r'\b(confirm|verify|update|check|validate).{0,20}(parcel|package|delivery|shipment|courier|address)\b',
    r'\b(otp|one.?time.?password|verification code|security code).{0,20}(do not|don.?t|never).{0,10}share\b',
    r'\b(if this wasn.?t you|if you did.?n.?t|not authorized by you|if not you).{0,20}(click|visit|tap|call|go to)\b',
    r'\b(click|tap|visit|go to|open).{0,15}(link|here|below|this|url).{0,15}(to |and )?(verify|confirm|update|cancel|stop|secure|check)\b',
    r'\b(kyc|pan card|aadhar|aadhaar|pan.?verification)\b',
    r'\b(redelivery|redeliver|reschedule.{0,10}delivery|customs?.{0,10}fee|delivery.{0,10}fee)\b',
    r'\b(dear sir|dear madam|dear beneficiary|dear friend|respected sir)\b',
    r'\bkindly (verify|confirm|provide|update|click|respond|share|fill|submit|enter)\b',
    r'\b(plz|pls|plse)\b.{0,20}(confirm|verify|update|share|click|send|provide)\b',
    r'\b(your.{0,10}(otp|code|pin) is.{0,5}\d{4,8})\b',
    r'\b(sms|text|message).{0,15}(from|by|sent).{0,15}(bank|service|support|team)\b',
    r'\b(update|verify|link).{0,10}(your|ur).{0,10}(pan|kyc|aadhar|bank|account)\b',
    r'\b(expire|block|suspend|deactivat).{0,15}(today|tonight|within|in \d+|soon|immediately)\b',
]

PHISHING_DOMAIN_KEYWORDS = [
    "account", "verify", "secure", "login", "alert", "check",
    "update", "confirm", "support", "billing", "payment", "security",
    "suspend", "restore", "recover", "unlock", "validate", "authenticate",
    "signin", "password", "credential", "banking", "wallet", "reset"
]


def _grammar_anomaly_score(text: str) -> tuple[int, list[str]]:
    """Detect grammar/formatting anomalies common in phishing. Returns (score, details)."""
    score = 0
    details = []

    # Excessive caps: more than 40% of alpha chars are uppercase (minimum 20 chars)
    alpha = [c for c in text if c.isalpha()]
    if len(alpha) >= 20:
        upper_ratio = sum(1 for c in alpha if c.isupper()) / len(alpha)
        if upper_ratio > 0.6:
            score += 12
            details.append("Excessive ALL-CAPS text (common in scam messages)")
        elif upper_ratio > 0.4:
            score += 6
            details.append("Unusual amount of uppercase text")

    # Excessive exclamation/question marks
    excl_count = text.count("!") + text.count("?")
    if excl_count >= 8:
        score += 10
        details.append(f"Excessive punctuation ({excl_count} exclamation/question marks)")
    elif excl_count >= 4:
        score += 5
        details.append(f"Above-average exclamation marks ({excl_count})")

    # Repeated punctuation (!!! or ???)
    if re.search(r'[!?]{3,}', text):
        score += 8
        details.append("Repeated punctuation (e.g., !!!, ???) — phishing indicator")

    # Mixed scripts (Latin + Cyrillic in same text — possible homoglyph attack)
    has_latin = bool(re.search(r'[a-zA-Z]', text))
    has_cyrillic = bool(re.search(r'[\u0400-\u04FF]', text))
    if has_latin and has_cyrillic:
        score += 15
        details.append("Mixed Latin and Cyrillic characters — possible homoglyph deception")

    return score, details

def _count_matches(text: str, patterns: list[str]) -> tuple[int, list[str]]:
    count = 0
    matched_texts = []
    for p in patterns:
        m = re.search(p, text, re.IGNORECASE)
        if m:
            count += 1
            matched_texts.append(m.group())
    return count, matched_texts


def run_behavioral_analysis(text: str):
    """Scan text for phishing behavioral signals. Returns score + detail."""
    text_lower = text.lower()
    results = {}
    total_score = 0
    categories_triggered = 0

    # Urgency (+12 per, max 30)
    c, m = _count_matches(text_lower, URGENCY_PATTERNS)
    score = min(c * 12, 30)
    total_score += score
    if c:
        categories_triggered += 1
        results["urgency"] = {
            "triggered": True,
            "score": score,
            "matches": m,
            "detail": f"Urgency language detected ({c} signal{'s' if c > 1 else ''})"
        }

    # Threats (+18 per, max 40)
    c, m = _count_matches(text_lower, THREAT_PATTERNS)
    score = min(c * 18, 40)
    total_score += score
    if c:
        categories_triggered += 1
        results["threat_language"] = {
            "triggered": True,
            "score": score,
            "matches": m,
            "detail": f"Threatening language detected ({c} signal{'s' if c > 1 else ''})"
        }

    # Reward bait (+20 per, max 45)
    c, m = _count_matches(text_lower, REWARD_PATTERNS)
    score = min(c * 20, 45)
    total_score += score
    if c:
        categories_triggered += 1
        results["reward_bait"] = {
            "triggered": True,
            "score": score,
            "matches": m,
            "detail": f"Prize / reward bait detected ({c} signal{'s' if c > 1 else ''})"
        }

    # Credential harvesting (+15 per, max 35)
    c, m = _count_matches(text_lower, CREDENTIAL_PATTERNS)
    score = min(c * 15, 35)
    total_score += score
    if c:
        categories_triggered += 1
        results["credential_harvesting"] = {
            "triggered": True,
            "score": score,
            "matches": m,
            "detail": f"Credential harvesting language detected ({c} signal{'s' if c > 1 else ''})"
        }

    # Impersonation (+12 per, max 30)
    c, m = _count_matches(text_lower, IMPERSONATION_PATTERNS)
    score = min(c * 12, 30)
    total_score += score
    if c:
        categories_triggered += 1
        results["impersonation"] = {
            "triggered": True,
            "score": score,
            "matches": m,
            "detail": f"Brand/authority impersonation detected ({c} signal{'s' if c > 1 else ''})"
        }

    # Sensitive info (+15 per, max 35)
    c, m = _count_matches(text_lower, SENSITIVE_PATTERNS)
    score = min(c * 15, 35)
    total_score += score
    if c:
        categories_triggered += 1
        results["sensitive_info_request"] = {
            "triggered": True,
            "score": score,
            "matches": m,
            "detail": f"Requests for sensitive personal data ({c} signal{'s' if c > 1 else ''})"
        }

    # ── NEW CATEGORIES ───────────────────────────────────────────────

    # Invoice / Payment scam (+14 per, max 35)
    c, m = _count_matches(text_lower, INVOICE_PATTERNS)
    score = min(c * 14, 35)
    total_score += score
    if c:
        categories_triggered += 1
        results["invoice_scam"] = {
            "triggered": True,
            "score": score,
            "matches": m,
            "detail": f"Fake invoice / payment scam signals ({c} signal{'s' if c > 1 else ''})"
        }

    # Crypto / Investment scam (+16 per, max 35)
    c, m = _count_matches(text_lower, CRYPTO_SCAM_PATTERNS)
    score = min(c * 16, 35)
    total_score += score
    if c:
        categories_triggered += 1
        results["crypto_scam"] = {
            "triggered": True,
            "score": score,
            "matches": m,
            "detail": f"Crypto / investment scam signals ({c} signal{'s' if c > 1 else ''})"
        }

    # CEO / BEC fraud (+16 per, max 35)
    c, m = _count_matches(text_lower, BEC_PATTERNS)
    score = min(c * 16, 35)
    total_score += score
    if c:
        categories_triggered += 1
        results["bec_fraud"] = {
            "triggered": True,
            "score": score,
            "matches": m,
            "detail": f"Business Email Compromise (BEC) signals ({c} signal{'s' if c > 1 else ''})"
        }

    # Job offer scam (+14 per, max 30)
    c, m = _count_matches(text_lower, JOB_SCAM_PATTERNS)
    score = min(c * 14, 30)
    total_score += score
    if c:
        categories_triggered += 1
        results["job_scam"] = {
            "triggered": True,
            "score": score,
            "matches": m,
            "detail": f"Job offer / employment scam signals ({c} signal{'s' if c > 1 else ''})"
        }

    # Grammar / formatting anomalies
    grammar_score, grammar_details = _grammar_anomaly_score(text)
    total_score += grammar_score
    if grammar_score > 0:
        categories_triggered += 1
        results["grammar_anomaly"] = {
            "triggered": True,
            "score": grammar_score,
            "matches": grammar_details,
            "detail": f"Grammar/formatting anomalies detected ({len(grammar_details)} signal{'s' if len(grammar_details) > 1 else ''})"
        }

    # SMS / Delivery / Smishing scam (+14 per, max 35)
    c, m = _count_matches(text_lower, SMISHING_PATTERNS)
    score = min(c * 14, 35)
    total_score += score
    if c:
        categories_triggered += 1
        results["smishing"] = {
            "triggered": True,
            "score": score,
            "matches": m,
            "detail": f"SMS/delivery phishing signals ({c} signal{'s' if c > 1 else ''})"
        }

    # Multi-signal escalation bonus (updated for 11 total categories)
    if categories_triggered >= 7:
        total_score += 45
    elif categories_triggered >= 6:
        total_score += 40
    elif categories_triggered >= 5:
        total_score += 35
    elif categories_triggered >= 4:
        total_score += 25
    elif categories_triggered >= 3:
        total_score += 15
    elif categories_triggered >= 2:
        total_score += 8

    return total_score, results, categories_triggered


# ---------------------------------------------------------------------------
# LAYER 4 — Scoring & Classification
# ---------------------------------------------------------------------------
# Configurable layer weights (must sum to 1.0)
LAYER_WEIGHTS = {
    "threat_intel": 0.45,      # Strongest signal — known malicious
    "domain_analysis": 0.30,   # URL/domain structural signals
    "behavioral": 0.25,        # Language/content patterns
}


def calculate_risk_score(threat_intel_hit: bool, domain_flags: dict,
                         behavioral_score: int, behavioral_categories: int):
    """
    Weighted risk scoring system.
    Each layer produces a raw score (0-100), then each is multiplied by its
    weight.  Cross-layer amplification rewards convergent evidence.
    Returns: (final_score, rank, emoji, weight_breakdown)
    """

    # ── Layer 1: Threat Intelligence (raw 0-100) ─────────────────────
    threat_raw = 95 if threat_intel_hit else 0

    # ── Layer 2: Domain Analysis (raw 0-100) ─────────────────────────
    domain_raw = 0
    domain_signals_detail = {}

    signal_weights = {
        "dangerous_uri":          45,   # data:/javascript: — near-certain malicious
        "typosquatting":          35,
        "ip_url":                 30,
        "double_extension":       30,   # .pdf.exe tricks
        "at_symbol":              25,
        "excessive_subdomains":   22,
        "punycode_idn":           22,   # internationalized domain abuse
        "url_shortener":          20,
        "suspicious_tld":         18,
        "high_entropy_domain":    18,   # randomized domain names
        "url_length_extreme":     15,
        "no_https":               12,
        "encoded_chars":          10,
        "url_length_long":        6,
    }

    for signal_name, weight in signal_weights.items():
        if domain_flags.get(signal_name):
            domain_raw += weight
            domain_signals_detail[signal_name] = weight

    # Domain age
    age = domain_flags.get("domain_age_days")
    if age is not None:
        if age < 30:
            domain_raw += 28
            domain_signals_detail["new_domain_<30d"] = 28
        elif age < 90:
            domain_raw += 12
            domain_signals_detail["young_domain_<90d"] = 12

    # Phishing keywords in path
    path_kw = domain_flags.get("phishing_path_keywords", 0)
    if isinstance(path_kw, int) and path_kw > 0:
        pw = min(path_kw * 8, 25)
        domain_raw += pw
        domain_signals_detail["phishing_path_keywords"] = pw

    # Phishing keywords in domain name
    domain_kw = domain_flags.get("phishing_domain_keywords", 0)
    if isinstance(domain_kw, int) and domain_kw > 0:
        dw = min(domain_kw * 12, 30)
        domain_raw += dw
        domain_signals_detail["phishing_domain_keywords"] = dw

    # Multi-signal convergence bonus
    domain_flag_count = sum(1 for k, v in domain_flags.items()
                           if v and k not in ("trusted_domain", "domain_age_days",
                                              "phishing_path_keywords", "phishing_domain_keywords"))
    if domain_flag_count >= 5:
        domain_raw += 25
    elif domain_flag_count >= 4:
        domain_raw += 20
    elif domain_flag_count >= 3:
        domain_raw += 15
    elif domain_flag_count >= 2:
        domain_raw += 8

    domain_raw = min(domain_raw, 100)

    # ── Layer 3: Behavioral (raw 0-100) ──────────────────────────────
    behavioral_raw = min(behavioral_score, 100)

    # ── Dynamic weight adjustment ────────────────────────────────────
    # For text-only scans (no URL/domain data), boost behavioral weight
    has_url_data = domain_raw > 0 or threat_raw > 0
    if has_url_data:
        w_threat = LAYER_WEIGHTS["threat_intel"]
        w_domain = LAYER_WEIGHTS["domain_analysis"]
        w_behav  = LAYER_WEIGHTS["behavioral"]
    else:
        # Text-only: behavioral gets the dominant weight for accurate text scam detection
        w_threat = 0.05
        w_domain = 0.05
        w_behav  = 0.90

    # ── Weighted combination ─────────────────────────────────────────
    weighted_threat  = threat_raw  * w_threat
    weighted_domain  = domain_raw * w_domain
    weighted_behav   = behavioral_raw * w_behav
    score = weighted_threat + weighted_domain + weighted_behav

    # Cross-layer amplification (convergent evidence from multiple layers)
    active_layers = sum(1 for x in [threat_raw, domain_raw, behavioral_raw] if x > 15)
    if active_layers >= 3:
        score *= 1.35    # All three layers agree → strong boost
    elif active_layers == 2:
        score *= 1.18    # Two layers agree → moderate boost

    # Specifically when domain AND behavioral converge
    if domain_raw >= 25 and behavioral_raw >= 25:
        score += 10

    score = min(round(score), 100)

    # ── Confidence calculation ───────────────────────────────────────
    confidence_factors = 0
    confidence_max = 0

    # Threat intel checked?
    confidence_max += 30
    if threat_raw > 0:
        confidence_factors += 30
    else:
        confidence_factors += 15

    # Domain data available?
    has_domain_data = any(domain_flags.get(k) is not None
                         for k in ("trusted_domain", "domain_age_days", "typosquatting"))
    confidence_max += 40
    if has_domain_data:
        confidence_factors += 35 if domain_flag_count > 0 else 25

    # Behavioral analysis ran?
    confidence_max += 30
    if behavioral_categories > 0:
        confidence_factors += 30
    elif behavioral_raw == 0:
        confidence_factors += 15

    confidence = round(confidence_factors / confidence_max * 100) if confidence_max > 0 else 50

    # ── Classification ───────────────────────────────────────────────
    # Tighter thresholds for better detection
    if score <= 15:
        rank, emoji = "Safe", "🛡️"
    elif score <= 30:
        rank, emoji = "Suspicious", "⚠️"
    else:
        rank, emoji = "Scam", "🚨"

    # Override: behavioral has 4+ categories AND strong score → force Scam
    if behavioral_categories >= 4 and behavioral_score >= 40:
        rank, emoji = "Scam", "🚨"
        score = max(score, 41)

    # Override: behavioral has 3+ categories AND decent score → at least Suspicious, push toward Scam
    if behavioral_categories >= 3 and behavioral_score >= 30 and rank != "Scam":
        rank, emoji = "Suspicious", "⚠️"
        score = max(score, 31)

    # Override: if behavioral alone has 4+ categories, at least Suspicious
    if behavioral_categories >= 4 and rank == "Safe":
        rank, emoji = "Suspicious", "⚠️"
        score = max(score, 25)

    # Override: if behavioral has 2+ categories, never Safe
    if behavioral_categories >= 2 and rank == "Safe":
        rank, emoji = "Suspicious", "⚠️"
        score = max(score, 18)

    # Override: dangerous URI = always Scam
    if domain_flags.get("dangerous_uri"):
        rank, emoji = "Scam", "🚨"
        score = max(score, 85)

    # Override: non-trusted domain with phishing keywords/signals = at least Suspicious
    if domain_flags.get("trusted_domain") is False:
        has_phishing_signals = any(domain_flags.get(k) for k in (
            "phishing_domain_keywords", "phishing_path_keywords",
            "typosquatting", "suspicious_tld", "ip_url"))
        if has_phishing_signals and rank == "Safe":
            rank, emoji = "Suspicious", "⚠️"
            score = max(score, 20)

    weight_breakdown = {
        "threat_intel":  {"raw": threat_raw,     "weight": w_threat,  "weighted": round(weighted_threat, 1)},
        "domain":        {"raw": domain_raw,     "weight": w_domain, "weighted": round(weighted_domain, 1),
                          "signals": domain_signals_detail},
        "behavioral":    {"raw": behavioral_raw, "weight": w_behav,   "weighted": round(weighted_behav, 1)},
        "amplification": {"active_layers": active_layers, "applied": active_layers >= 2},
        "confidence":    confidence
    }

    return score, rank, emoji, weight_breakdown


# ---------------------------------------------------------------------------
# LAYER 5 — OCR (Image text extraction)
# ---------------------------------------------------------------------------
def extract_text_from_image(base64_string: str) -> tuple[str, str | None]:
    """Returns (extracted_text, error_message). error_message is None on success."""
    if not OCR_AVAILABLE:
        return "", (
            "OCR is not available. Install Tesseract OCR and Python packages "
            "(Pillow, pytesseract) to analyze screenshots. "
            "Alternatively, copy the text from the image and paste it in the Text tab."
        )
    try:
        # Strip data-URI prefix if present
        if "," in base64_string:
            base64_string = base64_string.split(",", 1)[1]
        img_data = base64.b64decode(base64_string)
        img = Image.open(io.BytesIO(img_data))
        text = pytesseract.image_to_string(img)
        extracted = text.strip()
        if not extracted:
            return "", "Could not extract any text from this image. The image may be too blurry, contain no text, or use unsupported fonts. Try pasting the text directly in the Text tab."
        logger.info(f"  📷 OCR extracted {len(extracted)} chars from image")
        return extracted, None
    except Exception as exc:
        logger.error(f"  OCR error: {exc}")
        return "", f"OCR processing failed: {str(exc)}. Try pasting the text directly in the Text tab."


def extract_urls_from_text(text: str) -> list[str]:
    """Find URLs embedded in arbitrary text."""
    url_pattern = r'https?://[^\s<>"\')\]}\,]+'
    return re.findall(url_pattern, text)


# ---------------------------------------------------------------------------
# AUTH ENDPOINTS
# ---------------------------------------------------------------------------
@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json(force=True)
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already exists"}), 400

    new_user = User(email=email, password_hash=generate_password_hash(password))
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User created successfully"}), 201

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True)
    email = data.get("email")
    password = data.get("password")

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"error": "Invalid email or password"}), 401

    login_user(user)
    return jsonify({
        "message": "Login successful",
        "user": {"id": user.id, "email": user.email}
    }), 200

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logout successful"}), 200

@app.route("/history", methods=["GET"])
@login_required
def history():
    scans = ScanHistory.query.filter_by(user_id=current_user.id).order_by(ScanHistory.timestamp.desc()).all()
    
    # Calculate stats
    total = len(scans)
    safe = sum(1 for s in scans if s.verdict == "Safe")
    suspicious = sum(1 for s in scans if s.verdict == "Suspicious")
    scam = sum(1 for s in scans if s.verdict == "Scam")
    
    # Security Score (0-100)
    # Safe = 100 pts, Suspicious = 40 pts, Scam = 0 pts
    score = 100 if total == 0 else round(((safe * 100) + (suspicious * 40)) / total)
    
    history_data = [
        {
            "id": scan.id,
            "verdict": scan.verdict,
            "risk_score": scan.risk_score,
            "signals": json.loads(scan.signals_json) if scan.signals_json else [],
            "timestamp": scan.timestamp.isoformat()
        } for scan in scans
    ]
    return jsonify({
        "user": {"email": current_user.email},
        "history": history_data,
        "stats": {
            "total": total,
            "safe": safe,
            "suspicious": suspicious,
            "scam": scam,
            "security_score": score
        }
    }), 200

@app.route("/trusted_domains", methods=["GET", "POST"])
@login_required
def trusted_domains():
    if request.method == "POST":
        data = request.get_json(force=True)
        domain = data.get("domain", "").strip().lower()
        if not domain:
            return jsonify({"error": "Domain is required"}), 400
        
        # Check if already exists
        if TrustedDomain.query.filter_by(user_id=current_user.id, domain=domain).first():
            return jsonify({"message": "Domain already in list"}), 200
            
        new_td = TrustedDomain(user_id=current_user.id, domain=domain)
        db.session.add(new_td)
        db.session.commit()
        return jsonify({"message": "Domain added to trusted list"}), 201

    domains = TrustedDomain.query.filter_by(user_id=current_user.id).order_by(TrustedDomain.timestamp.desc()).all()
    return jsonify({"domains": [{"id": d.id, "domain": d.domain} for d in domains]}), 200

@app.route("/trusted_domains/<int:domain_id>", methods=["DELETE"])
@login_required
def delete_trusted_domain(domain_id):
    td = TrustedDomain.query.filter_by(id=domain_id, user_id=current_user.id).first()
    if not td:
        return jsonify({"error": "Not found"}), 404
    db.session.delete(td)
    db.session.commit()
    return jsonify({"message": "Domain removed"}), 200

@app.route("/download_report", methods=["GET"])
@login_required
def download_report():
    try:
        scans = ScanHistory.query.filter_by(user_id=current_user.id).all()
        report = []
        report.append("CYBER SENTINEL - SECURITY REPORT")
        report.append(f"Generated for: {current_user.email}")
        report.append(f"Total Scans Found: {len(scans)}")
        report.append("-" * 50)
        for s in scans:
            report.append(f"{s.timestamp} | {s.verdict} | Score: {s.risk_score}")
        
        return "\n".join(report), 200, {
            'Content-Type': 'text/plain',
            'Content-Disposition': 'attachment; filename=report.txt'
        }
    except Exception as e:
        return str(e), 500

# ---------------------------------------------------------------------------
# Main /analyze endpoint
# ---------------------------------------------------------------------------
@app.route("/analyze", methods=["POST"])
def analyze():
    start_time = time.time()

    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "Invalid JSON payload"}), 400

    input_type = data.get("type", "").strip().lower()
    content = data.get("content", "").strip()

    if not content:
        return jsonify({"error": "No content provided"}), 400

    logger.info(f"{'='*50}")
    logger.info(f"📨 New analysis request: type={input_type}, length={len(content)}")

    # ----- Determine text + URLs to analyse -----
    urls_to_check: list[str] = []
    analysis_text = ""

    if input_type == "url":
        url = content
        # Only prepend http:// for normal URLs, not dangerous schemes
        if not url.startswith("http") and not _is_dangerous_uri(url):
            url = "http://" + url
        urls_to_check.append(url)
        # Use full URL as analysis text (domain + path + query carry signals)
        try:
            parsed = urlparse(url)
            analysis_text = unquote(
                (parsed.hostname or "") + (parsed.path or "") +
                ("?" + parsed.query if parsed.query else "")
            )
        except Exception:
            analysis_text = url
        logger.info(f"  🔗 URL to check: {url}")

    elif input_type == "text":
        analysis_text = content
        urls_to_check = extract_urls_from_text(content)
        logger.info(f"  📝 Text preview: {content[:80]}...")
        if urls_to_check:
            logger.info(f"  🔗 Found {len(urls_to_check)} embedded URLs")

    elif input_type == "image_base64":
        extracted, error = extract_text_from_image(content)
        if error:
            logger.warning(f"  ❌ Image analysis failed: {error}")
            return jsonify({"error": error}), 400
        analysis_text = extracted
        urls_to_check = extract_urls_from_text(extracted)
        logger.info(f"  📷 OCR text preview: {extracted[:80]}...")

    else:
        return jsonify({"error": f"Unknown input type: '{input_type}'"}), 400

    # ----- Run Layers -----

    # Pre-processing: resolve URL redirects (especially URL shorteners)
    resolved_urls = []
    for url in urls_to_check:
        # Skip redirect following for dangerous schemes (they can't be resolved)
        if _is_dangerous_uri(url):
            resolved_urls.append(url)
        else:
            final = resolve_redirects(url)
            resolved_urls.append(final)
            if final != url:
                resolved_urls.append(url)  # Also check the original
    urls_to_check = list(dict.fromkeys(resolved_urls))  # Deduplicate, preserve order

    # Layer 1 — Threat Intel (on each URL)
    threat_intel_result = {
        "triggered": False,
        "source": None,
        "detail": "No URLs to check" if not urls_to_check else "Not found in any threat intelligence feed",
        "sources_checked": []
    }
    for url in urls_to_check:
        result = run_threat_intel(url)
        if result["triggered"]:
            threat_intel_result = result
            break
        threat_intel_result["sources_checked"] = result["sources_checked"]

    # Layer 2 — Domain Analysis (on each URL)
    domain_result = {"signals": [], "flags": {}}
    for url in urls_to_check:
        dr = run_domain_analysis(url)
        domain_result["signals"].extend(dr["signals"])
        # Merge flags (keep worst-case)
        for k, v in dr["flags"].items():
            if k == "domain_age_days":
                existing = domain_result["flags"].get(k)
                if existing is None or v < existing:
                    domain_result["flags"][k] = v
            elif k == "trusted_domain":
                domain_result["flags"][k] = domain_result["flags"].get(k, True) and v
            elif k == "phishing_path_keywords":
                existing = domain_result["flags"].get(k, 0)
                domain_result["flags"][k] = max(existing, v) if isinstance(existing, int) else v
            else:
                domain_result["flags"][k] = domain_result["flags"].get(k, False) or v

    # Layer 3 — Behavioral
    behavioral_score, behavioral_results, behavioral_cats = run_behavioral_analysis(analysis_text)

    # Layer 4 — Score & classify (weighted)
    risk_score, rank, emoji, weight_breakdown = calculate_risk_score(
        threat_intel_result["triggered"],
        domain_result["flags"],
        behavioral_score,
        behavioral_cats
    )

    # Trusted domain bypass
    if (domain_result["flags"].get("trusted_domain")
            and not threat_intel_result["triggered"]
            and behavioral_score < 10):
        risk_score = 0
        rank = "Safe"
        emoji = "🛡️"

    # Layer 0 — Learning Memory (overrides everything if matched)
    memory_result = memory_check(urls_to_check, analysis_text)
    memory_overridden = False
    if memory_result["matched"]:
        logger.info(f"  🧠 Memory match! Verdict override → {memory_result['verdict']}")
        memory_overridden = True
        if memory_result["verdict"] == "Scam":
            risk_score = max(risk_score, 85)
            rank = "Scam"
            emoji = "🚨"
        elif memory_result["verdict"] == "Safe":
            risk_score = 0
            rank = "Safe"
            emoji = "🛡️"

    # Build layer breakdown for the frontend
    layers = {
        "learning_memory": {
            "triggered": memory_result["matched"],
            "source": memory_result.get("source"),
            "detail": memory_result.get("detail", ""),
            "overridden": memory_overridden
        },
        "threat_intel": {
            "triggered": threat_intel_result["triggered"],
            "source": threat_intel_result.get("source"),
            "detail": threat_intel_result.get("detail", ""),
            "sources_checked": threat_intel_result.get("sources_checked", [])
        },
        "domain_analysis": {
            "triggered": bool(domain_result["signals"]),
            "signals": domain_result["signals"]
        },
        "behavioral": {
            "triggered": behavioral_score > 0,
            "score": behavioral_score,
            "categories": behavioral_results,
            "signals": []
        },
        "classification": rank
    }
    # Flatten behavioral signals for display
    for cat, info in behavioral_results.items():
        layers["behavioral"]["signals"].append(info.get("detail", cat))

    elapsed = round((time.time() - start_time) * 1000)

    # Console logging summary
    rank_colors = {"Safe": "\033[32m", "Suspicious": "\033[33m", "Scam": "\033[31m"}
    rc = rank_colors.get(rank, "")
    logger.info(f"  📊 Result: {rc}{rank}\033[0m | Score: {risk_score}/100 | Time: {elapsed}ms")
    if behavioral_results:
        cats = ", ".join(behavioral_results.keys())
        logger.info(f"  🧠 Behavioral categories: {cats}")
    if domain_result["signals"]:
        logger.info(f"  🌐 Domain signals: {len(domain_result['signals'])} found")

    # If the user is logged in, save the scan result to their history
    if current_user.is_authenticated:
        try:
            # Collect signals for "Explain Result"
            all_signals = []
            if threat_intel_result["triggered"]:
                all_signals.append({"layer": "Threat Intel", "detail": threat_intel_result.get("detail", "Found in known threat databases")})
            
            # Domain signals
            for s in domain_result.get("signals", []): 
                all_signals.append({"layer": "Domain", "detail": s})
            
            # Behavioral signals
            for cat, info in behavioral_results.items():
                all_signals.append({"layer": "Behavioral", "detail": info.get("detail", cat)})

            new_scan = ScanHistory(
                user_id=current_user.id,
                verdict=rank,
                risk_score=risk_score,
                signals_json=json.dumps(all_signals, default=str)
            )
            db.session.add(new_scan)
            db.session.commit()
            logger.info(f"  💾 Scan saved to history with {len(all_signals)} signals for user {current_user.email}")
        except Exception as e:
            db.session.rollback()
            logger.error(f"  ❌ Failed to save scan to history: {e}")

    return jsonify({
        "risk_score": risk_score,
        "rank": rank,
        "emoji": emoji,
        "confidence": weight_breakdown.get("confidence", 50),
        "elapsed_ms": elapsed,
        "weight_breakdown": weight_breakdown,
        "layers": layers
    })


# ---------------------------------------------------------------------------
# User Feedback — dynamic, privacy-preserving correction system
# ---------------------------------------------------------------------------
# Correction log — anonymous signals only (no user content stored)
CORRECTIONS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "correction_signals.json")

_correction_signals = {
    "corrections": [],          # [{original, corrected, signal_type, ts}]
    "confidence_validations": 0,
    "total_feedback": 0,
    "weight_adjustments": {}
}

def _load_corrections():
    global _correction_signals
    if os.path.exists(CORRECTIONS_FILE):
        try:
            with open(CORRECTIONS_FILE, "r", encoding="utf-8") as f:
                _correction_signals = json.load(f)
            logger.info(f"📊 Loaded {len(_correction_signals.get('corrections', []))} correction signals")
        except Exception as e:
            logger.warning(f"Could not load corrections: {e}")

def _save_corrections():
    try:
        with open(CORRECTIONS_FILE, "w", encoding="utf-8") as f:
            json.dump(_correction_signals, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Failed to save corrections: {e}")

def _apply_weight_adjustment(original_verdict: str, corrected_verdict: str, signal_type: str):
    """
    Micro-adjust LAYER_WEIGHTS based on correction patterns.
    If a layer caused a false positive (over-scored), slightly reduce its weight.
    If a layer missed a threat (under-scored), slightly increase its weight.
    Adjustments are capped to maintain system stability.
    """
    global LAYER_WEIGHTS
    STEP = 0.008        # Small step per correction
    MIN_W = 0.10        # No layer can drop below 10%
    MAX_W = 0.60        # No layer can rise above 60%

    # Determine which layer to adjust based on detected signal type
    layer_map = {
        "threat_intel": "threat_intel",
        "domain": "domain_analysis",
        "behavioral": "behavioral",
    }

    target_layer = layer_map.get(signal_type)
    if not target_layer:
        return  # Unknown signal type, skip

    was_over = original_verdict in ("Scam", "Suspicious") and corrected_verdict == "Safe"
    was_under = original_verdict == "Safe" and corrected_verdict in ("Scam", "Suspicious")
    was_mismatch = original_verdict != corrected_verdict and not was_over and not was_under

    if was_over:
        # Layer over-contributed → reduce its weight, redistribute to others
        reduction = min(STEP, LAYER_WEIGHTS[target_layer] - MIN_W)
        if reduction > 0:
            LAYER_WEIGHTS[target_layer] -= reduction
            others = [k for k in LAYER_WEIGHTS if k != target_layer]
            for o in others:
                LAYER_WEIGHTS[o] += reduction / len(others)
            logger.info(f"   ⚙️ Reduced '{target_layer}' weight by {reduction:.3f} (was over-scoring)")
    elif was_under:
        # Layer under-contributed → increase its weight, take from others
        increase = min(STEP, MAX_W - LAYER_WEIGHTS[target_layer])
        if increase > 0:
            LAYER_WEIGHTS[target_layer] += increase
            others = [k for k in LAYER_WEIGHTS if k != target_layer]
            for o in others:
                LAYER_WEIGHTS[o] -= increase / len(others)
            logger.info(f"   ⚙️ Increased '{target_layer}' weight by {increase:.3f} (was under-scoring)")
    elif was_mismatch:
        # E.g., Suspicious→Scam or Scam→Suspicious — mild adjustment
        adj = STEP * 0.5
        increase = min(adj, MAX_W - LAYER_WEIGHTS[target_layer])
        if increase > 0:
            LAYER_WEIGHTS[target_layer] += increase
            others = [k for k in LAYER_WEIGHTS if k != target_layer]
            for o in others:
                LAYER_WEIGHTS[o] -= increase / len(others)

    # Clamp all weights and re-normalize to sum to 1.0
    for k in LAYER_WEIGHTS:
        LAYER_WEIGHTS[k] = max(MIN_W, min(MAX_W, LAYER_WEIGHTS[k]))
    total = sum(LAYER_WEIGHTS.values())
    for k in LAYER_WEIGHTS:
        LAYER_WEIGHTS[k] = round(LAYER_WEIGHTS[k] / total, 4)

    logger.info(f"   ⚙️ Current weights: {LAYER_WEIGHTS}")


VALID_FEEDBACK = ("correct", "actually_safe", "actually_suspicious", "actually_scam")

@app.route("/feedback", methods=["POST"])
def feedback():
    """
    Feedback system with learning memory.
    - "correct" → validates confidence only (no weight changes, no content stored)
    - corrections → adjusts weights, extracts scam signatures, persists to learning memory
    """
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "Invalid JSON"}), 400

    fb_type = data.get("feedback", "").strip()
    original_verdict = data.get("original_verdict", "").strip()
    risk_score = data.get("risk_score", "?")
    signal_type = data.get("signal_type", "").strip()   # "threat_intel", "domain", "behavioral"
    comment = data.get("comment", "").strip()[:500]

    if fb_type not in VALID_FEEDBACK:
        return jsonify({"error": "Invalid feedback type"}), 400

    _correction_signals["total_feedback"] = _correction_signals.get("total_feedback", 0) + 1

    logger.info(f"{'='*50}")

    if fb_type == "correct":
        # ── Confidence validation only ──────────────────────────────────
        _correction_signals["confidence_validations"] = _correction_signals.get("confidence_validations", 0) + 1
        logger.info(f"✅ CORRECT feedback — verdict '{original_verdict}' validated")
        logger.info(f"   Confidence validations total: {_correction_signals['confidence_validations']}")
        _save_corrections()
        logger.info(f"{'='*50}")
        return jsonify({
            "status": "ok",
            "message": "Thank you! Your confirmation strengthens our detection confidence.",
            "learned": False,
            "action": "confidence_validated"
        })

    # ── Correction feedback ─────────────────────────────────────────
    corrected_map = {
        "actually_safe": "Safe",
        "actually_suspicious": "Suspicious",
        "actually_scam": "Scam"
    }
    corrected_verdict = corrected_map.get(fb_type, "")

    logger.info(f"🔄 CORRECTION: {original_verdict} → {corrected_verdict}")
    logger.info(f"   Signal type: {signal_type or 'unspecified'}")
    logger.info(f"   Risk score: {risk_score}")
    if comment:
        logger.info(f"   Comment: {comment}")

    # Store anonymous correction signal (NO user content)
    signal = {
        "original_verdict": original_verdict,
        "corrected_verdict": corrected_verdict,
        "detected_signal_type": signal_type or "unknown",
        "timestamp": datetime.utcnow().isoformat()
    }
    _correction_signals.setdefault("corrections", []).append(signal)

    # Apply micro weight adjustment
    if signal_type:
        _apply_weight_adjustment(original_verdict, corrected_verdict, signal_type)
        _correction_signals["weight_adjustments"] = {
            k: round(v, 4) for k, v in LAYER_WEIGHTS.items()
        }

    # ── LEARNING MEMORY — persist correction + extract scam signatures ──
    content = data.get("content", "").strip()
    content_type = data.get("content_type", "").strip()
    learned_sigs = False
    if content and content_type:
        # Map feedback type to verdict for memory_learn
        verdict_for_learn = ""
        if fb_type == "actually_scam":
            verdict_for_learn = "scam"
        elif fb_type == "actually_safe":
            verdict_for_learn = "safe"
        elif fb_type == "actually_suspicious":
            verdict_for_learn = "scam"  # Treat suspicious correction as scam for learning

        if verdict_for_learn:
            memory_learn(
                content=content,
                content_type=content_type,
                correct_verdict=verdict_for_learn,
                original_rank=original_verdict,
                original_score=risk_score,
                comment=comment
            )
            learned_sigs = True
            logger.info(f"   🧠 Content persisted to learning memory (verdict: {verdict_for_learn})")
    else:
        logger.info(f"   ⚠️ No content received with feedback — cannot persist to learning memory")

    _save_corrections()
    logger.info(f"{'='*50}")

    # If user is logged in, associate with feedback log
    user_id = current_user.id if current_user.is_authenticated else None
    try:
        new_feedback = FeedbackLog(
            user_id=user_id,
            original_verdict=original_verdict,
            corrected_verdict=corrected_verdict
        )
        db.session.add(new_feedback)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"  ❌ Failed to save feedback to database: {e}")

    return jsonify({
        "status": "ok",
        "message": "Thank you! Your correction has been recorded and will improve future detection accuracy.",
        "learned": True,
        "learned_signatures": learned_sigs,
        "action": "weights_adjusted"
    })


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
@app.route("/health", methods=["GET"])
def health():
    with _memory_lock:
        learned_sigs = _learned_memory.get("learned_signatures", [])
        mem_stats = {
            "scam_urls": len(_learned_memory.get("known_scam_urls", {})),
            "safe_urls": len(_learned_memory.get("known_safe_urls", {})),
            "scam_patterns": len(_learned_memory.get("known_scam_patterns", {})),
            "safe_patterns": len(_learned_memory.get("known_safe_patterns", {})),
            "learned_signatures": len(learned_sigs) if isinstance(learned_sigs, list) else 0,
            "total_feedback": _learned_memory.get("stats", {}).get("total_feedback", 0),
            "corrections": _learned_memory.get("stats", {}).get("corrections", 0)
        }
    return jsonify({
        "status": "ok",
        "ocr_available": OCR_AVAILABLE,
        "whois_available": WHOIS_AVAILABLE,
        "learning_memory": mem_stats,
        "correction_signals": {
            "total_corrections": len(_correction_signals.get("corrections", [])),
            "confidence_validations": _correction_signals.get("confidence_validations", 0),
            "total_feedback": _correction_signals.get("total_feedback", 0),
            "current_weights": {k: round(v, 4) for k, v in LAYER_WEIGHTS.items()}
        }
    })


# ---------------------------------------------------------------------------
# Start background threads & run
# ---------------------------------------------------------------------------
def _reset_canonical_weights():
    """Reset LAYER_WEIGHTS to canonical defaults on every startup.
    Prevents weight drift from past correction_signals corrupting detection."""
    global LAYER_WEIGHTS
    LAYER_WEIGHTS["threat_intel"] = 0.45
    LAYER_WEIGHTS["domain_analysis"] = 0.30
    LAYER_WEIGHTS["behavioral"] = 0.25
    logger.info(f"⚖️  Layer weights reset to canonical defaults: {LAYER_WEIGHTS}")


if __name__ == "__main__":
    logger.info("🛡️  Cyber Sentinel starting...")
    logger.info(f"  OCR available: {OCR_AVAILABLE}")
    logger.info(f"  WHOIS available: {WHOIS_AVAILABLE}")
    # Load learning memory and correction signals
    _load_memory()
    _load_corrections()
    # Reset weights to canonical defaults (prevents drift from past corrections)
    _reset_canonical_weights()
    # Create database and tables
    with app.app_context():
        db.create_all()
    # Start OpenPhish feed loader in background
    t = threading.Thread(target=_load_openphish, daemon=True)
    t.start()
    app.run(debug=True, host="127.0.0.1", port=5000)
