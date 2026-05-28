"""
Suspicious Link & Tracker Analyzer
Digital Rights Foundation — Cyber Harassment Helpline Tool
"""

import streamlit as st
import requests
import json
import re
import socket
import datetime
from urllib.parse import urlparse
from bs4 import BeautifulSoup

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

# ─────────────────────────────────────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Link Analyzer — DRF",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ─────────────────────────────────────────────────────────────────────────────
# GLOBAL CSS OVERRIDE
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Fira+Code:wght@300;400;500;600&family=Rajdhani:wght@400;500;600;700&family=Space+Grotesk:wght@300;400;500;600&display=swap');

/* ── Reset & Root ── */
:root {
    --bg:          #090a0f;
    --surface:     #12141d;
    --surface2:    #1a1d2e;
    --border:      #2d3248;
    --border2:     #3d4268;
    --text:        #c8cfe8;
    --text-dim:    #5a6380;
    --text-bright: #e8eaf6;
    --neon-red:    #ff2a2a;
    --neon-amber:  #ffb800;
    --neon-cyan:   #00f0ff;
    --neon-green:  #00ff88;
    --neon-purple: #b060ff;
    --font-mono:   'Fira Code', 'Courier New', monospace;
    --font-head:   'Rajdhani', sans-serif;
    --font-body:   'Space Grotesk', sans-serif;
    --radius:      10px;
    --glow-red:    0 0 18px rgba(255,42,42,0.35);
    --glow-amber:  0 0 18px rgba(255,184,0,0.35);
    --glow-cyan:   0 0 18px rgba(0,240,255,0.3);
    --glow-green:  0 0 18px rgba(0,255,136,0.25);
    --card-shadow: 0 4px 32px rgba(0,0,0,0.55);
}

/* ── Hide Streamlit chrome ── */
#MainMenu, header[data-testid="stHeader"], footer,
div[data-testid="stToolbar"], div[data-testid="stDecoration"],
.stDeployButton { display: none !important; }

/* ── Base ── */
html, body, [data-testid="stAppViewContainer"],
[data-testid="stMain"], .main, .block-container {
    background: var(--bg) !important;
    color: var(--text) !important;
    font-family: var(--font-body) !important;
}

.block-container { padding: 2rem 2.5rem 4rem !important; max-width: 1200px !important; }

/* ── Typography ── */
h1,h2,h3,h4 { font-family: var(--font-head) !important; letter-spacing: 0.05em; }

/* ── Scanline overlay on body ── */
[data-testid="stAppViewContainer"]::before {
    content: '';
    position: fixed; inset: 0; z-index: 0; pointer-events: none;
    background: repeating-linear-gradient(
        0deg,
        transparent,
        transparent 2px,
        rgba(0,240,255,0.018) 2px,
        rgba(0,240,255,0.018) 4px
    );
}

/* ── Input ── */
div[data-testid="stTextInput"] input,
div[data-testid="stTextArea"] textarea {
    background: var(--surface) !important;
    border: 1px solid var(--border) !important;
    border-radius: var(--radius) !important;
    color: var(--neon-cyan) !important;
    font-family: var(--font-mono) !important;
    font-size: 0.88rem !important;
    padding: 0.65rem 1rem !important;
    caret-color: var(--neon-cyan);
    transition: border 0.25s, box-shadow 0.25s;
}
div[data-testid="stTextInput"] input:focus,
div[data-testid="stTextArea"] textarea:focus {
    border-color: var(--neon-cyan) !important;
    box-shadow: var(--glow-cyan) !important;
    outline: none !important;
}
div[data-testid="stTextInput"] label,
div[data-testid="stTextArea"] label {
    color: var(--text-dim) !important;
    font-family: var(--font-mono) !important;
    font-size: 0.75rem !important;
    letter-spacing: 0.08em !important;
    text-transform: uppercase !important;
}

/* ── Buttons ── */
div[data-testid="stButton"] button {
    background: transparent !important;
    border: 1px solid var(--neon-cyan) !important;
    border-radius: var(--radius) !important;
    color: var(--neon-cyan) !important;
    font-family: var(--font-head) !important;
    font-size: 1rem !important;
    font-weight: 600 !important;
    letter-spacing: 0.08em !important;
    padding: 0.55rem 1.8rem !important;
    transition: all 0.2s !important;
    cursor: pointer !important;
    text-transform: uppercase !important;
}
div[data-testid="stButton"] button:hover {
    background: rgba(0,240,255,0.08) !important;
    box-shadow: var(--glow-cyan) !important;
}
div[data-testid="stDownloadButton"] button {
    background: rgba(0,255,136,0.07) !important;
    border: 1px solid var(--neon-green) !important;
    color: var(--neon-green) !important;
    border-radius: var(--radius) !important;
    font-family: var(--font-head) !important;
    font-size: 0.95rem !important;
    font-weight: 600 !important;
    letter-spacing: 0.08em !important;
    text-transform: uppercase !important;
    transition: all 0.2s !important;
}
div[data-testid="stDownloadButton"] button:hover {
    background: rgba(0,255,136,0.14) !important;
    box-shadow: var(--glow-green) !important;
}

/* ── Divider ── */
hr { border-color: var(--border) !important; margin: 1.5rem 0 !important; }

/* ── Spinner ── */
div[data-testid="stSpinner"] { color: var(--neon-cyan) !important; }
div[data-testid="stSpinner"] > div { border-top-color: var(--neon-cyan) !important; }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# HELPER: render HTML cards
# ─────────────────────────────────────────────────────────────────────────────
def card(content_html: str, accent: str = "#2d3248", glow: str = "none") -> str:
    return f"""
    <div style="
        background: #12141d;
        border: 1px solid {accent};
        border-radius: 10px;
        padding: 1.2rem 1.5rem;
        margin: 0.6rem 0;
        box-shadow: {glow}, 0 4px 32px rgba(0,0,0,0.55);
        font-family: 'Fira Code', monospace;
        font-size: 0.82rem;
        color: #c8cfe8;
        line-height: 1.7;
    ">{content_html}</div>"""

def label(text, color="#5a6380"):
    return f'<span style="color:{color};text-transform:uppercase;letter-spacing:.08em;font-size:.7rem;">{text}</span>'

def mono(text, color="#c8cfe8"):
    return f'<span style="font-family:\'Fira Code\',monospace;color:{color};">{text}</span>'

def badge(text, color, bg=None):
    bg = bg or color + "22"
    return (f'<span style="display:inline-block;background:{bg};color:{color};'
            f'border:1px solid {color};border-radius:5px;padding:1px 9px;'
            f'font-size:.72rem;letter-spacing:.06em;font-weight:600;">{text}</span>')

# ─────────────────────────────────────────────────────────────────────────────
# CORE LOGIC
# ─────────────────────────────────────────────────────────────────────────────

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

KNOWN_TRACKERS = [
    ("Google Analytics",     ["google-analytics.com", "gtag/js", "ga.js", "analytics.js"]),
    ("Google Tag Manager",   ["googletagmanager.com", "gtm.js"]),
    ("Facebook Pixel",       ["connect.facebook.net", "fbevents.js", "facebook-pixel"]),
    ("Hotjar",               ["hotjar.com", "hotjar"]),
    ("Mixpanel",             ["mixpanel.com", "mixpanel"]),
    ("Segment",              ["segment.com", "segment.io", "analytics.min.js"]),
    ("Amplitude",            ["amplitude.com", "amplitude"]),
    ("TikTok Pixel",         ["analytics.tiktok.com", "tiktok-pixel"]),
    ("Twitter/X Pixel",      ["static.ads-twitter.com", "twq("]),
    ("Microsoft Clarity",    ["clarity.ms", "microsoft-clarity"]),
    ("Intercom",             ["intercom.io", "intercom"]),
    ("DoubleClick",          ["doubleclick.net", "dc.js"]),
    ("Amazon Pixel",         ["assoc-amazon.com", "amazon-adsystem"]),
    ("LinkedIn Insight",     ["snap.licdn.com", "linkedin insight"]),
    ("Yandex Metrica",       ["mc.yandex.ru", "yandex-metrica"]),
]


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def unshorten_url(url: str, timeout: int = 10):
    """Follow all redirects, return final URL and redirect chain."""
    try:
        resp = requests.head(url, allow_redirects=True, timeout=timeout, headers=HEADERS)
        chain = [r.url for r in resp.history] + [resp.url]
        return resp.url, chain, resp.status_code
    except requests.exceptions.SSLError:
        # Retry without verification as last resort (flag it)
        try:
            resp = requests.head(url, allow_redirects=True, timeout=timeout,
                                 headers=HEADERS, verify=False)
            chain = [r.url for r in resp.history] + [resp.url]
            return resp.url, chain, resp.status_code
        except Exception as e:
            return None, [], str(e)
    except Exception as e:
        return None, [], str(e)


def threat_heuristics(url: str) -> list:
    """Return list of (severity, description) tuples."""
    flags = []
    parsed = urlparse(url)

    # HTTP check
    if parsed.scheme == "http":
        flags.append(("critical", "Connection is unencrypted (HTTP). Data can be intercepted."))

    # Raw IP address
    host = parsed.hostname or ""
    try:
        socket.inet_aton(host)
        flags.append(("critical", f"URL uses a raw IP address ({host}) instead of a domain name."))
    except Exception:
        pass

    # IPv6
    if host.startswith("[") or (host.count(":") > 1):
        flags.append(("warning", "URL contains an IPv6 address, uncommon in legitimate links."))

    # Excess hyphens
    hyphen_count = host.count("-")
    if hyphen_count >= 3:
        flags.append(("warning", f"Domain contains {hyphen_count} hyphens — common in typosquat/phishing domains."))

    # Excess subdomains
    subdomain_parts = host.split(".")
    if len(subdomain_parts) > 4:
        flags.append(("warning", f"URL has {len(subdomain_parts) - 2} subdomains — may be used to spoof a trusted brand."))

    # Very long URL
    if len(url) > 200:
        flags.append(("warning", f"URL is unusually long ({len(url)} chars) — may hide the real destination."))

    # Suspicious keywords in path/query
    sus_keywords = ["login", "signin", "account", "verify", "secure", "update",
                    "confirm", "banking", "paypal", "password", "credential"]
    lower_url = url.lower()
    hits = [kw for kw in sus_keywords if kw in lower_url]
    if hits:
        flags.append(("warning", f"URL contains phishing-related keywords: {', '.join(hits)}"))

    # URL encoding abuse
    if url.count("%") > 5:
        flags.append(("warning", f"URL contains heavy percent-encoding ({url.count('%')} instances) — may be obfuscating content."))

    # @ symbol (credential embedding)
    if "@" in parsed.netloc:
        flags.append(("critical", "URL contains '@' in the host — may be using credential-embedding to spoof domain."))

    # Mixed unicode / punycode
    if "xn--" in host:
        flags.append(("critical", "Punycode (xn--) detected in domain — possible IDN homograph attack (fake look-alike characters)."))

    return flags


def scrape_metadata(url: str, timeout: int = 12):
    """Fetch <head>, extract title, description, and trackers."""
    try:
        resp = requests.get(url, timeout=timeout, headers=HEADERS, stream=True)
        resp.raise_for_status()
        # Only read first 200 KB to avoid downloading massive pages
        content = b""
        for chunk in resp.iter_content(chunk_size=8192):
            content += chunk
            if len(content) > 200_000:
                break
        soup = BeautifulSoup(content, "html.parser")

        title = soup.title.string.strip() if soup.title and soup.title.string else "N/A"

        meta_desc = "N/A"
        for tag in soup.find_all("meta"):
            if tag.get("name", "").lower() == "description":
                meta_desc = tag.get("content", "N/A")[:300]
                break

        # Collect all script sources + inline script text
        scripts_raw = []
        for tag in soup.find_all("script"):
            src = tag.get("src", "")
            if src:
                scripts_raw.append(src)
            if tag.string:
                scripts_raw.append(tag.string[:500])

        full_text = " ".join(scripts_raw).lower()

        trackers_found = []
        for name, patterns in KNOWN_TRACKERS:
            if any(p.lower() in full_text for p in patterns):
                trackers_found.append(name)

        # Collect external script domains
        external_scripts = []
        for tag in soup.find_all("script", src=True):
            src = tag["src"]
            if src.startswith("//") or src.startswith("http"):
                try:
                    dom = urlparse(src if src.startswith("http") else "https:" + src).netloc
                    if dom:
                        external_scripts.append(dom)
                except Exception:
                    pass
        external_scripts = list(dict.fromkeys(external_scripts))  # deduplicate

        return {
            "title": title,
            "description": meta_desc,
            "trackers": trackers_found,
            "external_scripts": external_scripts[:20],
            "http_status": resp.status_code,
            "content_type": resp.headers.get("Content-Type", "unknown"),
            "server": resp.headers.get("Server", "unknown"),
            "error": None,
        }
    except requests.exceptions.Timeout:
        return {"error": "Request timed out. The server may be down or blocking automated requests."}
    except requests.exceptions.SSLError as e:
        return {"error": f"SSL/TLS certificate error: {e}"}
    except requests.exceptions.ConnectionError as e:
        return {"error": f"Connection failed: {e}"}
    except Exception as e:
        return {"error": f"Unexpected error: {e}"}


def check_domain_age(url: str):
    """Return domain creation date and age in days. Requires python-whois."""
    if not WHOIS_AVAILABLE:
        return None, None, "python-whois library not installed."
    try:
        domain = urlparse(url).hostname or ""
        # Strip subdomains for whois
        parts = domain.split(".")
        if len(parts) > 2:
            domain = ".".join(parts[-2:])
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation is None:
            return None, None, "Creation date not available in WHOIS record."
        if not isinstance(creation, datetime.datetime):
            creation = datetime.datetime(creation.year, creation.month, creation.day)
        age_days = (datetime.datetime.utcnow() - creation).days
        return creation, age_days, None
    except Exception as e:
        return None, None, f"WHOIS lookup failed: {e}"


# ─────────────────────────────────────────────────────────────────────────────
# UI — HEADER
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<div style="
    border-bottom: 1px solid #2d3248;
    padding: 1.2rem 0 1.4rem 0;
    margin-bottom: 1.8rem;
    display: flex;
    align-items: center;
    gap: 1rem;
">
    <div style="
        width: 42px; height: 42px;
        border: 2px solid #00f0ff;
        border-radius: 8px;
        display: flex; align-items: center; justify-content: center;
        box-shadow: 0 0 18px rgba(0,240,255,0.4);
        font-size: 1.3rem;
        flex-shrink: 0;
    ">🔍</div>
    <div>
        <div style="
            font-family: 'Rajdhani', sans-serif;
            font-size: 1.55rem;
            font-weight: 700;
            color: #e8eaf6;
            letter-spacing: 0.07em;
            text-transform: uppercase;
            line-height: 1.1;
        ">Suspicious Link & Tracker Analyzer</div>
        <div style="
            font-family: 'Fira Code', monospace;
            font-size: 0.72rem;
            color: #5a6380;
            letter-spacing: 0.1em;
            margin-top: 2px;
        ">Digital Rights Foundation — Helpline Forensics Tool v2.0</div>
    </div>
    <div style="
        margin-left: auto;
        background: rgba(0,240,255,0.06);
        border: 1px solid #00f0ff33;
        border-radius: 8px;
        padding: 0.3rem 0.85rem;
        font-family: 'Fira Code', monospace;
        font-size: 0.72rem;
        color: #00f0ff;
        letter-spacing: 0.06em;
    ">● SECURE SESSION</div>
</div>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# UI — INPUT
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<div style="
    font-family: 'Rajdhani', sans-serif;
    font-size: 1rem;
    color: #5a6380;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    margin-bottom: 0.4rem;
">// Target URL Input</div>
""", unsafe_allow_html=True)

col_input, col_btn = st.columns([5, 1])
with col_input:
    raw_url = st.text_input(
        label="Enter URL to analyze",
        placeholder="https://suspicious-link.example.com/redirect?id=xyz",
        label_visibility="collapsed",
    )
with col_btn:
    st.markdown("<div style='height:0.05rem'></div>", unsafe_allow_html=True)
    analyze = st.button("⚡ Analyze", use_container_width=True)

st.markdown("""
<div style="
    font-family: 'Fira Code', monospace;
    font-size: 0.68rem;
    color: #3d4268;
    margin-top: 0.4rem;
    letter-spacing: 0.05em;
">⚠ This tool sends real network requests. Only analyze URLs relevant to active casework.</div>
""", unsafe_allow_html=True)

st.markdown("<hr>", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────
if analyze and raw_url.strip():
    url = normalize_url(raw_url.strip())
    results = {"input_url": url, "timestamp": datetime.datetime.utcnow().isoformat() + "Z"}

    # ── 1. Unshorten ─────────────────────────────────────────────────────────
    st.markdown("""
    <div style="font-family:'Rajdhani',sans-serif;font-size:1.05rem;
    color:#5a6380;text-transform:uppercase;letter-spacing:.1em;
    margin-bottom:.5rem;">// 01 — URL Resolution</div>""", unsafe_allow_html=True)

    with st.spinner("Following redirects…"):
        final_url, chain, status = unshorten_url(url)

    results["final_url"] = final_url
    results["redirect_chain"] = chain
    results["http_status"] = status

    if final_url:
        redirect_html = ""
        if len(chain) > 1:
            for i, hop in enumerate(chain):
                arrow = "┌" if i == 0 else ("└" if i == len(chain) - 1 else "├")
                col = "#5a6380" if i < len(chain) - 1 else "#00f0ff"
                redirect_html += (
                    f'<div>{arrow} <span style="color:{col};font-size:.8rem;">{hop}</span></div>'
                )
        else:
            redirect_html = f'<div style="color:#00f0ff;">{final_url}</div>'

        changed = final_url != url
        diff_badge = (badge("REDIRECTED", "#ffb800") + "&nbsp;") if changed else (badge("DIRECT", "#00f0ff") + "&nbsp;")

        st.markdown(card(
            f'{label("Final Destination")} {diff_badge}<br>'
            f'<div style="margin-top:.5rem">{redirect_html}</div>'
            + (f'<div style="margin-top:.6rem;color:#5a6380;font-size:.72rem;">'
               f'Total hops: {len(chain) - 1 if len(chain) > 1 else 0} &nbsp;|&nbsp; '
               f'HTTP status: <span style="color:#00f0ff;">{status}</span></div>' if len(chain) > 1 else ""),
            accent="#2d3248", glow="0 0 18px rgba(0,240,255,0.12)"
        ), unsafe_allow_html=True)
    else:
        st.markdown(card(
            f'{badge("UNREACHABLE", "#ff2a2a")}<br>'
            f'<span style="color:#ff2a2a;margin-top:.5rem;display:block;">{status}</span>',
            accent="#ff2a2a33", glow="0 0 14px rgba(255,42,42,0.3)"
        ), unsafe_allow_html=True)

    # ── 2. Threat Heuristics ─────────────────────────────────────────────────
    st.markdown("""
    <div style="font-family:'Rajdhani',sans-serif;font-size:1.05rem;
    color:#5a6380;text-transform:uppercase;letter-spacing:.1em;
    margin:.9rem 0 .5rem;">// 02 — Threat Heuristics Engine</div>""", unsafe_allow_html=True)

    analyze_target = final_url if final_url else url
    flags = threat_heuristics(analyze_target)
    results["threat_flags"] = [{"severity": s, "description": d} for s, d in flags]

    if not flags:
        st.markdown(card(
            f'{badge("NO THREATS DETECTED", "#00ff88")} &nbsp;'
            f'<span style="color:#5a6380;font-size:.78rem;margin-left:.4rem;">'
            f'No heuristic flags triggered for this URL structure.</span>',
            accent="#00ff8822"
        ), unsafe_allow_html=True)
    else:
        for severity, desc in flags:
            color = "#ff2a2a" if severity == "critical" else "#ffb800"
            icon = "🔴" if severity == "critical" else "🟡"
            glow = "0 0 16px rgba(255,42,42,0.25)" if severity == "critical" else "0 0 16px rgba(255,184,0,0.2)"
            st.markdown(card(
                f'{icon} {badge(severity.upper(), color)} &nbsp;'
                f'<span style="color:#c8cfe8;font-size:.83rem;margin-left:.4rem;">{desc}</span>',
                accent=color + "44", glow=glow
            ), unsafe_allow_html=True)

    # ── 3. Metadata & Trackers ───────────────────────────────────────────────
    st.markdown("""
    <div style="font-family:'Rajdhani',sans-serif;font-size:1.05rem;
    color:#5a6380;text-transform:uppercase;letter-spacing:.1em;
    margin:.9rem 0 .5rem;">// 03 — Metadata & Tracker Extraction</div>""", unsafe_allow_html=True)

    if final_url:
        with st.spinner("Scraping page metadata…"):
            meta = scrape_metadata(final_url)
        results["metadata"] = meta

        if meta.get("error"):
            st.markdown(card(
                f'{badge("SCRAPE ERROR", "#ff2a2a")}<br>'
                f'<span style="color:#ff6060;margin-top:.4rem;display:block;">{meta["error"]}</span>',
                accent="#ff2a2a33"
            ), unsafe_allow_html=True)
        else:
            # Page info
            st.markdown(card(
                f'{label("Page Title")}<br>'
                f'<span style="color:#e8eaf6;font-size:.88rem;">{meta["title"]}</span><br><br>'
                f'{label("Meta Description")}<br>'
                f'<span style="color:#c8cfe8;font-size:.82rem;">{meta["description"]}</span><br><br>'
                f'{label("HTTP Status")} <span style="color:#00f0ff;">{meta["http_status"]}</span> &nbsp;'
                f'{label("Content-Type")} <span style="color:#c8cfe8;">{meta["content_type"]}</span> &nbsp;'
                f'{label("Server")} <span style="color:#c8cfe8;">{meta["server"]}</span>',
                accent="#2d3248"
            ), unsafe_allow_html=True)

            # Trackers
            if meta["trackers"]:
                tracker_badges = " &nbsp;".join(
                    badge(t, "#ff2a2a") for t in meta["trackers"]
                )
                st.markdown(card(
                    f'{label("Known Trackers Found", "#ff2a2a")} '
                    f'{badge(str(len(meta["trackers"])) + " DETECTED", "#ff2a2a")}<br>'
                    f'<div style="margin-top:.5rem">{tracker_badges}</div>',
                    accent="#ff2a2a44", glow="0 0 18px rgba(255,42,42,0.2)"
                ), unsafe_allow_html=True)
            else:
                st.markdown(card(
                    f'{badge("NO KNOWN TRACKERS", "#00ff88")} '
                    f'<span style="color:#5a6380;font-size:.78rem;margin-left:.4rem;">'
                    f'No matched tracker signatures in script sources.</span>',
                    accent="#00ff8822"
                ), unsafe_allow_html=True)

            # External scripts
            if meta["external_scripts"]:
                script_list = "".join(
                    f'<div style="color:#5a6380;font-size:.75rem;">'
                    f'▸ <span style="color:#c8cfe8;">{s}</span></div>'
                    for s in meta["external_scripts"]
                )
                st.markdown(card(
                    f'{label("External Script Domains")} '
                    f'<span style="color:#ffb800;font-size:.72rem;">({len(meta["external_scripts"])} domains)</span>'
                    f'<div style="margin-top:.5rem">{script_list}</div>',
                    accent="#3d4268"
                ), unsafe_allow_html=True)
    else:
        st.markdown(card(
            f'{badge("SKIPPED", "#5a6380")} '
            f'<span style="color:#5a6380;">Metadata extraction skipped — URL was unreachable.</span>',
            accent="#2d3248"
        ), unsafe_allow_html=True)
        results["metadata"] = None

    # ── 4. Domain Age ────────────────────────────────────────────────────────
    st.markdown("""
    <div style="font-family:'Rajdhani',sans-serif;font-size:1.05rem;
    color:#5a6380;text-transform:uppercase;letter-spacing:.1em;
    margin:.9rem 0 .5rem;">// 04 — Domain Age & WHOIS</div>""", unsafe_allow_html=True)

    with st.spinner("Querying WHOIS registry…"):
        creation, age_days, whois_err = check_domain_age(analyze_target)

    results["domain_whois"] = {
        "creation_date": creation.isoformat() if creation else None,
        "age_days": age_days,
        "error": whois_err,
    }

    if whois_err:
        st.markdown(card(
            f'{badge("WHOIS UNAVAILABLE", "#5a6380")}<br>'
            f'<span style="color:#5a6380;font-size:.78rem;margin-top:.3rem;display:block;">{whois_err}</span>',
            accent="#2d3248"
        ), unsafe_allow_html=True)
    elif creation and age_days is not None:
        if age_days < 30:
            age_color = "#ff2a2a"
            age_badge = badge("HIGH RISK — NEW DOMAIN", "#ff2a2a")
            age_glow = "0 0 18px rgba(255,42,42,0.3)"
        elif age_days < 180:
            age_color = "#ffb800"
            age_badge = badge("CAUTION — YOUNG DOMAIN", "#ffb800")
            age_glow = "0 0 14px rgba(255,184,0,0.25)"
        else:
            age_color = "#00ff88"
            age_badge = badge("ESTABLISHED", "#00ff88")
            age_glow = "none"

        st.markdown(card(
            f'{label("Domain Created")} <span style="color:{age_color};">{creation.strftime("%Y-%m-%d")}</span> '
            f'&nbsp;&bull;&nbsp; {label("Age")} <span style="color:{age_color};">{age_days} days</span><br>'
            f'<div style="margin-top:.4rem">{age_badge}</div>',
            accent=age_color + "44", glow=age_glow
        ), unsafe_allow_html=True)

    # ── 5. Risk Summary ──────────────────────────────────────────────────────
    critical_count = sum(1 for f in flags if f[0] == "critical")
    warning_count  = sum(1 for f in flags if f[0] == "warning")
    tracker_count  = len((results.get("metadata") or {}).get("trackers", []))
    new_domain     = (age_days is not None and age_days < 30)

    if critical_count > 0 or new_domain:
        risk_level, risk_color, risk_glow = "CRITICAL THREAT", "#ff2a2a", "0 0 24px rgba(255,42,42,0.4)"
    elif warning_count > 0 or tracker_count > 0:
        risk_level, risk_color, risk_glow = "ELEVATED RISK", "#ffb800", "0 0 20px rgba(255,184,0,0.3)"
    else:
        risk_level, risk_color, risk_glow = "LOW RISK", "#00ff88", "0 0 18px rgba(0,255,136,0.25)"

    results["risk_summary"] = {
        "level": risk_level,
        "critical_flags": critical_count,
        "warning_flags": warning_count,
        "trackers_detected": tracker_count,
        "new_domain": new_domain,
    }

    st.markdown(f"""
    <div style="
        margin-top: 1.2rem;
        background: #12141d;
        border: 2px solid {risk_color};
        border-radius: 12px;
        padding: 1.2rem 1.6rem;
        box-shadow: {risk_glow}, 0 4px 32px rgba(0,0,0,0.55);
        display: flex;
        align-items: center;
        gap: 1.2rem;
    ">
        <div style="
            font-size: 2rem;
            width: 52px; height: 52px;
            border: 2px solid {risk_color};
            border-radius: 50%;
            display: flex; align-items: center; justify-content: center;
            box-shadow: {risk_glow};
            flex-shrink: 0;
        ">{'🚨' if 'CRITICAL' in risk_level else ('⚠️' if 'ELEVATED' in risk_level else '✅')}</div>
        <div>
            <div style="
                font-family: 'Rajdhani', sans-serif;
                font-size: 1.4rem;
                font-weight: 700;
                color: {risk_color};
                letter-spacing: 0.08em;
                text-transform: uppercase;
            ">Overall Risk: {risk_level}</div>
            <div style="
                font-family: 'Fira Code', monospace;
                font-size: 0.75rem;
                color: #5a6380;
                margin-top: 3px;
            ">Critical flags: {critical_count} &nbsp;|&nbsp; Warnings: {warning_count} &nbsp;|&nbsp; Trackers: {tracker_count} &nbsp;|&nbsp; New domain: {'YES' if new_domain else 'NO'}</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ── 6. Export ────────────────────────────────────────────────────────────
    st.markdown("<br>", unsafe_allow_html=True)

    col_dl1, col_dl2, _ = st.columns([1, 1, 3])

    json_export = json.dumps(results, indent=2, default=str)

    txt_lines = [
        "=" * 60,
        "DIGITAL RIGHTS FOUNDATION — LINK ANALYSIS REPORT",
        "=" * 60,
        f"Timestamp     : {results['timestamp']}",
        f"Input URL     : {results['input_url']}",
        f"Final URL     : {results.get('final_url', 'N/A')}",
        f"HTTP Status   : {results.get('http_status', 'N/A')}",
        "",
        "── REDIRECT CHAIN ──────────────────────────────────────",
    ]
    for i, hop in enumerate(results.get("redirect_chain", [])):
        txt_lines.append(f"  {i+1}. {hop}")
    txt_lines += [
        "",
        "── THREAT FLAGS ─────────────────────────────────────────",
    ]
    for f in results.get("threat_flags", []):
        txt_lines.append(f"  [{f['severity'].upper():8}] {f['description']}")
    if not results.get("threat_flags"):
        txt_lines.append("  None detected.")
    txt_lines += [
        "",
        "── METADATA ─────────────────────────────────────────────",
    ]
    meta_r = results.get("metadata") or {}
    txt_lines += [
        f"  Title       : {meta_r.get('title', 'N/A')}",
        f"  Description : {meta_r.get('description', 'N/A')}",
        f"  Trackers    : {', '.join(meta_r.get('trackers', [])) or 'None'}",
        f"  Ext Scripts : {', '.join(meta_r.get('external_scripts', [])) or 'None'}",
        "",
        "── WHOIS ────────────────────────────────────────────────",
    ]
    w = results.get("domain_whois", {})
    txt_lines += [
        f"  Created     : {w.get('creation_date', 'N/A')}",
        f"  Age (days)  : {w.get('age_days', 'N/A')}",
        f"  Error       : {w.get('error', 'None')}",
        "",
        "── RISK SUMMARY ─────────────────────────────────────────",
        f"  Level       : {results['risk_summary']['level']}",
        f"  Critical    : {results['risk_summary']['critical_flags']}",
        f"  Warnings    : {results['risk_summary']['warning_flags']}",
        f"  Trackers    : {results['risk_summary']['trackers_detected']}",
        f"  New Domain  : {'YES' if results['risk_summary']['new_domain'] else 'NO'}",
        "",
        "=" * 60,
        "END OF REPORT",
        "=" * 60,
    ]
    txt_export = "\n".join(txt_lines)

    with col_dl1:
        st.download_button(
            label="⬇ Export JSON",
            data=json_export,
            file_name=f"drf_analysis_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            use_container_width=True,
        )
    with col_dl2:
        st.download_button(
            label="⬇ Export TXT",
            data=txt_export,
            file_name=f"drf_analysis_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain",
            use_container_width=True,
        )

    st.markdown("""
    <div style="
        font-family: 'Fira Code', monospace;
        font-size: 0.68rem;
        color: #3d4268;
        margin-top: 0.5rem;
        letter-spacing: 0.05em;
    ">Reports are suitable for legal evidence logging. Include operator name and case ID before archiving.</div>
    """, unsafe_allow_html=True)

elif analyze and not raw_url.strip():
    st.markdown(card(
        f'{badge("INPUT REQUIRED", "#ffb800")} '
        f'<span style="color:#ffb800;margin-left:.4rem;">Please enter a URL before running analysis.</span>',
        accent="#ffb80044"
    ), unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# FOOTER
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<div style="
    margin-top: 3rem;
    padding-top: 1rem;
    border-top: 1px solid #2d3248;
    font-family: 'Fira Code', monospace;
    font-size: 0.67rem;
    color: #3d4268;
    letter-spacing: 0.06em;
    display: flex;
    justify-content: space-between;
">
    <span>Digital Rights Foundation — Internal Tooling</span>
    <span>No data is stored. All analysis runs locally.</span>
</div>
""", unsafe_allow_html=True)
