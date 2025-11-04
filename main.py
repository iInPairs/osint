#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Исправленный full working main.py for aiogram v3.
Фікси: кнопки, /info таймаути, адмін-команди, без зависань.
"""
import os
import re
import json
import socket
import ssl
import datetime as dt
from typing import Any, Dict, Optional, List
import tempfile
import logging
import asyncio
from datetime import datetime
from urllib.parse import urlparse, quote_plus, unquote
from urllib import robotparser
from html import escape as html_escape
from typing import Any, Dict, Optional, List, Tuple
import csv
from io import StringIO
from typing import Set


import aiohttp
import aiodns
import aiofiles
from bs4 import BeautifulSoup

# optional libs
try:
    import whois
except Exception:
    whois = None

try:
    import exifread
except Exception:
    exifread = None

from aiogram import Bot, Dispatcher, types, F, html
from aiogram.exceptions import TelegramAPIError, TelegramRetryAfter
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.utils.keyboard import InlineKeyboardBuilder
from aiogram.types import InputFile

# ---------------- Configuration ----------------
BOT_TOKEN = os.getenv("BOT_TOKEN", "8374692266:AAF-rN5Lp1u7U2UwIa6VPhbuQsiQES7Z3N8")
OWNER_ID = int(os.getenv("OWNER_ID", "8493326566"))

USER_AGENT = os.getenv("USER_AGENT", "OSINT-Aiogram-v3-Dispatcher/1.0 (+https://example.com)")
IP_API_URL = os.getenv("IP_API_URL", "http://ip-api.com/json/{}")
EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
DNS_TYPES = ("A", "MX", "NS", "TXT")

CACHE_FILE = os.getenv("CACHE_FILE", "osint_cache_v3_dispatcher.json")
REPORTS_DIR = os.getenv("REPORTS_DIR", "osint_reports_v3_dispatcher")
os.makedirs(REPORTS_DIR, exist_ok=True)

# in-memory store останніх результатів для кожного користувача
_last_results: Dict[int, Dict[str, Any]] = {}
# default ports for quick scan
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 587, 3306, 3389, 8080]


# rate-limit per user
RATE_WINDOW = int(os.getenv("RATE_WINDOW", "60"))
RATE_MAX = int(os.getenv("RATE_MAX", "12"))
_user_calls: Dict[int, List[float]] = {}

# blacklist
BLACKLIST_FILE = os.getenv("BLACKLIST_FILE", "blacklist.json")
_blacklist_lock = asyncio.Lock()

# logging
LOG_FILE = os.getenv("LOG_FILE", "bot_osint.log")
logging.basicConfig(level=logging.INFO, filename=LOG_FILE,
                    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("osint_dispatcher")

if not BOT_TOKEN:
    logger.error("BOT_TOKEN required")
    raise SystemExit("BOT_TOKEN required")

# ---------------- Aiogram setup ----------------
bot = Bot(token=BOT_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
dp = Dispatcher()

# global sessions
aiohttp_session: Optional[aiohttp.ClientSession] = None
aiodns_resolver: Optional[aiodns.DNSResolver] = None

# concurrency limiter for network
NET_SEMAPHORE = asyncio.Semaphore(int(os.getenv("NET_CONCURRENCY", "6")))

# ---------------- Helpers ----------------
def make_serializable(obj: Any) -> Any:
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, (datetime,)):
        return obj.isoformat()
    if isinstance(obj, (bytes, bytearray)):
        try:
            return obj.decode("utf-8", errors="replace")
        except Exception:
            return str(obj)
    if isinstance(obj, set):
        return [make_serializable(x) for x in obj]
    if isinstance(obj, (list, tuple)):
        return [make_serializable(x) for x in obj]
    if isinstance(obj, dict):
        return {str(k): make_serializable(v) for k, v in obj.items()}
    try:
        return str(obj)
    except Exception:
        return repr(obj)

# Додатково: не потрібно імпортувати нічого нового — використовується datetime.timezone
async def save_json_file(obj: Any, prefix: str = "osint_report_") -> str:
    """
    Збереження JSON-файлу з timezone-aware UTC timestamp у імені файлу.
    """
    safe = make_serializable(obj)
    # Використовуємо aware UTC datetime замість deprecated utcnow()
    ts = datetime.now(datetime.timezone.utc).strftime('%Y%m%d_%H%M%S')
    fname = os.path.join(REPORTS_DIR, f"{prefix}{ts}.json")
    async with aiofiles.open(fname, "w", encoding="utf-8") as f:
        await f.write(json.dumps(safe, ensure_ascii=False, indent=2))
    return fname


# cache
_cache_lock = asyncio.Lock()
async def load_cache() -> Dict[str, Any]:
    async with _cache_lock:
        if not os.path.exists(CACHE_FILE):
            return {}
        try:
            async with aiofiles.open(CACHE_FILE, "r", encoding="utf-8") as f:
                text = await f.read()
                return json.loads(text)
        except Exception:
            return {}

async def save_cache(cache_obj: Dict[str, Any]):
    async with _cache_lock:
        async with aiofiles.open(CACHE_FILE, "w", encoding="utf-8") as f:
            await f.write(json.dumps(make_serializable(cache_obj), ensure_ascii=False, indent=2))

def check_rate(user_id: int) -> bool:
    now = asyncio.get_event_loop().time()
    ts = _user_calls.setdefault(user_id, [])
    ts[:] = [t for t in ts if now - t < RATE_WINDOW]
    if len(ts) >= RATE_MAX:
        return False
    ts.append(now)
    return True

def safe_pre(data: Any) -> str:
    if not isinstance(data, str):
        data = json.dumps(make_serializable(data), ensure_ascii=False, indent=2)
    return f"<pre>{html_escape(data)}</pre>"

async def load_blacklist() -> Dict[str, Any]:
    async with _blacklist_lock:
        if not os.path.exists(BLACKLIST_FILE):
            return {"domains": []}
        try:
            async with aiofiles.open(BLACKLIST_FILE, "r", encoding="utf-8") as f:
                return json.loads(await f.read())
        except Exception:
            return {"domains": []}

async def save_blacklist(data: Dict[str, Any]):
    async with _blacklist_lock:
        async with aiofiles.open(BLACKLIST_FILE, "w", encoding="utf-8") as f:
            await f.write(json.dumps(data, ensure_ascii=False, indent=2))

# ---------------- Network operations ----------------
async def async_fetch(url: str, timeout: int = 12) -> (Optional[str], Optional[str]):
    headers = {"User-Agent": USER_AGENT}
    async with NET_SEMAPHORE:
        try:
            async with aiohttp_session.get(url, headers=headers, timeout=timeout, allow_redirects=True) as resp:
                resp.raise_for_status()
                text = await resp.text(errors="ignore")
                return text, str(resp.url)
        except Exception as e:
            logger.debug("fetch error %s", e)
            return None, f"Error fetching: {e}"

async def async_fetch_bytes(url: str, timeout: int = 20) -> (Optional[bytes], Optional[str]):
    headers = {"User-Agent": USER_AGENT}
    async with NET_SEMAPHORE:
        try:
            async with aiohttp_session.get(url, headers=headers, timeout=timeout, allow_redirects=True) as resp:
                resp.raise_for_status()
                data = await resp.read()
                return data, str(resp.url)
        except Exception as e:
            logger.debug("fetch bytes error %s", e)
            return None, f"Error: {e}"

async def async_fetch_head(url: str, timeout: int = 12) -> Tuple[Optional[Dict[str,str]], Optional[str]]:
    headers = {"User-Agent": USER_AGENT}
    async with NET_SEMAPHORE:
        try:
            async with aiohttp_session.head(url, headers=headers, timeout=timeout, allow_redirects=True) as resp:
                return dict(resp.headers), str(resp.url)
        except Exception as e:
            logger.debug("head error %s", e)
            return None, f"Error head: {e}"

async def async_dns_lookup(domain: str) -> Dict[str, Any]:
    out = {}
    if aiodns_resolver is None:
        for t in DNS_TYPES:
            try:
                if t == "A":
                    out["A"] = [socket.gethostbyname(domain)]
                else:
                    out[t] = "aiodns not available"
            except Exception as e:
                out[t] = f"Error: {e}"
        return out

    for t in DNS_TYPES:
        try:
            answers = await aiodns_resolver.query(domain, t)
            vals = []
            if isinstance(answers, list):
                for a in answers:
                    vals.append(str(a))
            else:
                vals.append(str(answers))
            out[t] = vals
        except Exception as e:
            out[t] = f"Error or none: {e}"
    return out

# blocking WHOIS/exif -> executor
async def run_blocking(func, *args, **kwargs):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: func(*args, **kwargs))

def whois_sync(domain: str):
    if whois is None:
        return {"error": "whois library not installed"}
    try:
        w = whois.whois(domain)
        try:
            return dict(w)
        except Exception:
            data = {}
            for k in dir(w):
                if k.startswith("_"):
                    continue
                try:
                    v = getattr(w, k)
                    if callable(v):
                        continue
                    data[k] = v
                except Exception:
                    continue
            return data
    except Exception as e:
        return {"error": str(e)}

def exif_from_file_sync(path: str):
    if exifread is None:
        return {"error": "exifread not installed"}
    try:
        with open(path, "rb") as f:
            tags = exifread.process_file(f, details=False)
        return {k: str(v) for k, v in tags.items()}
    except Exception as e:
        return {"error": str(e)}

# EXIF helpers (unchanged)
def _rational_to_float(value):
    try:
        if isinstance(value, (list, tuple)):
            vals = [float(str(x)) for x in value]
            deg = vals[0]
            minute = vals[1] if len(vals) > 1 else 0
            sec = vals[2] if len(vals) > 2 else 0
            return deg + minute/60 + sec/3600
        s = str(value)
        parts = re.split('[ ,]+', s.strip())
        nums = []
        for p in parts:
            if "/" in p:
                a, b = p.split("/")
                nums.append(float(a)/float(b))
            else:
                try:
                    nums.append(float(p))
                except:
                    pass
        if not nums:
            return None
        deg = nums[0]
        minute = nums[1] if len(nums) > 1 else 0
        sec = nums[2] if len(nums) > 2 else 0
        return deg + minute/60 + sec/3600
    except Exception:
        return None

async def fetch_crtsh_subdomains(domain: str, timeout: int = 10) -> List[str]:
    try:
        q = quote_plus(f"%25.{domain}")  # %25. => %.domain
        url = f"https://crt.sh/?q={q}&output=json"
        text, final = await async_fetch(url, timeout=timeout)
        if not text:
            return []
        # crt.sh sometimes returns multiple JSON objects without array -> handle robustly
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # try to fix common crt.sh problem: replace '}{' with '},{'
            fixed = "[" + text.replace("}{", "},{") + "]"
            data = json.loads(fixed)
        names: Set[str] = set()
        for item in data:
            for field in ("name_value", "common_name"):
                val = item.get(field)
                if not val:
                    continue
                # name_value can contain newlines for multiple names
                for s in str(val).splitlines():
                    s = s.strip().lower()
                    if s.endswith("."):
                        s = s[:-1]
                    if s:
                        # filter out wildcard-only entry
                        s = s.lstrip("*.")  # remove leading wildcard
                        if domain.lower() in s:
                            names.add(s)
        return sorted(names)
    except Exception as e:
        logger.exception("crtsh error")
        return []

async def quick_port_scan(host: str, ports: List[int], timeout: float = 1.0) -> Dict[int,str]:
    """
    Легкий TCP connect scan для підрахунку відкритих/закритих/filtered.
    Повертає словник порт -> status.
    """
    out: Dict[int, str] = {}
    loop = asyncio.get_event_loop()

    async def try_port(p):
        try:
            fut = loop.run_in_executor(None, lambda: _sync_connect(host, p, timeout))
            ok = await asyncio.wait_for(fut, timeout=timeout+0.5)
            return p, "open" if ok else "closed"
        except asyncio.TimeoutError:
            return p, "filtered/timeout"
        except Exception:
            return p, "error"

    tasks = [try_port(p) for p in ports]
    for coro in asyncio.as_completed(tasks):
        p, status = await coro
        out[p] = status
    return out

def _sync_connect(host: str, port: int, timeout: float = 1.0) -> bool:
    """Синхронна допоміжна функція для виконання в executor."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            return True
    except Exception:
        return False

async def find_sitemaps_from_robots(base_url: str) -> List[str]:
    """
    Завантажує robots.txt і повертає список sitemap-рядків, або пустий список.
    """
    try:
        parsed = urlparse(base_url if base_url.startswith("http") else "https://" + base_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        txt, _ = await async_fetch(robots_url, timeout=6)
        if not txt:
            return []
        sitemaps = []
        for line in txt.splitlines():
            if line.strip().lower().startswith("sitemap:"):
                s = line.split(":", 1)[1].strip()
                if s:
                    sitemaps.append(s)
        return sitemaps
    except Exception:
        return []

def store_last_result(user_id: int, key: str, value: Any):
    """Зберігає останній результат у пам'ять (використовується для /export_last)."""
    _last_results.setdefault(user_id, {})[key] = value


def exif_gps_to_latlon(tags: Dict[str,str]) -> Optional[Dict[str,float]]:
    lat_key = next((k for k in tags if k.lower().endswith("gpslatitude")), None)
    lat_ref_key = next((k for k in tags if k.lower().endswith("gpslatituderef")), None)
    lon_key = next((k for k in tags if k.lower().endswith("gpslongitude")), None)
    lon_ref_key = next((k for k in tags if k.lower().endswith("gpslongituderef")), None)
    if not lat_key or not lon_key:
        return None
    lat_val = tags[lat_key]
    lon_val = tags[lon_key]
    lat = _rational_to_float(lat_val)
    lon = _rational_to_float(lon_val)
    if lat is None or lon is None:
        return None
    if lat_ref_key and tags.get(lat_ref_key, "").strip().upper() in ("S", "SOUTH"):
        lat = -abs(lat)
    if lon_ref_key and tags.get(lon_ref_key, "").strip().upper() in ("W", "WEST"):
        lon = -abs(lon)
    return {"lat": round(lat, 6), "lon": round(lon, 6)}

# robots.txt
async def robots_allows(base_url: str, path: str = "/") -> Optional[bool]:
    parsed = urlparse(base_url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    txt, final = await async_fetch(robots_url)
    if txt is None:
        return None
    rp = robotparser.RobotFileParser()
    rp.parse(txt.splitlines())
    try:
        return rp.can_fetch(USER_AGENT, path)
    except Exception:
        return None

# parse page
async def parse_page(text: str) -> Dict[str, Any]:
    soup = BeautifulSoup(text, "html.parser")
    title = soup.title.string.strip() if soup.title and soup.title.string else ""
    desc_tag = soup.find("meta", attrs={"name":"description"})
    desc = desc_tag.get("content").strip() if desc_tag and desc_tag.get("content") else ""
    text_all = soup.get_text(" ", strip=True)
    emails = sorted(set(EMAIL_RE.findall(text_all)))
    return {"title": title, "description": desc, "emails": emails}

# full scan (simple)
async def full_scan(url: str) -> Dict[str, Any]:
    cache = await load_cache()
    if url in cache:
        logger.info("cache hit %s", url)
        return cache[url]
    allowed = await robots_allows(url, "/")
    html, final = await async_fetch(url)
    if not html:
        result = {"error": final}
        cache[url] = result
        await save_cache(cache)
        return result
    parsed = await parse_page(html)
    host = urlparse(final).netloc
    ip = None
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        pass
    geo = {}
    if ip:
        try:
            async with aiohttp_session.get(IP_API_URL.format(ip), timeout=8) as r:
                geo = await r.json()
        except Exception as e:
            geo = {"error": str(e)}
    dns = await async_dns_lookup(host)
    whois_info = await run_blocking(whois_sync, host)
    result = {
        "requested_url": url,
        "final_url": final,
        "robots_allowed": allowed,
        "title": parsed.get("title"),
        "description": parsed.get("description"),
        "emails": parsed.get("emails"),
        "host": host,
        "ip": ip,
        "geo": geo,
        "dns": dns,
        "whois": whois_info,
        "timestamp": datetime.utcnow()
    }
    cache[url] = result
    await save_cache(cache)
    return result

# ---------------- Wikipedia + DDG helpers ----------------
async def wikipedia_search(query: str) -> Dict[str, Any]:
    try:
        q = quote_plus(query)
        search_api = f"https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch={q}&srlimit=1&format=json"
        text, _ = await async_fetch(search_api, timeout=6)
        if not text:
            return {"error": "wiki search failed"}
        data = json.loads(text)
        results = data.get("query", {}).get("search", [])
        if not results:
            return {"error": "no wiki page found"}
        title = results[0].get("title")
        title_enc = quote_plus(title.replace(" ", "_"))
        summary_api = f"https://en.wikipedia.org/api/rest_v1/page/summary/{title_enc}"
        stext, _ = await async_fetch(summary_api, timeout=6)
        if not stext:
            return {"error": "wiki summary fetch failed", "title": title}
        sdata = json.loads(stext)
        return {
            "title": sdata.get("title"),
            "summary": sdata.get("extract"),
            "description": sdata.get("description"),
            "wiki_url": sdata.get("content_urls", {}).get("desktop", {}).get("page"),
            "thumbnail": sdata.get("thumbnail", {}).get("source") if sdata.get("thumbnail") else None,
            "raw": sdata
        }
    except Exception as e:
        logger.exception("wikipedia_search error")
        return {"error": str(e)}

async def ddg_quick_search(query: str, max_links: int = 8) -> List[Dict[str, str]]:
    try:
        q = quote_plus(query)
        ddg_url = f"https://duckduckgo.com/html/?q={q}"
        html, _ = await async_fetch(ddg_url, timeout=6)
        if not html:
            return []
        soup = BeautifulSoup(html, "html.parser")
        results = []
        for a in soup.find_all("a", attrs={"class": "result__a"}, href=True)[:max_links]:
            href = a["href"]
            title = a.get_text(strip=True)
            results.append({"title": title, "href": href})
        if not results:
            for a in soup.find_all("a", href=True)[:max_links]:
                href = a["href"]
                title = a.get_text(strip=True) or href
                results.append({"title": title, "href": href})
        return results
    except Exception as e:
        logger.exception("ddg_quick_search error")
        return []

def extract_domain_from_url(url: str) -> Optional[str]:
    try:
        parsed = urlparse(unquote(url))
        host = parsed.netloc or parsed.path
        host = host.split(":")[0]
        host = host.lower()
        if host.startswith("www."):
            host = host[4:]
        if "." in host:
            return host
        return None
    except Exception:
        return None

def choose_official_link(links: List[Dict[str,str]], company_name: str) -> Optional[str]:
    name = company_name.lower()
    for l in links:
        href = l.get("href","").lower()
        title = l.get("title","").lower()
        if name.replace(" ", "") in href or name in href or name in title:
            return l.get("href")
    for l in links:
        d = extract_domain_from_url(l.get("href",""))
        if d:
            return l.get("href")
    return None

# ---------------- Telegram handlers ----------------
ETHICAL_TEXT = (
    "This bot is intended only for legitimate and ethical collection of open information.\n"
    "Do not use it for doxxing, stalking, or other illegal activities.\n"
    "The author is not responsible for any misuse."
)

# Error logging + notify owner
@dp.errors()
async def on_error(event, exception):
    try:
        logger.exception("Unhandled exception: %s", exception)
        if OWNER_ID:
            try:
                await bot.send_message(OWNER_ID, f"Error in bot: {html_escape(str(exception))}")
            except Exception:
                logger.warning("Failed to notify owner")
    except Exception:
        pass

@dp.message(F.text.regexp(r'(?i)^/start$'))
async def cmd_start(message: types.Message):
    kb = InlineKeyboardBuilder()
    kb.button(text="Scan URL", callback_data="menu_scan")
    kb.button(text="DNS / WHOIS / IP", callback_data="menu_dns")
    kb.button(text="Send photo (EXIF)", callback_data="menu_exif")
    kb.adjust(1)

    safe_name = html_escape(message.from_user.first_name or 'user')
    text = (
        f"Hi, {safe_name}!\n\n{ETHICAL_TEXT}\n\n"
        "Available commands (non-admin):\n"
        "/start — show this message\n"
        "/help — brief help about commands\n\n"
        "/scan (url) — full page analysis (content parsing and security checks)\n"
        "/secscan (url) — passive safe site configuration audit (HEAD/GET, TLS, headers, robots/security.txt)\n"
        "/fetch (url) — quick parse of title/description; extract emails and links\n"
        "/headers (url) — show HTTP response headers\n"
        "/emails (url_or_domain) — search for email addresses on a page or domain\n"
        "/sitemap (url_or_domain) — find and parse sitemap (returns URLs or CSV)\n"
        "/subdomains (domain) — search subdomains (crt.sh)\n"
        "/portscan (host) [ports] — quick port scan (comma-separated ports)\n"
        "/export_last (type) — export last stored result for this user (types: subdomains, portscan, sitemap)\n"
        "/report — list recent saved reports\n\n"
        "/dns (domain) — DNS queries (A/AAAA/CNAME/MX etc.)\n"
        "/whois (domain) — WHOIS information for a domain\n"
        "/ip (host_or_ip) — resolve host or show IP geolocation\n\n"
        "/shorten (url) — create a short link (tinyurl)\n"
        "/info (company name) — search general info about a company/organization\n\n"
        "You can also send a photo to the bot for EXIF analysis (the bot will return extracted EXIF data and GPS if present).\n\n"
        "If you need detailed help for a specific command, use /help or contact the developer — @sollamon."
    )

    # Send without HTML parsing so the name won't cause issues
    await message.answer(text, parse_mode=None, reply_markup=kb.as_markup())



# menu callbacks — now with a filter
@dp.callback_query(F.data.startswith("menu_"))
async def callback_menu_handler(query: types.CallbackQuery):
    data = query.data or ""
    if data == "menu_scan":
        await query.message.edit_text("Use: /scan (url) (e.g.: /scan https://example.com)")
    elif data == "menu_dns":
        await query.message.edit_text("Commands: /dns (domain), /whois (domain), /ip (host_or_ip)")
    elif data == "menu_exif":
        await query.message.edit_text("Send a photo — the bot will return EXIF data.")
    # must answer the callback
    await query.answer()

@dp.callback_query(F.data.regexp(r"^get_report:\d+$"))
async def cb_get_report(query: types.CallbackQuery):
    # даємо миттєвий feedback UI
    await query.answer()

    # розпарсимо індекс
    try:
        _, idx_str = query.data.split(":", 1)
        idx = int(idx_str)
    except Exception:
        await query.message.reply("Invalid report id (internal error).")
        return

    # спроба перелічити файли
    try:
        files = sorted(os.listdir(REPORTS_DIR))
    except Exception:
        logger.exception("listing reports dir error")
        await query.message.reply("Failed to access reports directory.")
        return

    if not files:
        await query.message.reply("No saved reports.")
        return

    recent = files[-10:][::-1]  # останні 10, від нових до старих
    if idx < 0 or idx >= len(recent):
        await query.message.reply("Report not found (it may have been removed).")
        return

    fname = recent[idx]
    path = os.path.join(REPORTS_DIR, fname)

    # безпечна перевірка, щоб переконатися, що файл у REPORTS_DIR
    try:
        real_reports_dir = os.path.realpath(REPORTS_DIR)
        real_path = os.path.realpath(path)
        # краща перевірка, ніж startswith
        if os.path.commonpath([real_reports_dir, real_path]) != real_reports_dir:
            logger.warning("Attempt to access file outside reports dir: %s", real_path)
            await query.message.reply("Access denied.")
            return
    except Exception:
        # якщо перевірка впала — логнемо, але намагатимемось продовжити з обережністю
        logger.exception("realpath/commonpath check failed")

    if not os.path.isfile(path):
        await query.message.reply("File not found.")
        return

    # перевіряємо розмір файлу перед відправкою
    try:
        size = os.path.getsize(path)
    except Exception:
        logger.exception("could not stat file before sending: %s", path)
        await query.message.reply("Cannot read report file info (internal error).")
        return

    # Ліміт для send_document — ~50 MB для більшості ботів (можна підлаштувати під ваш випадок)
    MAX_TG_SIZE = 50 * 1024 * 1024
    if size > MAX_TG_SIZE:
        await query.message.reply(
            f"Report is too large to send via Telegram ({size//1024} KB). "
            "Please download it from the server or archive it first."
        )
        return

    # власне відправка — з відкритого файлу (часто надійніше)
    try:
        with open(path, "rb") as fp:
            doc = types.InputFile(fp, filename=fname)
            await bot.send_document(chat_id=query.message.chat.id,
                                    document=doc,
                                    caption=html.escape(f"Report: {fname}"))
    except TelegramRetryAfter as e:
        # Telegram просить почекати
        logger.exception("TelegramRetryAfter while sending report %s", path)
        await query.message.reply(f"Telegram rate limit — retry after {getattr(e, 'timeout', 'N/A')}s.")
    except TelegramAPIError as e:
        logger.exception("TelegramAPIError while sending report %s", path)
        await query.message.reply("Network error while sending report. Try again later.")
    except TelegramAPIError as e:
        # загальні помилки API
        logger.exception("TelegramAPIError while sending report %s", path)
        await query.message.reply(
            "Failed to send report file (Telegram API error).\n"
            f"Error: {e.__class__.__name__}"
        )
    except Exception as e:
        # невідома помилка — логнемо повний traceback, користувачу даємо коротку індикацію
        logger.exception("send report error for file %s", path)
        # не виводимо весь traceback в чат, але повідомляємо тип помилки
        short_err = f"{e.__class__.__name__}"
        await query.message.reply(
            "Failed to send report file (internal error).\n"
            f"Error type: {short_err}\n"
            "If you are the bot owner, check logs for full traceback."
        )

# /scan
@dp.message(F.text.startswith("/scan"))
async def handle_scan_text(message: types.Message):
    if not check_rate(message.from_user.id):
        await message.reply("Too many requests — please wait a bit.")
        return
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2 or not parts[1].strip():
        await message.reply("Usage: /scan (url)\nExample: /scan example.com or /scan https://example.com")
        return
    url = parts[1].strip()
    if not urlparse(url).scheme:
        url = "http://" + url
    bl = await load_blacklist()
    host = urlparse(url).netloc
    if host in bl.get("domains", []):
        await message.reply("This domain is blacklisted and will not be scanned.")
        return
    status = await message.reply(f"Scanning {html_escape(url)} ...")
    try:
        result = await asyncio.wait_for(full_scan(url), timeout=25)
        txt = json.dumps(make_serializable(result), ensure_ascii=False, indent=2)
        if len(txt) < 3500:
            await status.edit_text(f"Result:\n{safe_pre(txt)}", parse_mode=ParseMode.HTML)
        else:
            path = await save_json_file(result, prefix="scan_")
            await bot.send_document(message.chat.id, InputFile(path), caption=html_escape(f"Scan result ({url})"))
            await status.delete()
            try:
                os.remove(path)
            except:
                pass
    except asyncio.TimeoutError:
        await status.edit_text("Scanning exceeded the time limit (timeout).")
    except Exception as e:
        logger.exception("scan error")
        await status.edit_text(f"Error during scan: {html_escape(str(e))}")
    finally:
        # ensure the status is not left in a "pending" state
        try:
            await asyncio.sleep(0)  # yield
        except:
            pass

# /fetch
@dp.message(F.text.startswith("/fetch"))
async def handle_fetch_text(message: types.Message):
    if not check_rate(message.from_user.id):
        await message.reply("Too many requests — please wait a bit.")
        return
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2 or not parts[1].strip():
        await message.reply("Usage: /fetch (url)")
        return
    url = parts[1].strip()
    if not urlparse(url).scheme:
        url = "http://" + url
    msg = await message.reply(f"Fetching {html_escape(url)} ...")
    try:
        html, final = await asyncio.wait_for(async_fetch(url, timeout=10), timeout=12)
        if not html:
            await msg.edit_text(f"Error: {html_escape(final)}")
            return
        parsed = await parse_page(html)
        out = {"final_url": final, "title": parsed.get("title"), "description": parsed.get("description"), "emails": parsed.get("emails")}
        await msg.edit_text(f"Result:\n{safe_pre(out)}", parse_mode=ParseMode.HTML)
    except asyncio.TimeoutError:
        await msg.edit_text("Request timed out.")
    except Exception as e:
        logger.exception("fetch error")
        await msg.edit_text(f"Error: {html_escape(str(e))}")

# /headers
@dp.message(F.text.startswith("/headers"))
async def handle_headers_text(message: types.Message):
    if not check_rate(message.from_user.id):
        await message.reply("Too many requests — please wait.")
        return
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2 or not parts[1].strip():
        await message.reply("Usage: /headers (url)")
        return
    url = parts[1].strip()
    if not urlparse(url).scheme:
        url = "http://" + url
    msg = await message.reply(f"Retrieving headers for {html_escape(url)} ...")
    try:
        hdrs, final = await asyncio.wait_for(async_fetch_head(url, timeout=8), timeout=10)
        if hdrs is None:
            await msg.edit_text(f"Error: {html_escape(final)}")
            return
        await msg.edit_text(f"Headers for {html_escape(final)}:\n{safe_pre(hdrs)}", parse_mode=ParseMode.HTML)
    except asyncio.TimeoutError:
        await msg.edit_text("Header request timed out.")
    except Exception as e:
        logger.exception("headers error")
        await msg.edit_text(f"Error: {html_escape(str(e))}")

# /shorten
@dp.message(F.text.startswith("/shorten"))
async def handle_shorten_text(message: types.Message):
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2 or not parts[1].strip():
        await message.reply("Usage: /shorten (url)")
        return
    url = parts[1].strip()
    if not urlparse(url).scheme:
        url = "http://" + url
    try:
        short_api = f"https://tinyurl.com/api-create.php?url={quote_plus(url)}"
        async with aiohttp_session.get(short_api, timeout=8) as r:
            if r.status == 200:
                short = (await r.text()).strip()
                await message.reply(f"Short link: {html_escape(short)}")
            else:
                await message.reply("Failed to shorten the link — service unavailable.")
    except Exception as e:
        logger.exception("shorten error")
        await message.reply(f"Error: {html_escape(str(e))}")

# /emails
@dp.message(F.text.startswith("/emails"))
async def handle_emails_text(message: types.Message):
    if not check_rate(message.from_user.id):
        await message.reply("Too many requests — please wait.")
        return
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2 or not parts[1].strip():
        await message.reply("Usage: /emails (url_or_domain)")
        return
    target = parts[1].strip()
    if not urlparse(target).scheme:
        url = "http://" + target
    else:
        url = target
    msg = await message.reply(f"Fetching {html_escape(url)} ...")
    try:
        html, final = await asyncio.wait_for(async_fetch(url, timeout=10), timeout=12)
        if not html:
            if url.startswith("http://"):
                try_url = "https://" + url[len("http://"):]
                html, final = await asyncio.wait_for(async_fetch(try_url, timeout=8), timeout=10)
        if not html:
            await msg.edit_text(f"Error: {html_escape(final)}")
            return
        parsed = await parse_page(html)
        soup = BeautifulSoup(html, "html.parser")
        mailto = set()
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.lower().startswith("mailto:"):
                addr = href.split(":",1)[1].split("?")[0].strip()
                if addr:
                    mailto.add(addr)
        regex_found = set(EMAIL_RE.findall(html))
        parsed_found = set(parsed.get("emails", []))
        all_emails = set()
        for e in regex_found | parsed_found | mailto:
            e_clean = e.strip().strip('.,;:()[]<>"\'')
            if e_clean:
                all_emails.add(e_clean)
        all_emails = sorted(all_emails)
        if not all_emails:
            await msg.edit_text("Found emails: none found")
            return
        MAX_DISPLAY = 50
        if len(all_emails) <= MAX_DISPLAY:
            lines = [f'<a href="mailto:{html_escape(e)}">{html_escape(e)}</a>' for e in all_emails]
            text = "Found emails:\n" + "\n".join(lines)
            await msg.edit_text(text, parse_mode=ParseMode.HTML)
            return
        data = {"source_url": final, "emails": all_emails, "count": len(all_emails), "timestamp": datetime.utcnow()}
        path = await save_json_file(data, prefix="emails_")
        await bot.send_document(message.chat.id, InputFile(path), caption=html_escape(f"Found emails ({len(all_emails)})"))
        await msg.delete()
        try:
            os.remove(path)
        except:
            pass
    except asyncio.TimeoutError:
        await msg.edit_text("Request timed out.")
    except Exception as e:
        logger.exception("emails error")
        await msg.edit_text(f"Error: {html_escape(str(e))}")

# /info with timeouts and robust flow
@dp.message(F.text.startswith("/info"))
async def handle_info_text(message: types.Message):
    if not check_rate(message.from_user.id):
        await message.reply("Too many requests — please wait.")
        return

    parts = message.text.split(maxsplit=1)
    if len(parts) < 2 or not parts[1].strip():
        await message.reply("Usage: /info (company name)\nExample: /info GitHub, Inc.")
        return
    query = parts[1].strip()
    status = await message.reply(f"Searching for information about: {html_escape(query)} ...")

    result: Dict[str, Any] = {"query": query, "timestamp": datetime.now(datetime.timezone.utc)}

    try:
        # run wiki + ddg in parallel with timeouts
        tasks = [
            asyncio.create_task(wikipedia_search(query)),
            asyncio.create_task(ddg_quick_search(query, max_links=8))
        ]
        done, pending = await asyncio.wait(tasks, timeout=8)
        wiki = {}
        links = []
        for t in tasks:
            if t.done():
                try:
                    val = t.result()
                    if isinstance(val, dict) and val.get("title"):
                        wiki = val
                    elif isinstance(val, list):
                        links = val
                except Exception:
                    pass
            else:
                t.cancel()
        result["wikipedia"] = wiki or {"note": "no result or timeout"}
        result["ddg_links"] = links

        # choose official
        official_link = choose_official_link(links, query)
        result["official_link_guess"] = official_link

        domain = None
        if official_link:
            domain = extract_domain_from_url(official_link)
        if not domain and wiki and isinstance(wiki, dict) and wiki.get("wiki_url"):
            d = extract_domain_from_url(wiki.get("wiki_url"))
            if d:
                domain = d
        result["domain"] = domain

        if domain:
            # try fetch site with timeout
            site_url = f"https://{domain}"
            html = final = None
            try:
                html, final = await asyncio.wait_for(async_fetch(site_url, timeout=8), timeout=10)
            except asyncio.TimeoutError:
                html = final = None
            if not html:
                try:
                    html, final = await asyncio.wait_for(async_fetch("http://" + domain, timeout=6), timeout=8)
                except asyncio.TimeoutError:
                    html = final = None
            if html:
                parsed = await parse_page(html)
                result["site_snapshot"] = {
                    "fetched_url": final,
                    "title": parsed.get("title"),
                    "description": parsed.get("description"),
                    "emails": parsed.get("emails")
                }
            else:
                result["site_snapshot"] = {"error": f"Failed to load {domain}"}

            # whois with timeout (executor)
            try:
                whois_info = await asyncio.wait_for(run_blocking(whois_sync, domain), timeout=6)
                result["whois"] = whois_info
            except asyncio.TimeoutError:
                result["whois"] = {"error": "whois timeout"}
            except Exception as e:
                result["whois"] = {"error": str(e)}
        else:
            result["site_snapshot"] = {"note": "No domain found for query"}

        pretty = json.dumps(make_serializable(result), ensure_ascii=False, indent=2)
        if len(pretty) < 3000:
            lines = []
            if result.get("wikipedia") and not result["wikipedia"].get("error"):
                w = result["wikipedia"]
                if w.get("title"):
                    lines.append(f"<b>{html_escape(w.get('title'))}</b>")
                if w.get("description"):
                    lines.append(html_escape(w.get("description")))
                if w.get("summary"):
                    lines.append(html_escape(w.get("summary")[:1000]))
                if w.get("wiki_url"):
                    lines.append(f"Wiki: {html_escape(w.get('wiki_url'))}")
            if result.get("domain"):
                lines.append(f"Official domain (guess): {html_escape(result['domain'])}")
                snap = result.get("site_snapshot", {})
                if isinstance(snap, dict):
                    if snap.get("title"):
                        lines.append(f"Site title: {html_escape(snap['title'])}")
                    if snap.get("description"):
                        lines.append(f"Site description: {html_escape(snap['description'])}")
                    if snap.get("emails"):
                        lines.append(f"Emails on site: {html_escape(', '.join(snap['emails']) if snap['emails'] else 'none found')}")
            if result.get("ddg_links"):
                lines.append("Top links:")
                for l in result["ddg_links"][:6]:
                    title = l.get("title","")
                    href = l.get("href","")
                    lines.append(f"- {html_escape(title)} — {html_escape(href)}")
            await status.edit_text("\n\n".join(lines), parse_mode=ParseMode.HTML)
        else:
            path = await save_json_file(result, prefix="info_")
            await bot.send_document(message.chat.id, InputFile(path), caption=html_escape(f"Info: {query}"))
            await status.delete()
            try:
                os.remove(path)
            except:
                pass
    except Exception as e:
        logger.exception("info handler error")
        try:
            await status.edit_text(f"Error while searching for information: {html_escape(str(e))}")
        except:
            pass
# /dns
@dp.message(F.text.startswith("/dns"))
async def handle_dns_text(message: types.Message):
    if not check_rate(message.from_user.id):
        await message.reply("Too many requests — try again later.")
        return
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2 or not parts[1].strip():
        await message.reply("Usage: /dns (domain)")
        return
    domain = parts[1].strip()
    msg = await message.reply(f"Performing DNS lookup for {html_escape(domain)} ...")
    try:
        res = await asyncio.wait_for(async_dns_lookup(domain), timeout=8)
        await msg.edit_text(f"DNS for {html_escape(domain)}:\n{safe_pre(res)}", parse_mode=ParseMode.HTML)
    except asyncio.TimeoutError:
        await msg.edit_text("DNS lookup timed out.")
    except Exception as e:
        logger.exception("dns error")
        await msg.edit_text(f"Error: {html_escape(str(e))}")

# /whois
@dp.message(F.text.startswith("/whois"))
async def handle_whois_text(message: types.Message):
    if not check_rate(message.from_user.id):
        await message.reply("Too many requests — try again later.")
        return
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2 or not parts[1].strip():
        await message.reply("Usage: /whois (domain)")
        return
    domain = parts[1].strip()
    msg = await message.reply(f"Performing WHOIS for {html_escape(domain)} ...")
    try:
        res = await asyncio.wait_for(run_blocking(whois_sync, domain), timeout=8)
        txt = json.dumps(make_serializable(res), ensure_ascii=False, indent=2)
        if len(txt) < 3500:
            await msg.edit_text(f"WHOIS for {html_escape(domain)}:\n{safe_pre(txt)}", parse_mode=ParseMode.HTML)
        else:
            path = await save_json_file(res, prefix="whois_")
            await bot.send_document(message.chat.id, InputFile(path), caption=html_escape(f"WHOIS ({domain})"))
            await msg.delete()
            try:
                os.remove(path)
            except:
                pass
    except asyncio.TimeoutError:
        await msg.edit_text("WHOIS request timed out.")
    except Exception as e:
        logger.exception("whois error")
        await msg.edit_text(f"Error: {html_escape(str(e))}")

# /ip
@dp.message(F.text.startswith("/ip"))
async def handle_ip_text(message: types.Message):
    if not check_rate(message.from_user.id):
        await message.reply("Too many requests — try again later.")
        return
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2 or not parts[1].strip():
        await message.reply("Usage: /ip (host_or_ip)")
        return
    target = parts[1].strip()
    msg = await message.reply("Working...")
    ip = None
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
        ip = target
    else:
        try:
            ip = socket.gethostbyname(target)
        except Exception:
            ip = None
    if not ip:
        await msg.edit_text("Failed to resolve host to an IP")
        return
    try:
        async with aiohttp_session.get(IP_API_URL.format(ip), timeout=8) as r:
            geo = await r.json()
    except Exception as e:
        geo = {"error": str(e)}
    await msg.edit_text(f"IP: {html_escape(ip)}\nGeo:\n{safe_pre(geo)}", parse_mode=ParseMode.HTML)

@dp.message(F.text.startswith("/subdomains"))
async def handle_subdomains(message: types.Message):
    if not check_rate(message.from_user.id):
        await message.reply("Too many requests — please wait.")
        return
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2 or not parts[1].strip():
        await message.reply("Usage: /subdomains (domain)\nExample: /subdomains example.com")
        return
    domain = parts[1].strip()
    status = await message.reply(f"Searching for subdomains for {html_escape(domain)} ...")
    try:
        subs = await asyncio.wait_for(fetch_crtsh_subdomains(domain), timeout=12)
        if not subs:
            await status.edit_text("No subdomains found.")
            return
        # store the latest result
        store_last_result(message.from_user.id, "subdomains", {"domain": domain, "subs": subs})
        # limit display to 200 lines (to avoid overloading the message)
        MAX_SHOW = 200
        if len(subs) <= 30:
            await status.edit_text("Found subdomains:\n" + "\n".join(html_escape(s) for s in subs))
        elif len(subs) <= MAX_SHOW:
            # show first 200 and offer to download the file
            text = f"Found {len(subs)} subdomains. First {MAX_SHOW}:\n" + "\n".join(html_escape(s) for s in subs[:MAX_SHOW])
            # save to file and provide a download button
            path = await save_json_file({"domain": domain, "subdomains": subs}, prefix="subdomains_")
            kb = InlineKeyboardBuilder()
            kb.button(text="Download JSON (all)", callback_data=f"get_report:subdomains_{os.path.basename(path)}")
            kb.adjust(1)
            await status.edit_text(text)
            await message.reply_document(InputFile(path), caption=html_escape(f"Subdomains for {domain}"))
            try:
                os.remove(path)
            except:
                pass
        else:
            # too many — send file and a short report
            path = await save_json_file({"domain": domain, "subdomains": subs}, prefix="subdomains_")
            await status.edit_text(f"Found {len(subs)} subdomains. Sending JSON file.")
            await message.reply_document(InputFile(path), caption=html_escape(f"Subdomains for {domain}"))
            try:
                os.remove(path)
            except:
                pass
    except asyncio.TimeoutError:
        await status.edit_text("crt.sh request timed out.")
    except Exception as e:
        logger.exception("subdomains error")
        await status.edit_text(f"Error: {html_escape(str(e))}")

@dp.message(F.text.startswith("/portscan"))
async def handle_portscan(message: types.Message):
    if not check_rate(message.from_user.id):
        await message.reply("Too many requests — please wait.")
        return
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2 or not parts[1].strip():
        await message.reply(
            "Usage: /portscan (host) [ports]\nExample: /portscan example.com\nOr: /portscan 1.2.3.4 22,80,443"
        )
        return
    rest = parts[1].strip().split(maxsplit=1)
    host = rest[0].strip()
    ports = DEFAULT_PORTS
    if len(rest) > 1 and rest[1].strip():
        try:
            ports = [int(p.strip()) for p in rest[1].split(",") if p.strip()]
            # validation: limit number of ports, e.g. to 40
            if len(ports) > 40:
                await message.reply("Too many ports — maximum is 40.")
                return
        except Exception:
            await message.reply("Invalid ports format. Use commas: 22,80,443")
            return
    status = await message.reply(f"Scanning {html_escape(host)} ports: {', '.join(str(p) for p in ports)} ...")
    try:
        # try to resolve host to IP
        try:
            ip = socket.gethostbyname(host)
        except Exception:
            ip = host  # maybe already an IP or unreachable
        scan_res = await asyncio.wait_for(quick_port_scan(ip, ports, timeout=1.0), timeout=(len(ports) * 1.2) + 5)
        # save last result
        store_last_result(message.from_user.id, "portscan", {"host": host, "result": scan_res})
        # output formatting
        lines = [f"{p}: {scan_res.get(p)}" for p in sorted(scan_res.keys())]
        await status.edit_text("Port scan result:\n" + "\n".join(html_escape(line) for line in lines))
    except asyncio.TimeoutError:
        await status.edit_text("Portscan exceeded time limit.")
    except Exception as e:
        logger.exception("portscan error")
        await status.edit_text(f"Error: {html_escape(str(e))}")

@dp.message(F.text.startswith("/sitemap"))
async def handle_sitemap(message: types.Message):
    if not check_rate(message.from_user.id):
        await message.reply("Too many requests — please wait.")
        return
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2 or not parts[1].strip():
        await message.reply("Usage: /sitemap (url_or_domain)\nExample: /sitemap example.com")
        return
    target = parts[1].strip()
    status = await message.reply(f"Searching for sitemap for {html_escape(target)} ...")
    try:
        sitemaps = await asyncio.wait_for(find_sitemaps_from_robots(target), timeout=6)
        # if not found — try standard locations
        if not sitemaps:
            candidates = [
                f"https://{target}/sitemap.xml",
                f"http://{target}/sitemap.xml",
                f"https://{target}/sitemap_index.xml"
            ]
            found = []
            for c in candidates:
                txt, final = await async_fetch(c, timeout=6)
                if txt:
                    found.append(final)
            sitemaps = found
        if not sitemaps:
            await status.edit_text("Sitemap not found.")
            return
        # take the first sitemap(s) and parse URLs (limit)
        urls = []
        for sm in sitemaps[:3]:  # parse up to 3 sitemaps
            txt, final = await async_fetch(sm, timeout=8)
            if not txt:
                continue
            # simple parser: extract <loc>...</loc>
            for m in re.findall(r"<loc>(.*?)</loc>", txt, flags=re.IGNORECASE):
                if m:
                    urls.append(m.strip())
            # limit
            if len(urls) >= 500:
                break
        urls = urls[:500]
        if not urls:
            await status.edit_text("Sitemap found, but no URLs detected / parsing failed.")
            return
        store_last_result(message.from_user.id, "sitemap", {"target": target, "sitemap_urls": urls})
        # if small number — display, otherwise send file
        if len(urls) <= 40:
            await status.edit_text("Found URLs:\n" + "\n".join(html_escape(u) for u in urls))
        else:
            # save as CSV
            sio = StringIO()
            writer = csv.writer(sio)
            writer.writerow(["url"])
            for u in urls:
                writer.writerow([u])
            sio.seek(0)
            bio = StringIO(sio.read())
            fname = f"sitemap_{target.replace('/', '_')}.csv"
            # write to temporary file for sending
            tmp = os.path.join(REPORTS_DIR, fname)
            async with aiofiles.open(tmp, "w", encoding="utf-8") as f:
                await f.write(bio.getvalue())
            await status.edit_text(f"Found {len(urls)} URLs. Sending CSV file.")
            await message.reply_document(InputFile(tmp), caption=html_escape(f"Sitemap URLs for {target}"))
            try:
                os.remove(tmp)
            except:
                pass
    except asyncio.TimeoutError:
        await status.edit_text("Sitemap search timed out.")
    except Exception as e:
        logger.exception("sitemap error")
        await status.edit_text(f"Error: {html_escape(str(e))}")

@dp.message(F.text.startswith("/export_last"))
async def handle_export_last(message: types.Message):
    """
    /export_last (type)  - type optional: subdomains | portscan | sitemap
    If type is not provided — returns the list of available types for this user.
    """
    parts = message.text.split(maxsplit=1)
    user_store = _last_results.get(message.from_user.id, {})
    if not user_store:
        await message.reply("No saved results available for export.")
        return
    if len(parts) < 2 or not parts[1].strip():
        await message.reply("Available types for export: " + ", ".join(user_store.keys()))
        return
    typ = parts[1].strip()
    data = user_store.get(typ)
    if not data:
        await message.reply("No data of this type. Available: " + ", ".join(user_store.keys()))
        return
    # format file depending on type
    if typ == "subdomains":
        subs = data.get("subs") or data.get("subdomains") or []
        sio = StringIO()
        w = csv.writer(sio)
        w.writerow(["subdomain"])
        for s in subs:
            w.writerow([s])
        sio.seek(0)
        tmpname = os.path.join(REPORTS_DIR, f"export_subdomains_{message.from_user.id}.csv")
        async with aiofiles.open(tmpname, "w", encoding="utf-8") as f:
            await f.write(sio.getvalue())
        await message.reply_document(InputFile(tmpname), caption="Export subdomains (CSV)")
        try:
            os.remove(tmpname)
        except:
            pass
        return
    if typ == "portscan":
        res = data.get("result", {})
        sio = StringIO()
        w = csv.writer(sio)
        w.writerow(["port", "status"])
        for p in sorted(res.keys()):
            w.writerow([p, res[p]])
        sio.seek(0)
        tmpname = os.path.join(REPORTS_DIR, f"export_portscan_{message.from_user.id}.csv")
        async with aiofiles.open(tmpname, "w", encoding="utf-8") as f:
            await f.write(sio.getvalue())
        await message.reply_document(InputFile(tmpname), caption="Export portscan (CSV)")
        try:
            os.remove(tmpname)
        except:
            pass
        return
    if typ == "sitemap":
        urls = data.get("sitemap_urls") or []
        sio = StringIO()
        w = csv.writer(sio)
        w.writerow(["url"])
        for u in urls:
            w.writerow([u])
        sio.seek(0)
        tmpname = os.path.join(REPORTS_DIR, f"export_sitemap_{message.from_user.id}.csv")
        async with aiofiles.open(tmpname, "w", encoding="utf-8") as f:
            await f.write(sio.getvalue())
        await message.reply_document(InputFile(tmpname), caption="Export sitemap (CSV)")
        try:
            os.remove(tmpname)
        except:
            pass
        return
    # fallback: save as json
    path = await save_json_file(data, prefix=f"export_{typ}_")
    await message.reply_document(InputFile(path), caption=html_escape(f"Export ({typ})"))
    try:
        os.remove(path)
    except:
        pass


# owner commands (blacklist, save, reports, setkey etc.)
@dp.message(F.text.startswith("/blacklist_add"))
async def cmd_blacklist_add(message: types.Message):
    if message.from_user.id != OWNER_ID:
        return
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2:
        await message.reply("Usage: /blacklist_add (domain)")
        return
    domain = parts[1].strip()
    bl = await load_blacklist()
    if domain in bl.get("domains", []):
        await message.reply("Domain is already in the blacklist")
        return
    bl.setdefault("domains", []).append(domain)
    await save_blacklist(bl)
    await message.reply(f"Added to blacklist: {html_escape(domain)}")

@dp.message(F.text.startswith("/blacklist_remove"))
async def cmd_blacklist_remove(message: types.Message):
    if message.from_user.id != OWNER_ID:
        return
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2:
        await message.reply("Usage: /blacklist_remove (domain)")
        return
    domain = parts[1].strip()
    bl = await load_blacklist()
    if domain not in bl.get("domains", []):
        await message.reply("Domain not found in blacklist")
        return
    bl["domains"].remove(domain)
    await save_blacklist(bl)
    await message.reply(f"Removed from blacklist: {html_escape(domain)}")

@dp.message(F.text.startswith("/blacklist_list"))
async def cmd_blacklist_list(message: types.Message):
    if message.from_user.id != OWNER_ID:
        await message.reply("Available only to the owner.")
        return
    bl = await load_blacklist()
    domains = bl.get("domains", [])
    if not domains:
        await message.reply("Blacklist is empty.")
    else:
        await message.reply("Blacklist:\n" + "\n".join(html_escape(d) for d in domains))

@dp.message(F.text.startswith("/save"))
async def cmd_save(message: types.Message):
    if message.from_user.id != OWNER_ID:
        await message.reply("Available only to the owner.")
        return
    cache = await load_cache()
    if not cache:
        await message.reply("No data to save.")
        return
    path = await save_json_file(cache, prefix="cache_")
    await bot.send_document(message.chat.id, InputFile(path), caption=html_escape("Saved cache/reports"))
    try:
        os.remove(path)
    except:
        pass

@dp.message(F.text.startswith("/report"))
async def cmd_report(message: types.Message):
    try:
        files = sorted(os.listdir(REPORTS_DIR))
    except Exception as e:
        logger.exception("listing reports dir error")
        await message.reply("Failed to list reports directory.")
        return

    if not files:
        await message.reply("No saved reports.")
        return

    # take last 10 files and reverse so newest first
    recent = files[-10:][::-1]

    kb = InlineKeyboardBuilder()
    for idx, f in enumerate(recent):
        # use small, safe callback_data: get_report:<index>
        kb.button(text=f, callback_data=f"get_report:{idx}")
    kb.adjust(1)

    await message.reply("Recent reports:", reply_markup=kb.as_markup())



# ---------------- Passive security scanner (secscan) ----------------
# Functions must be safe and passive — only HEAD/GET, TLS cert read, and analysis of headers/content.

# Fallback-safe helper: safe_pre (if you already have it, you can skip)
try:
    safe_pre  # type: ignore
except NameError:
    from html import escape as _html_escape
    def safe_pre(data: Any) -> str:
        if not isinstance(data, str):
            data = json.dumps(data, ensure_ascii=False, indent=2)
        return f"<pre>{_html_escape(data)}</pre>"

# Fallback-safe store_last_result (in-memory)
try:
    store_last_result  # type: ignore
except NameError:
    _last_results: Dict[int, Dict[str, Any]] = {}
    def store_last_result(user_id: int, key: str, value: Any):
        _last_results.setdefault(user_id, {})[key] = value

# ---------- TLS cert retrieval (blocking) ----------
def _get_cert_sync(host: str, port: int = 443, timeout: float = 6.0) -> Dict[str, Any]:
    """Blocking access to the TLS certificate; run in an executor via run_blocking."""
    out: Dict[str, Any] = {"host": host, "port": port}
    try:
        ctx = ssl.create_default_context()
        # Do not verify (so we can get the cert even if it's invalid)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                out["cert"] = cert
                notAfter = cert.get("notAfter")
                if notAfter:
                    try:
                        # Example format: 'Jul 16 12:00:00 2025 GMT'
                        dt = datetime.strptime(notAfter, "%b %d %H:%M:%S %Y %Z")
                        dt = dt.replace(tzinfo=dt.timezone.utc)
                        out["not_after"] = dt.isoformat()
                        out["days_left"] = (dt - datetime.now(dt.timezone.utc)).days
                    except Exception:
                        out["not_after_raw"] = notAfter
                out["issuer"] = cert.get("issuer")
                out["subject"] = cert.get("subject")
        out["ok"] = True
    except Exception as e:
        out["ok"] = False
        out["error"] = str(e)
    return out

async def get_tls_info(host: str, port: int = 443, timeout: float = 6.0) -> Dict[str, Any]:
    """Asynchronous wrapper to get TLS certificate (via run_blocking)."""
    try:
        return await run_blocking(_get_cert_sync, host, port, timeout)
    except Exception:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: _get_cert_sync(host, port, timeout))

# ---------- Security headers & content analyzer ----------
def analyze_security_headers(headers: Optional[Dict[str, str]], html_text: Optional[str], url: str) -> Dict[str, List[str]]:
    """
    Simple analysis of headers/content — returns a dict with categories:
    critical, high, medium, low, info
    """
    findings = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
    if headers is None:
        headers = {}
    # normalize keys
    h = {k.lower(): v for k, v in headers.items()}

    parsed = urlparse(url)
    scheme = parsed.scheme.lower()

    # HSTS
    if scheme == "https":
        sts = h.get("strict-transport-security")
        if not sts:
            findings["high"].append("Missing Strict-Transport-Security (HSTS) header.")
        else:
            try:
                m = re.search(r"max-age=(\d+)", sts)
                if m:
                    max_age = int(m.group(1))
                    if max_age < 31536000:
                        findings["medium"].append(f"HSTS max-age is small ({max_age}); consider >= 31536000.")
                else:
                    findings["low"].append("HSTS header present but no max-age found.")
            except Exception:
                findings["low"].append("HSTS header present but parsing failed.")

    # X-Content-Type-Options
    if "x-content-type-options" not in h:
        findings["medium"].append("Missing X-Content-Type-Options header (nosniff).")

    # X-Frame-Options
    if "x-frame-options" not in h and "content-security-policy" not in h:
        # if CSP exists it may cover frame-ancestors
        findings["medium"].append("Missing X-Frame-Options header (clickjacking protection).")

    # CSP
    if "content-security-policy" not in h:
        findings["low"].append("Missing Content-Security-Policy (CSP). Consider adding to mitigate XSS.")
    else:
        csp = h.get("content-security-policy", "")
        if "unsafe-inline" in csp or "unsafe-eval" in csp:
            findings["medium"].append("CSP allows 'unsafe-inline' or 'unsafe-eval' which weakens CSP.")

    # Referrer-Policy
    if "referrer-policy" not in h:
        findings["low"].append("Missing Referrer-Policy header.")

    # Permissions-Policy / Feature-Policy
    if "permissions-policy" not in h and "feature-policy" not in h:
        findings["low"].append("Missing Permissions-Policy (Feature-Policy).")

    # Server header leakage
    if "server" in h:
        findings["info"].append(f"Server header present: {h.get('server')}. May reveal implementation details.")

    # Cookies: simple Set-Cookie analysis
    set_cookie_raw = h.get("set-cookie")
    if set_cookie_raw:
        cookies = str(set_cookie_raw).lower()
        # if site is served over https but Secure flag missing — bad
        if scheme == "https" and "secure" not in cookies:
            findings["high"].append("Set-Cookie missing Secure flag over HTTPS.")
        if "httponly" not in cookies:
            findings["medium"].append("Set-Cookie missing HttpOnly flag for at least one cookie.")

    # Mixed content: look for http:// resources in HTML when served over HTTPS
    if html_text and scheme == "https":
        if re.search(r'src\s*=\s*["\']http://', html_text, re.IGNORECASE) or re.search(r'href\s*=\s*["\']http://', html_text, re.IGNORECASE):
            findings["medium"].append("Page includes http:// resources while served over HTTPS (mixed content).")

    # Basic robots info (informational)
    try:
        if parsed.netloc:
            findings["info"].append("Check robots.txt and sitemap for sensitive disallowed paths (not scanned here).")
    except Exception:
        pass

    return findings

# ---------- Handler ---------
@dp.message(F.text.startswith("/secscan"))
async def handle_secscan_enhanced(message: types.Message):
    """
    /secscan (url)  -- passive safe site configuration audit.
    Extended version: additional passive checks of headers, HTML, TLS, robots/security.txt,
    HTTP methods (via OPTIONS), mixed content, SRI, cookie flags.
    IMPORTANT: the check DOES NOT perform anything that could cause harm.
    The "findings" result contains only problematic findings (errors/warnings) — without excessive info in the main output.
    """
    if not check_rate(message.from_user.id):
        await message.reply("Too many requests — please wait.")
        return

    parts = message.text.split(maxsplit=1)
    if len(parts) < 2 or not parts[1].strip():
        await message.reply("Usage: /secscan (url)\nExample: /secscan example.com")
        return

    target_raw = parts[1].strip()
    if not urlparse(target_raw).scheme:
        target = "https://" + target_raw
    else:
        target = target_raw

    status = await message.reply(f"Performing enhanced passive check: {html_escape(target)} ...")

    result: Dict[str, Any] = {
        "target": target,
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        "findings": {"critical": [], "high": [], "medium": [], "low": [], "info": []}
    }

    try:
        parsed = urlparse(target)
        host = parsed.hostname or parsed.path

        # 1) HEAD
        try:
            hdrs, final_head = await asyncio.wait_for(async_fetch_head(target, timeout=6), timeout=8)
        except Exception:
            hdrs, final_head = {}, None

        # 2) GET (short) — get HTML for analysis
        try:
            html, final_page = await asyncio.wait_for(async_fetch(target, timeout=8), timeout=10)
        except Exception:
            html, final_page = None, None

        # 3) OPTIONS — check allowed methods
        try:
            opts = await asyncio.wait_for(fetch_options(target, timeout=6), timeout=8)
        except Exception:
            opts = None

        # 4) TLS cert (by hostname)
        try:
            tls_info = await asyncio.wait_for(get_tls_info(host, 443, timeout=6), timeout=8)
        except Exception as e:
            tls_info = {"ok": False, "error": str(e)}

        # 5) robots.txt
        try:
            robots_txt = await asyncio.wait_for(async_fetch(urlparse(target)._replace(path='/robots.txt').geturl(), timeout=4), timeout=6)
        except Exception:
            robots_txt = None

        # 6) security.txt
        try:
            sec_txt = await asyncio.wait_for(async_fetch(urlparse(target)._replace(path='/.well-known/security.txt').geturl(), timeout=4), timeout=6)
        except Exception:
            sec_txt = None

        # 7) Analyze headers/HTML/OPTIONS/TLS
        findings = {"critical": [], "high": [], "medium": [], "low": [], "info": []}

        analyze_security_headers_enhanced(hdrs or {}, html or "", target, findings)
        analyze_tls_info_enhanced(tls_info, findings)
        analyze_options(opts, findings)
        analyze_robots_and_security(robots_txt, sec_txt, findings)

        # Collect result (only problematic findings will be shown to the user)
        result["findings"] = findings
        result["headers"] = hdrs or {}
        result["tls_info"] = {k: make_serializable(v) for k, v in (tls_info or {}).items()}
        result["final_url"] = final_page or final_head or target

        store_last_result(message.from_user.id, "secscan", result)

        # Build a short human-readable output - ONLY problematic severities (no info)
        out_lines = []
        for sev in ("critical", "high", "medium", "low"):
            items = findings.get(sev, [])
            if items:
                out_lines.append(f"<b>{sev.upper()} ({len(items)})</b>")
                for it in items:
                    out_lines.append(html_escape(str(it)))
                out_lines.append("")

        out_text = "\n".join(out_lines) if out_lines else "No issues found."

        pretty = json.dumps(make_serializable(result), ensure_ascii=False, indent=2)
        if len(pretty) < 3000:
            await status.edit_text(out_text + "\n\nFull result (JSON):\n" + safe_pre(pretty))
        else:
            path = await save_json_file(result, prefix="secscan_")
            await bot.send_document(message.chat.id, InputFile(path), caption=html_escape(f"Security scan for {target}"))
            await status.delete()
            try:
                os.remove(path)
            except:
                pass

    except asyncio.TimeoutError:
        await status.edit_text("Scan exceeded time limit.")
    except Exception as e:
        logger.exception("secscan error")
        await status.edit_text(f"Error during scan: {html_escape(str(e))}")


# ---------------- Вспомогательные проверки ----------------
def analyze_security_headers_enhanced(headers: Dict[str, Any], html: str, target: str, findings: Dict[str, List[str]]):
    """Analyzes HTTP headers and HTML and appends issues to `findings` (only problems).
    `headers` — object supporting dict-like access; if multiple values exist — they are joined.
    `target` — full URL (needed to check cookie scheme / mixed content).
    """
    # normalize keys
    hdr = {k.lower(): (', '.join(v) if isinstance(v, (list, tuple)) else str(v)) for k, v in (headers or {}).items()}

    # 1) HSTS
    hsts = hdr.get('strict-transport-security')
    if hsts:
        try:
            max_age = int([p.split('=')[1] for p in hsts.split(';') if 'max-age' in p][0])
            if max_age < 31536000:
                findings['medium'].append(f'HSTS max-age is too small: {max_age} seconds (recommended ≥31536000).')
        except Exception:
            findings['low'].append('HSTS present but failed to parse max-age.')
    else:
        findings['high'].append('Missing Strict-Transport-Security (HSTS) header.')

    # 2) Content-Security-Policy
    csp = hdr.get('content-security-policy')
    csp_ro = hdr.get('content-security-policy-report-only')
    if not csp and not csp_ro:
        findings['high'].append('Missing Content-Security-Policy (CSP) header. This increases XSS risk.')
    else:
        active = csp or csp_ro or ''
        if "\"'unsafe-inline'\"" in active or "'unsafe-inline'" in active:
            findings['medium'].append("CSP allows 'unsafe-inline' — this weakens XSS protection.")
        if "\"'unsafe-eval'\"" in active or "'unsafe-eval'" in active:
            findings['medium'].append("CSP allows 'unsafe-eval' — risk of arbitrary JS execution.")
        if 'default-src' not in active and 'script-src' not in active:
            findings['medium'].append('CSP does not contain default-src or script-src — may be insufficiently restrictive.')
        if 'frame-ancestors' not in active and 'x-frame-options' not in hdr:
            findings['medium'].append('CSP/X-Frame-Options do not forbid embedding (clickjacking risk).')

    # 3) X-Content-Type-Options
    if hdr.get('x-content-type-options', '').lower() != 'nosniff':
        findings['medium'].append("Missing or incorrect X-Content-Type-Options: should be 'nosniff'.")

    # 4) X-Frame-Options / frame-ancestors
    xfo = hdr.get('x-frame-options')
    if not xfo and (not csp or 'frame-ancestors' not in (csp or '')):
        findings['medium'].append('Missing X-Frame-Options and CSP frame-ancestors — site may be vulnerable to clickjacking.')

    # 5) Referrer-Policy
    if not hdr.get('referrer-policy'):
        findings['low'].append('Missing Referrer-Policy — possible referrer/URL leakage.')

    # 6) Permissions-Policy / Feature-Policy
    if not hdr.get('permissions-policy') and not hdr.get('feature-policy'):
        findings['low'].append('Missing Permissions-Policy (Feature-Policy) — the site does not restrict access to web APIs.')

    # 7) Server / X-Powered-By
    server = hdr.get('server')
    xp = hdr.get('x-powered-by')
    if server:
        findings['low'].append(f'Server header exposed: {server} (may leak technology stack).')
    if xp:
        findings['low'].append(f'X-Powered-By header exposed: {xp} (may leak technology stack).')

    # 8) Cookies flags
    for k, v in (headers or {}).items():
        if k.lower() == 'set-cookie':
            cookies = v if isinstance(v, (list, tuple)) else [v]
            for c in cookies:
                cstr = str(c)
                if 'httponly' not in cstr.lower():
                    findings['high'].append(f'Cookie without HttpOnly: {cstr.split(";")[0]}')
                # use target, so it must be passed to the function
                if 'secure' not in cstr.lower() and urlparse(target).scheme == 'https':
                    findings['high'].append(f'Cookie missing Secure flag over HTTPS: {cstr.split(";")[0]}')
                if 'samesite' not in cstr.lower():
                    findings['medium'].append(f'Cookie without SameSite: {cstr.split(";")[0]}')

    # 9) Mixed content + SRI
    if urlparse(target).scheme == 'https' and html:
        mixed = scan_html_for_mixed_content_and_sri(html)
        findings['high'].extend(mixed.get('mixed', []))
        findings['medium'].extend(mixed.get('no_sri', []))


def analyze_tls_info_enhanced(tls_info: Dict[str, Any], findings: Dict[str, List[str]]):
    """TLS checks: expiry, weak signatures, self-signed, missing SAN, etc."""
    if not tls_info.get('ok'):
        findings['high'].append(f"Failed to obtain TLS info: {tls_info.get('error')}")
        return

    days = tls_info.get('days_left')
    if isinstance(days, int):
        if days <= 0:
            findings['critical'].append(f"TLS certificate expired (not_after: {tls_info.get('not_after')}).")
        elif days <= 14:
            findings['high'].append(f"TLS certificate expires in {days} days (not_after: {tls_info.get('not_after')}).")
        elif days <= 60:
            findings['medium'].append(f"TLS certificate expires in {days} days (not_after: {tls_info.get('not_after')}).")

    sig = tls_info.get('signature_algorithm')
    if sig and 'sha1' in sig.lower():
        findings['high'].append(f"TLS certificate uses a weak signature algorithm: {sig}.")

    keysize = tls_info.get('key_size')
    if keysize and keysize < 2048:
        findings['high'].append(f"RSA key size is insufficient: {keysize} bits (recommended ≥2048).")

    if tls_info.get('self_signed'):
        findings['high'].append('TLS certificate is self-signed.')

    san = tls_info.get('san')
    host = tls_info.get('host')
    if san and host and host not in san:
        findings['high'].append(f'Hostname {host} not present in certificate SAN: {san}.')


async def fetch_options(target: str, timeout: int = 6):
    """Performs an OPTIONS request (passive) and returns the Allow header or None."""
    try:
        resp, final = await async_fetch(target, timeout=timeout, method='OPTIONS')
        if isinstance(resp, dict):
            allow = resp.get('allow') or resp.get('Allow')
            return allow
        return None
    except Exception:
        return None


def analyze_options(allow_header: str, findings: Dict[str, List[str]]):
    if not allow_header:
        return
    methods = [m.strip().upper() for m in allow_header.split(',') if m.strip()]
    dangerous = set(['PUT', 'DELETE', 'TRACE', 'CONNECT'])
    found = dangerous.intersection(set(methods))
    if found:
        findings['high'].append(f'Server allows potentially dangerous HTTP methods: {", ".join(sorted(found))}.')


def analyze_robots_and_security(robots_txt, sec_txt, findings: Dict[str, List[str]]):
    if robots_txt:
        try:
            body = robots_txt[0] if isinstance(robots_txt, (list, tuple)) else robots_txt
            if 'Disallow:' in body and ('/admin' in body.lower() or '/backup' in body.lower() or '/config' in body.lower()):
                findings['low'].append('robots.txt contains Disallow for potentially sensitive paths (admin/backup/config) — may indicate hidden resources.')
        except Exception:
            pass
    if sec_txt:
        try:
            body = sec_txt[0] if isinstance(sec_txt, (list, tuple)) else sec_txt
            if 'Contact:' in body and 'security' not in body.lower():
                findings['low'].append('security.txt present but does not contain an obvious security contact.')
        except Exception:
            pass


def scan_html_for_mixed_content_and_sri(html: str) -> Dict[str, List[str]]:
    """Searches for external resources over http:// on https sites (mixed content) and missing SRI.
    Simple text-based checks without a full parser for speed.
    """
    mixed = []
    no_sri = []
    import re
    for m in re.finditer(r'<(?:script|link|img|iframe)\b[^>]*(?:src|href)=["\'](http://[^"\']+)["\']', html, flags=re.I):
        url = m.group(1)
        mixed.append(f'Mixed content: resource over HTTP: {url}')
    for m in re.finditer(r'<(script|link)\b([^>]*?)>', html, flags=re.I | re.S):
        tag = m.group(1).lower()
        attrs = m.group(2)
        srcm = re.search(r'(?:src|href)=["\'](https?://[^"\']+)["\']', attrs, flags=re.I)
        if srcm:
            src = srcm.group(1)
            if src.startswith('http') and ('integrity=' not in attrs.lower()) and (('cdnjs' in src.lower()) or ('cdn.jsdelivr' in src.lower()) or ('unpkg' in src.lower())):
                no_sri.append(f'External resource without SRI: {src} — consider adding Subresource Integrity.')
    return {'mixed': mixed, 'no_sri': no_sri}


@dp.message(F.text.startswith("/setkey"))
async def cmd_setkey(message: types.Message):
    if message.from_user.id != OWNER_ID:
        await message.reply("Available only to the owner.")
        return
    parts = message.text.split(maxsplit=2)
    if len(parts) < 3:
        await message.reply("Usage: /setkey (service) (key)")
        return
    service, key = parts[1], parts[2]
    cache = await load_cache()
    keys = cache.setdefault("_api_keys", {})
    keys[service] = key
    await save_cache(cache)
    await message.reply(f"Key for {html_escape(service)} saved.")


# photo handler: download via file_path
@dp.message(F.photo)
async def photo_handler(message: types.Message):
    if not check_rate(message.from_user.id):
        await message.reply("Too many requests — try again later.")
        return
    await message.reply("Photo received — downloading and analyzing EXIF...")
    photo = message.photo[-1]
    file_obj = await bot.get_file(photo.file_id)
    file_path = getattr(file_obj, "file_path", None)
    if not file_path:
        await message.reply("Failed to get file path.")
        return
    file_url = f"https://api.telegram.org/file/bot{BOT_TOKEN}/{file_path}"
    fd, tmp_path = tempfile.mkstemp(prefix="osint_img_", suffix=".jpg")
    os.close(fd)
    try:
        async with aiohttp_session.get(file_url, timeout=30) as r:
            r.raise_for_status()
            data = await r.read()
            async with aiofiles.open(tmp_path, "wb") as f:
                await f.write(data)
        res = await run_blocking(exif_from_file_sync, tmp_path)
        gps = exif_gps_to_latlon(res) if isinstance(res, dict) else None
        if gps:
            res["gps_decoded"] = gps
            res["gps_google_maps"] = f"https://www.google.com/maps/search/?api=1&query={gps['lat']},{gps['lon']}"
        txt = json.dumps(make_serializable(res), ensure_ascii=False, indent=2)
        if len(txt) < 3500:
            await message.reply(f"EXIF:\n{safe_pre(txt)}", parse_mode=ParseMode.HTML)
        else:
            path_out = await save_json_file(res, prefix="exif_")
            await bot.send_document(message.chat.id, InputFile(path_out), caption=html_escape("EXIF data"))
            try:
                os.remove(path_out)
            except:
                pass
    except Exception as e:
        logger.exception("photo download / exif error")
        await message.reply(f"Error processing photo: {html_escape(str(e))}")
    finally:
        try:
            os.remove(tmp_path)
        except:
            pass
@dp.message()
async def fallback(message: types.Message):
    if message.text and message.text.startswith("/"):
        await message.reply("Unknown command. Send /start to get the list of commands.")
    else:
        await message.reply("Send /start to get the list of commands or send a photo for EXIF analysis.")
# ---------------- Startup / Shutdown ----------------
@dp.startup()
async def on_startup():
    global aiohttp_session, aiodns_resolver
    aiohttp_session = aiohttp.ClientSession()
    try:
        aiodns_resolver = aiodns.DNSResolver()
    except Exception as e:
        logger.warning("aiodns init failed: %s. DNS lookup may be degraded.", e)
    logger.info("Bot started")

@dp.shutdown()
async def on_shutdown():
    global aiohttp_session
    if aiohttp_session:
        await aiohttp_session.close()
    logger.info("Bot stopped")

# ---------------- Main ----------------
def main():
    try:
        import uvloop
        uvloop.install()
    except Exception:
        pass
    dp.run_polling(bot, skip_updates=True)

if __name__ == "__main__":
    main()