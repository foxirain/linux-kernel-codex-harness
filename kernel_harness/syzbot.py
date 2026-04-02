from __future__ import annotations

import json
import re
from collections import Counter
from datetime import UTC, datetime
from html import unescape
from pathlib import Path
from urllib.parse import urljoin
from urllib.request import Request, urlopen


BUG_LINK_RE = re.compile(r'href=["\'](?P<href>/bug\?extid=[^"\'#]+)["\']')
PATH_RE = re.compile(r'([A-Za-z0-9_./+-]+\.(?:c|h)):(\d+)')
TITLE_RE = re.compile(r'<title>(.*?)</title>', re.IGNORECASE | re.DOTALL)
TAG_RE = re.compile(r'<[^>]+>')


def fetch_dashboard(source: str, out_path: Path, limit: int = 50) -> Path:
    dashboard_html = _read_source(source)
    bug_urls = _extract_bug_urls(dashboard_html, source)
    bugs = []

    for url in bug_urls[:limit]:
        try:
            bug_html = _read_source(url)
        except Exception:
            continue
        bugs.append(parse_bug_page(url, bug_html))

    payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "source": source,
        "bug_count": len(bugs),
        "bugs": bugs,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return out_path


def load_index(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def parse_bug_page(url: str, html: str) -> dict:
    text = _html_to_text(html)
    title = _extract_title(html, text)
    subsystems = _extract_csv_field(text, "Subsystems")
    status = _extract_scalar_field(text, "Status")
    first_crash = _extract_scalar_field(text, "First crash")
    file_hits = []
    seen_paths: set[str] = set()
    for path, line_no in PATH_RE.findall(text):
        if path in seen_paths:
            continue
        seen_paths.add(path)
        file_hits.append({"path": path, "line": int(line_no)})

    return {
        "extid": _extract_extid(url),
        "url": url,
        "title": title,
        "status": status,
        "subsystems": subsystems,
        "bug_type": _classify_bug_type(title, text),
        "first_crash": first_crash,
        "crash_count": _extract_crash_count(text),
        "file_hits": file_hits,
    }


def summarize_index(index: dict, top: int = 10) -> dict:
    bugs = index.get("bugs", [])
    subsystem_counter: Counter[str] = Counter()
    file_counter: Counter[str] = Counter()
    bugtype_counter: Counter[str] = Counter()

    for bug in bugs:
        for subsystem in bug.get("subsystems", []):
            subsystem_counter[subsystem] += 1
        bugtype_counter[bug.get("bug_type", "unknown")] += 1
        for file_hit in bug.get("file_hits", []):
            file_counter[file_hit.get("path", "")] += 1

    return {
        "bug_count": len(bugs),
        "top_subsystems": subsystem_counter.most_common(top),
        "top_bug_types": bugtype_counter.most_common(top),
        "top_files": file_counter.most_common(top),
    }


def _read_source(source: str) -> str:
    if source.startswith("http://") or source.startswith("https://"):
        req = Request(source, headers={"User-Agent": "kernel-codex-harness/0.1"})
        with urlopen(req, timeout=30) as response:
            return response.read().decode("utf-8", errors="ignore")
    return Path(source).read_text(encoding="utf-8", errors="ignore")


def _extract_bug_urls(html: str, source: str) -> list[str]:
    urls = []
    seen: set[str] = set()
    for match in BUG_LINK_RE.finditer(html):
        url = urljoin(source, match.group("href"))
        if url in seen:
            continue
        seen.add(url)
        urls.append(url)
    return urls


def _html_to_text(html: str) -> str:
    title_match = TITLE_RE.search(html)
    title_prefix = ""
    if title_match:
        title_prefix = unescape(title_match.group(1)).strip() + "\n"
    text = TAG_RE.sub(" ", html)
    text = unescape(text)
    text = re.sub(r'\r', '', text)
    text = re.sub(r'\n\s+', '\n', text)
    text = re.sub(r'[ \t]+', ' ', text)
    text = re.sub(r'\n{2,}', '\n', text)
    return title_prefix + text.strip()


def _extract_title(html: str, text: str) -> str:
    match = TITLE_RE.search(html)
    if match:
        return unescape(match.group(1)).strip()
    for line in text.splitlines():
        cleaned = line.strip()
        if cleaned and len(cleaned) < 200:
            return cleaned
    return "unknown syzbot bug"


def _extract_scalar_field(text: str, label: str) -> str:
    match = re.search(rf'{re.escape(label)}:\s*([^\n]+)', text)
    return match.group(1).strip() if match else ""


def _extract_csv_field(text: str, label: str) -> list[str]:
    value = _extract_scalar_field(text, label)
    if not value:
        return []
    return [item.strip() for item in re.split(r'[,/]', value) if item.strip()]


def _extract_crash_count(text: str) -> int:
    match = re.search(r'Crashes \((\d+)\)', text)
    return int(match.group(1)) if match else 0


def _extract_extid(url: str) -> str:
    match = re.search(r'extid=([0-9a-f]+)', url)
    return match.group(1) if match else ""


def _classify_bug_type(title: str, text: str) -> str:
    blob = f"{title}\n{text}".lower()
    pairs = [
        ("slab-use-after-free", "slab-use-after-free"),
        ("use-after-free", "use-after-free"),
        ("slab-out-of-bounds", "slab-out-of-bounds"),
        ("out-of-bounds", "out-of-bounds"),
        ("double-free", "double-free"),
        ("deadlock", "deadlock"),
        ("data-race", "data-race"),
        ("kasan", "KASAN"),
        ("kcsan", "KCSAN"),
        ("ubsan", "UBSAN"),
        ("warning", "WARNING"),
        ("general protection fault", "GPF"),
        ("kernel bug", "BUG"),
    ]
    for needle, label in pairs:
        if needle in blob:
            return label
    return "unknown"
