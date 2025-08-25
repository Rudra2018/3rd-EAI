# bug_bounty/h1_programs_crawler.py
import asyncio
import json
import sqlite3
from pathlib import Path
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

START_URL = "https://hackerone.com/opportunities/all/search?asset_types=API&ordering=Newest+programs"
DB_PATH = Path("db/h1_programs.sqlite")
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

SCHEMA = """
CREATE TABLE IF NOT EXISTS programs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  handle TEXT,
  url TEXT,
  assets TEXT,
  bounty TEXT,
  invites TEXT,
  created_at TEXT
);
"""

async def fetch_html(url):
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto(url, wait_until="networkidle")
        # try infinite scroll/“load more”
        for _ in range(4):
            try:
                await page.locator("text=Load more").click(timeout=1500)
                await page.wait_for_load_state("networkidle")
            except Exception:
                break
        content = await page.content()
        await browser.close()
        return content

def parse_programs(html):
    soup = BeautifulSoup(html, "lxml")
    cards = soup.select("[data-testid='opportunity-card'], a[href*='/programs/']")
    programs = []
    seen = set()
    for c in cards:
        # Name/handle/url
        link = c.get("href") if c.name == "a" else None
        if not link:
            a = c.select_one("a[href*='/programs/']")
            link = a.get("href") if a else None
        if not link:
            continue
        if not link.startswith("http"):
            link = "https://hackerone.com" + link
        name = c.get_text(" ", strip=True)[:200]
        # crude handle extraction
        parts = link.rstrip("/").split("/")
        handle = parts[-1] if parts else None
        if (name, link) in seen: 
            continue
        seen.add((name, link))
        # quick asset tag scrape
        tags = [t.get_text(strip=True) for t in c.select("[data-testid='opportunity-asset-type'], .Tag")]
        programs.append({
            "name": name,
            "handle": handle,
            "url": link,
            "assets": [t for t in tags if t],
        })
    return programs

def save_db(rows):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(SCHEMA)
    for r in rows:
        cur.execute(
            "INSERT INTO programs(name, handle, url, assets, bounty, invites, created_at) VALUES(?,?,?,?,?,?,datetime('now'))",
            (r.get("name"), r.get("handle"), r.get("url"),
             json.dumps(r.get("assets") or []),
             r.get("bounty"), r.get("invites"))
        )
    conn.commit()
    conn.close()

async def main():
    html = await fetch_html(START_URL)
    programs = parse_programs(html)
    # keep only API-tagged results (belt & suspenders)
    programs = [p for p in programs if any("api" in a.lower() for a in p.get("assets") or ["api"])]
    save_db(programs)
    print(f"Saved {len(programs)} programs to {DB_PATH}")

if __name__ == "__main__":
    asyncio.run(main())

