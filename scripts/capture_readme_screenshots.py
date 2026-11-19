"""Capture AgentFence's actual React dashboard tabs locally and update README.

Run from repository root:
    python -m pip install playwright
    python -m playwright install chromium
    python scripts/capture_readme_screenshots.py
"""
import argparse
import re
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
SCREENS = ROOT / "docs" / "screenshots"
PAGES = [
    ("Overview", "overview"),
    ("Live Audit Events", "audit-events"),
    ("Delegation Explorer", "delegations"),
    ("Policy Management", "policies"),
    ("Agents & Tools", "agents-and-tools"),
    ("Attack Simulation Lab", "attack-lab"),
    ("Tenant Management", "tenants"),
]
START = "<!-- SCREENSHOTS_START -->"
END = "<!-- SCREENSHOTS_END -->"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8080/")
    args = parser.parse_args()
    if not re.match(r"^http://(127\.0\.0\.1|localhost):\d+/?$", args.url):
        parser.error("Use only a local http://127.0.0.1:<port>/ address")
    readme = ROOT / "README.md"
    if not readme.exists():
        parser.error("Run from an AgentFence checkout with README.md")
    SCREENS.mkdir(parents=True, exist_ok=True)
    captured = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 900}, device_scale_factor=1)
        try:
            page.goto(args.url, wait_until="domcontentloaded", timeout=15000)
            page.locator(".sidebar .nav-item").first.wait_for(timeout=10000)
            for title, slug in PAGES:
                try:
                    page.locator(".sidebar .nav-item").filter(has_text=title).click(timeout=5000)
                    page.wait_for_timeout(1000)
                    dest = SCREENS / f"{slug}.png"
                    page.screenshot(path=str(dest), full_page=True, animations="disabled")
                    captured.append((title, dest))
                    print(f"Captured {dest.relative_to(ROOT)}")
                except Exception as err:
                    print(f"Skipped {title}: {err}")
        except Exception as err:
            print(f"App not ready at {args.url}: {err}")
        finally:
            browser.close()
    if not captured:
        raise SystemExit("No images captured. Build frontend, start backend, then retry.")
    gallery = [
        "> Captured from the locally running AgentFence demo. "
        "Review images for private information before committing.",
        "",
    ]
    for title, dest in captured:
        gallery.extend([f"### {title}", "", f"![AgentFence — {title}]({dest.relative_to(ROOT).as_posix()})", ""])
    markdown = readme.read_text(encoding="utf-8")
    if START not in markdown or END not in markdown:
        raise SystemExit("Screenshot markers missing; images saved, README not changed.")
    before, remaining = markdown.split(START, 1)
    _, after = remaining.split(END, 1)
    readme.write_text(before + START + "\n" + "\n".join(gallery) + END + after, encoding="utf-8")
    print(f"Updated README gallery with {len(captured)} real screenshots.")


if __name__ == "__main__":
    main()
