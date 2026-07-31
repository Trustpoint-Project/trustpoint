"""Minimal Playwright browser automation example.

Opens Google, enters a search query, and presses Enter.
"""

from __future__ import annotations

import argparse
import sys

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright


def run_search(query: str, *, headless: bool = False) -> None:
    """Open Google and submit the given search query."""
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=headless)

        try:
            page = browser.new_page(
                viewport={"width": 1280, "height": 800},
                locale="en-US",
            )

            page.goto(
                "https://www.google.com/",
                wait_until="domcontentloaded",
                timeout=30_000,
            )

            # Google currently uses either a textarea or input named "q".
            search_box = page.locator(
                'textarea[name="q"], input[name="q"]'
            ).first

            search_box.wait_for(state="visible", timeout=15_000)
            search_box.fill(query)
            search_box.press("Enter")

            page.wait_for_load_state("domcontentloaded", timeout=30_000)
            print(f"Search submitted successfully: {query}")
            print(f"Current page: {page.url}")

            if not headless:
                input("Press Enter to close the browser...")

        except PlaywrightTimeoutError as exc:
            print(
                "The expected page element did not appear. "
                "A consent dialog or changed page layout may be blocking it.",
                file=sys.stderr,
            )
            raise SystemExit(1) from exc
        except PlaywrightError as exc:
            print(f"Browser automation failed: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc
        finally:
            browser.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Open Google and submit a search using Playwright."
    )
    parser.add_argument(
        "query",
        nargs="?",
        default="Trustpoint certificate management",
        help="Search query",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Run without displaying the browser window",
    )
    return parser.parse_args()


if __name__ == "__main__":
    arguments = parse_args()
    run_search(arguments.query, headless=arguments.headless)