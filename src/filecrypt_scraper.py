#!/usr/bin/env python3
"""
Filecrypt container link extractor.

Uses a normal Playwright-controlled Firefox session. It does not attempt to
bypass Cloudflare or solve CAPTCHAs. In --headful mode, complete any browser
challenge yourself and press Enter in the terminal.

Input JSON:
[
  {"name": "Some Package", "filecrypt_url": "https://filecrypt.cc/Container/xxx.html"}
]

Output preserves each input object and adds:
  "decrypted_urls": [...]
  "decryption_error": "..."   (only when an error occurred)

Notes:
- DLC links are returned as .dlc container URLs, not expanded into hoster URLs.
"""

from __future__ import annotations

import os
import sys
import argparse
import base64
import binascii
import json
import logging
import re
import sys
import time
import math
import random
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, unquote

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import playwright._impl._errors

from camoufox.sync_api import Camoufox

# TODO verify types
from playwright.sync_api import (
    Error as BrowserError,
    TimeoutError as BrowserTimeoutError,
    Page,
)


LOG = logging.getLogger("filecrypt_scraper")

CONTAINER_RE = re.compile(
    r"^https?://(?:www\.)?filecrypt\.(?:cc|co)/Container/\w+",
    re.IGNORECASE,
)
CNL_RE = re.compile(
    r"""CNLPOP\('([^']+)',\s*'([0-9a-fA-F]{32})',\s*'([^']+)',\s*'(.*?)'\);""",
    re.DOTALL,
)
WEBLINK_RE = re.compile(r"""<button\b[^>]*?onclick=["'][^"']*?/\*\d+\*/\('([\w/-]+)'""", re.I)
DLC_RE = re.compile(r"""onclick=["']DownloadDLC\(['"]([^'"]+)['"]\);["']""", re.I)
GO_RE = re.compile(r"https?://filecrypt\.cc/package_num\.php\?Action=Go&id=[\w-]+", re.I)

# Detect common challenge/interstitial markers. This is detection only.
CHALLENGE_MARKERS = (
    "just a moment",
    "checking your browser",
    "verify you are human",
    "cf-chl-",
    "challenge-platform",
    "security check",
)


def decrypt_cnl_payload(encoded: str, key_hex: str) -> list[str]:
    """Decrypt Filecrypt's CNL payload (AES-CBC; 16-byte key/IV)."""
    key = bytes.fromhex(key_hex)
    if len(key) != 16:
        raise ValueError(f"Expected 16-byte CNL key, got {len(key)} bytes")

    raw = base64.b64decode(unquote(encoded).replace(" ", "+"), validate=False)
    if not raw or len(raw) % 16:
        raise ValueError("CNL ciphertext is empty or not AES-block aligned")

    def decrypt(ciphertext: bytes, iv: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        plain = decryptor.update(ciphertext) + decryptor.finalize()
        try:
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            plain = unpadder.update(plain) + unpadder.finalize()
        except ValueError:
            plain = plain.rstrip(b"\x00")
        return plain.replace(b"\x00", b"")

    # pyLoad's CNL implementation uses the key as IV first. Some CNL payloads
    # instead carry the IV as the first AES block; try that documented fallback
    # if the first plaintext is not valid UTF-8.
    try:
        plaintext = decrypt(raw, key)
        text = plaintext.decode("utf-8").strip()
    except UnicodeDecodeError:
        if len(raw) <= 16:
            raise ValueError("CNL payload has no ciphertext after its IV")
        plaintext = decrypt(raw[16:], raw[:16])
        text = plaintext.decode("utf-8").strip()

    return [line.strip() for line in text.splitlines() if line.strip()]


def unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        item = item.strip()
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return result


def page_looks_challenged(page: Page) -> bool:
    try:
        sample = (page.title() + "\n" + page.locator("body").inner_text(timeout=2500)).lower()
    except BrowserError:
        try:
            sample = page.content().lower()
        except BrowserError:
            return False
    # return any(marker in sample for marker in CHALLENGE_MARKERS)
    for marker in CHALLENGE_MARKERS:
        if marker in sample:
            print(f"page_looks_challenged: found marker={marker!r}")
            return True
    return False


def wait_for_manual_challenge(page: Page, headful: bool, timeout_seconds: int) -> bool:
    if not page_looks_challenged(page):
        return True

    LOG.warning("A browser security/challenge page appears to be present: %s", page.url)

    # if not headful:
    #     LOG.error("Cannot complete an interactive challenge in headless mode.")
    #     return False

    cutcaptcha_shadow_host_selector = "div.cutcaptcha > div"
    cutcaptcha_spinner_selector = "span.cc__spinner"

    print("waiting for the captcha")
    time.sleep(5)

    print("solving cutcaptcha ...")

    shadow_host = page.locator(cutcaptcha_shadow_host_selector)
    print("shadow_host", shadow_host)
    # print("shadow_host dir", dir(shadow_host))
    print("shadow_host count:", shadow_host.count())
    print("shadow_host visible:", shadow_host.is_visible())
    print("shadow_host bounding box:", shadow_host.bounding_box())

    # hover the spinner to make it spin
    # move the browser-controlled pointer onto the element, generating the corresponding mouse events.
    # this is better than a synthetic javascript event:
    # "spinner.dispatchEvent(new MouseEvent("mouseenter", {bubbles: false, cancelable: false, view: window}));"
    # spinner = page.locator(cutcaptcha_spinner_selector)
    spinner = shadow_host.locator(cutcaptcha_spinner_selector)
    print("spinner", spinner)
    spinner_count_py = spinner.count()
    print("spinner count in Python:", spinner_count_py)
    js = (
        "() => {\n"
        f"  const host = document.querySelector({cutcaptcha_shadow_host_selector!r});\n"
        f"  return host?.shadowRootUnl?.querySelectorAll({cutcaptcha_spinner_selector!r}).length ?? 0;\n"
        "}\n"
    )
    spinner_count_js = page.evaluate(js)
    print("spinner count in JavaScript:", spinner_count_js)
    print("spinner visible:", spinner.is_visible())

    if spinner_count_py > 0:
        # if spinner_count_py == 0:
        # playwright._impl._errors.TimeoutError: Locator.hover: Timeout 30000ms exceeded.
        print("found spinner element in Python")
        print("spinner bounding box:", spinner.bounding_box())
        print("spinner.hover")
        spinner.hover()
    elif spinner_count_js > 0:
        # workaround: get the spinner bbox from javascript
        # and generate mouse events in python
        print("found spinner element in JavaScript")
        js = (
            "() => {\n"
            f"  var shadowHost = document.querySelector({cutcaptcha_shadow_host_selector!r});\n"
            # TODO check if shadowHost is null or undefined
            f"  var shadowRoot = shadowHost.shadowRootUnl;\n"
            # TODO check if shadowRoot is null or undefined
            f"  var spinner = shadowRoot.querySelector({cutcaptcha_spinner_selector!r});\n"
            # TODO check if spinner is null or undefined
            "  var rect = spinner.getBoundingClientRect();\n"
            "  return { x: rect.x, y: rect.y, width: rect.width, height: rect.height };\n"
            "}\n"
        )
        spinner_rect = page.evaluate(js)
        print("spinner_rect", spinner_rect)

        x1 = math.ceil(spinner_rect["x"])
        x2 = math.floor(spinner_rect["x"] + spinner_rect["width"])
        y1 = math.ceil(spinner_rect["y"])
        y2 = math.floor(spinner_rect["y"] + spinner_rect["height"])
        print(f"spinner: x1={x1} x2={x2} y1={y1} y2={y2}")

        x = random.randint(x1, x2)
        y = random.randint(y1, y2)
        print("moving mouse over spinner:", (x, y))
        page.mouse.move(x, y)

        # wait some random time, then click the spinner
        dt = random.randint(100, 500) / 1000
        print(f"sleep {dt}")
        time.sleep(dt)

        print("clicking spinner:", (x, y))
        page.mouse.click(x, y)

    else:
        if 1:
            print(f"FIXME not found spinner element")
            time.sleep(60)
        raise RuntimeError(f"not found spinner element")

    # no! cutcaptcha detects "spinner.click()" as a synthetic event
    # and increases the difficulty
    r'''
    # wait some random time, then click the spinner
    dt = random.randint(100, 500) / 1000
    print(f"sleep {dt}")
    time.sleep(dt)

    js = (
        "() => {\n"
        # 'document.querySelector("#shadow-host").shadowRootUnl.querySelector("input").click()'
        f"  var shadowHost = document.querySelector({cutcaptcha_shadow_host_selector!r});\n"
        # TODO check if shadowHost is null or undefined
        f"  var shadowRoot = shadowHost.shadowRootUnl;\n"
        # TODO check if shadowRoot is null or undefined
        f"  var spinner = shadowRoot.querySelector({cutcaptcha_spinner_selector!r});\n"
        # TODO check if spinner is null or undefined
        # no! this works only in python
        # # move the browser-controlled pointer onto the element, generating the corresponding mouse events.
        # # this is better than a synthetic event:
        # # "spinner.dispatchEvent(new MouseEvent("mouseenter", {bubbles: false, cancelable: false, view: window}));"
        # "spinner.hover();\n"
        # wait some random time, then click the spinner
        f"  setTimeout(() => spinner.click(), {random.randint(100, 500)});\n"
        "}\n"
    )
    print("evaluating javascript:\n" + "    " + js.replace("\n", "\n    "))
    try:
        page.evaluate(js)
    # no: TypeError: catching classes that do not inherit from BaseException is not allowed
    # except BrowserError as exc:
    except playwright._impl._errors.Error as exc:
        # Page.evaluate: can't access property "shadowRootUnl", shadowHost is null
        print(f"evaluating javascript failed: {type(exc).__name__}: {exc}")
    '''

    # TODO wait for the proof of work challenge

    # TODO check if we have solved the captcha

    # time.sleep(2)
    # return

    # wait until shadow_host disappears
    # shadow_host = page.locator(cutcaptcha_shadow_host_selector)
    # print("shadow_host", shadow_host)
    deadline = time.monotonic() + timeout_seconds
    LOG.info(f"Waiting up to {timeout_seconds} seconds for challenge to finish")
    while time.monotonic() < deadline:
        if page.is_closed():
            raise RuntimeError("Browser page closed during challenge")
        try:
            if shadow_host.count() == 0:
                LOG.info("Challenge element disappeared")
                # Allow the container page to finish rendering.
                try:
                    page.wait_for_load_state("domcontentloaded", timeout=5_000)
                except BrowserTimeoutError:
                    pass
                # Verify that the challenge really ended.
                if not page_looks_challenged(page):
                    return True
        except BrowserError as exc:
            LOG.debug("Error inspecting challenge: %s", exc)
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(1.0, remaining))
    LOG.error(f"Challenge did not complete within {timeout_seconds} seconds: {page.url}")
    return False


def goto(page: Page, url: str, headful: bool, challenge_timeout: int) -> bool:
    print(f"goto: url={url}")
    try:
        page.goto(url, wait_until="domcontentloaded", timeout=60_000)
        page.wait_for_load_state("networkidle", timeout=8_000)
    except BrowserTimeoutError:
        # Ad networks and analytics often keep connections open; DOM content
        # may still be fully usable.
        LOG.debug("Navigation/network-idle timeout for %s; inspecting current DOM", url)
    except BrowserError as exc:
        LOG.warning("Navigation failed for %s: %s", url, exc)
        return False

    print(f"goto: calling wait_for_manual_challenge")

    return wait_for_manual_challenge(page, headful, challenge_timeout)


def extract_package(
        page: Page,
        package: dict[str, Any],
        headful: bool,
        challenge_timeout: int,
    ) -> tuple[list[str], list[str]]:
    url = str(package.get("filecrypt_url", "")).strip()
    if not CONTAINER_RE.match(url):
        raise ValueError(f"Not a recognized Filecrypt container URL: {url!r}")

    # page = context.new_page()
    urls: list[str] = []
    dlc_urls: list[str] = []

    if 1: # keep indent
        if not goto(page, url, headful, challenge_timeout):
            raise RuntimeError("Filecrypt page did not become accessible")

        html = page.content()

        # Password-protected containers: ask interactively, then submit through
        # the page's own form. No password is written to the output JSON.
        password_input = page.locator('input[name="password"]#p4assw0rt')
        if password_input.count():
            password = package.get("password")
            if password is None and headful:
                password = input(f"Password for {package.get('name', url)!r}: ")
            if not password:
                raise RuntimeError(
                    "Container is password-protected; add a 'password' field "
                    "to this package or run with --headful."
                )
            password_input.fill(str(password))
            password_input.press("Enter")
            try:
                page.wait_for_load_state("domcontentloaded", timeout=20_000)
            except BrowserTimeoutError:
                pass

            print(f"extract_package: calling wait_for_manual_challenge")

            if not wait_for_manual_challenge(page, headful, challenge_timeout):
                raise RuntimeError("Challenge after password submission was not completed")
            html = page.content()

        # CNL payloads: encrypted URLs embedded directly in the page.
        for _jk, key_hex, encrypted, package_name in CNL_RE.findall(html):
            try:
                urls.extend(decrypt_cnl_payload(encrypted, key_hex))
            except (ValueError, binascii.Error) as exc:
                LOG.warning("Could not decrypt a CNL payload: %s", exc)

        # Weblinks: use a separate tab for each short link and follow its Go URL.
        # Manual challenge is supported when headful.
        for link_id in unique(re.findall(WEBLINK_RE, html)):
            link_page = page
            if 1: # keep indent
                link_url = urljoin(url, f"/Link/{link_id}.html")
                if not goto(link_page, link_url, headful, challenge_timeout):
                    continue
                for attempt in range(5):
                    link_html = link_page.content()
                    go_match = GO_RE.search(link_html)
                    if go_match:
                        go_url = go_match.group(0)
                        try:
                            response = link_page.goto(
                                go_url, wait_until="domcontentloaded", timeout=30_000
                            )
                            final_url = response.url if response else link_page.url
                            if final_url and final_url != go_url:
                                urls.append(final_url.replace("\x10", ""))
                            elif link_page.url and link_page.url != go_url:
                                urls.append(link_page.url.replace("\x10", ""))
                        except BrowserError as exc:
                            LOG.debug("Following Go URL failed: %s", exc)
                        break
                    time.sleep(1 + attempt)

        # DLC: this is a downloadable container, not a list of hoster URLs.
        for dlc_id in unique(DLC_RE.findall(html)):
            dlc_urls.append(urljoin(url, f"/DLC/{dlc_id}.dlc"))

        return unique(urls), unique(dlc_urls)


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract links from Filecrypt containers")
    parser.add_argument("input_json", type=Path, help="JSON file containing package objects")
    parser.add_argument("output_json", type=Path, help="Where to write enriched package JSON")
    parser.add_argument("--headful", action="store_true", help="Show Firefox and allow manual challenge completion")
    parser.add_argument("--challenge-timeout", type=int, default=180,
                        help="Seconds to wait after you press Enter (default: 180)")
    parser.add_argument("--log-level", default="INFO",
                        choices=("DEBUG", "INFO", "WARNING", "ERROR"))
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(message)s",
    )

    try:
        packages = json.loads(args.input_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        parser.error(f"Cannot read input JSON: {exc}")
    if not isinstance(packages, list):
        parser.error("Input JSON must contain a top-level list")

    results: list[dict[str, Any]] = []

    for package_num, decrypted_package in enumerate(decrypt_packages(packages, args), start=1):
        results.append(decrypted_package)

        # Save incrementally so a later interruption does not lose work.
        LOG.info(f"Writing {args.output_json}")
        args.output_json.parent.mkdir(parents=True, exist_ok=True)
        args.output_json.write_text(
            json.dumps(results + packages[package_num:], ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    r'''
    # Final output contains all packages, including any skipped/untouched tail.
    args.output_json.write_text(
        json.dumps(results, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    LOG.info(f"Done {args.output_json}")
    '''


def decrypt_packages(packages, args):

    camoufox_addons = [
        os.environ.get("FIREFOX_ADDON_DARKREADER"),
    ]
    camoufox_addons = list(filter(bool, camoufox_addons))
    for addon in camoufox_addons:
        print(f"adding camoufox addon: {addon}")

    camoufox_kwargs = dict(
        # headless=True,
        # headless=False, # debug: run the browser in headful mode
        headless=(not args.headful),

        # fix:
        # LeakWarning: Canvas and WebGL readback return random data,
        # as privacy.resistFingerprinting does in LibreWolf, Tor Browser and Mullvad Browser.
        # Stock Firefox does not do this, so the browser reads as a privacy-hardened Firefox.
        # It is on because the identity claims another OS or GPU than this machine's,
        # whose canvas would show the real one.
        # Pass `canvas_noise=False` to keep stock canvas behaviour.
        canvas_noise=False,

        # Human cursor movement
        humanize=True,

        config={
            # Read closed shadow roots
            "forceScopeAccess": True,
        },

        addons=camoufox_addons,
    )

    with (
            Camoufox(**camoufox_kwargs) as context,
            context.new_page() as page,
        ):
        # page = context.new_page()
        # page.goto("https://example.com")
        # time.sleep(10) # debug: keep the browser open

        print(f"using Camoufox version {context.version}")

        # uBlock Origin needs about 10 seconds to init filter lists on its first run
        # so we waste some time here
        dt = 10
        print(f"waiting for uBlock Origin to init filter lists: dt={dt}")
        if 1: # keep indent
            page.goto("https://ipfighter.com/bot-detection")
            # page.goto("https://antcpt.com/score_detector/")
            time.sleep(dt)

        # try:
        if 1: # keep indent
            for package_num, original in enumerate(packages, start=1):
                if not isinstance(original, dict):
                    LOG.warning(f"Item {package_num} is not an object; preserving it unchanged")
                    # results.append(original)
                    yield original
                    continue

                item = dict(original)
                label = item.get("name") or item.get("filecrypt_url") or f"package {package_num}"
                # no, packages can be an iterator, so len(packages) can be undefined
                # LOG.info(f"[{package_num}/{len(packages)}] Processing package {label}")
                LOG.info(f"Processing package {package_num}: {label}")

                try:
                    decrypted, dlc_urls = extract_package(
                        page, item, args.headful, args.challenge_timeout
                    )
                    item["decrypted_urls"] = decrypted
                    if dlc_urls:
                        item["dlc_urls"] = dlc_urls
                    item.pop("decryption_error", None)
                    LOG.info(f"Found {len(decrypted)} direct URLs, {len(dlc_urls)} DLC containers")
                    total_num_urls = len(decrypted) + len(dlc_urls)
                    if total_num_urls == 0:
                        print(f"error: found no URLs")
                        # return 1
                        yield original
                        continue
                except KeyboardInterrupt:
                    raise
                except Exception as exc:
                    item["decrypted_urls"] = []
                    item["decryption_error"] = f"{type(exc).__name__}: {exc}"
                    LOG.exception("Failed to process %s", label)

                yield item

        r'''
        finally:
            # TODO is this needed with the context block?
            page.close()
            context.close()
        '''


if __name__ == "__main__":
    raise SystemExit(main())
