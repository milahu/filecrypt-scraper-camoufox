# Generate Filecrypt Scraper Script

**User:** Anonymous  
**Created:** 2026/10/31 18:52:01  
**Updated:** 2026/10/31 20:02:25  
**Exported:** 2026/11/10 20:43:38  
**Link:** [<https://chatgpt.com/c/6ae62ac0-e48c-83eb-9158-e7cd443118a3?src=history_search>](https://chatgpt.com/c/6ae62ac0-e48c-83eb-9158-e7cd443118a3?src=history_search)

## Prompt:

10/31/2026, 6:58:10 PM

generate a python script to scrape download links from a filecrypt.cc container url like `https://filecrypt.cc/Container/479215D644.html`

the scraper should use the `patchright` library to control a chrome browser (`patchright` is a drop-in replacement for `playwright`)

the scraper should be a CLI script, which accepts a filecrypt.cc container URL as positional argument, and which prints all the scraped download links to stdout

the scraper should have the CLI flag "--headful" to make the chrome browser run in "headful" mode (the opposite of "headless")

the scraper can be based on this filecrypt.cc scraper:

`https://github.com/milahu/pyload/blob/develop/src/pyload/plugins/decrypters/FilecryptCc.py`

``` python

#
# Test links:
#   http://filecrypt.cc/Container/64E039F859.html

import base64
import re
import urllib.parse
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from pyload.core.network.http.exceptions import BadHeader
from pyload.core.network.http.http_request import HTTPRequest
from pyload.core.utils.convert import to_str

from ..anticaptchas.CoinHive import CoinHive
from ..anticaptchas.ReCaptcha import ReCaptcha
from ..anticaptchas.SolveMedia import SolveMedia
from ..anticaptchas.CutCaptcha import CutCaptcha
from ..anticaptchas.CircleCaptcha import CircleCaptcha
from ..anticaptchas.POWCaptchaFilecryptCc import POWCaptchaFilecryptCc as POWCaptcha

from ..base.decrypter import BaseDecrypter
from ..helpers import replace_patterns

from pyload.plugins.decrypters.ClickNLoad import clicknload_decrypt2

class FilecryptCc(BaseDecrypter):
    __name__ = "FilecryptCc"
    __type__ = "decrypter"
    __version__ = "0.52"
    __status__ = "testing"

    __pattern__ = r"https?://(?:www\.)?filecrypt\.(?:cc|co)/Container/\w+"
    __config__ = [
        ("enabled", "bool", "Activated", True),
        ("handle_mirror_pages", "bool", "Handle Mirror Pages", True),
    ]

    __description__ = """Filecrypt.cc decrypter plugin"""
    __license__ = "GPLv3"
    __authors__ = [
        ("zapp-brannigan", "fuerst.reinje@web.de"),
        ("GammaC0de", "nitzo2001[AT]yahoo[DOT]com"),
    ]

    COOKIES = [("filecrypt.cc", "lang", "en")]
    URL_REPLACEMENTS = [(r"filecrypt.co", "filecrypt.cc")]

    PACKAGE_NAME_PATTERN = r"<h2>([^<]+)</h2>"

    DLC_LINK_PATTERN = r'onclick="DownloadDLC\(\'(.+)\'\);">'

    # TODO remove. all these links are protected by captchas
    # so it is better to add links via clicknload (CNL)
    # <button id="055AC1A2EE" onclick="try{openLink(this.getAttribute('data-055ac1a2ee'), this);}"
    #   data-055ac1a2ee="591096EB26" class="download" target="_blank" title="Download"></button>
    WEBLINK_PATTERN = r"<button onclick=\"[\w\-]+?/\*\d+?\*/\('([\w/-]+?)',"

    # TODO how do they escape singlequotes in the package name?
    # "&apos;"? "&#39;"? "&#x27;"?
    # package name is the last argument to CNLPOP
    CNL_PATTERN = r"""CNLPOP\('([^']+)', '([^']+)', '([^']+)', '(.*?)'\);"""

    # FIXME where is: status, url, hoster
    MIRROR_PAGE_PATTERN = r'"[\w]*" href="(https?://(?:www\.)?filecrypt.cc/Container/\w+\.html\?mirror=\d+)">'
    OFFLINE_PATTERN = r">Not Found<"

    CAPTCHA_PATTERN = r"<h2>Security Check</h2>"
    INTERNAL_CAPTCHA_PATTERN = r'<img id="nc" .* src="(.+?)"'
    CIRCLE_CAPTCHA_PATTERN = r'<input type="image" src="(.+?)"'
    KEY_CAPTCHA_PATTERN = r"<script language=JavaScript src='(http://backs\.keycaptcha\.com/swfs/cap\.js)'"
    SOLVEMEDIA_CAPTCHA_PATTERN = r'<script type="text/javascript" src="(https?://api(?:-secure)?\.solvemedia\.com/papi/challenge.+?)"'
    CUTCAPTCHA_CAPTCHA_KEY_PATTERN = r'''\sCUTCAPTCHA_MISERY_KEY\s*=\s*["']([0-9a-f]{40})["']'''
    CUTCAPTCHA_API_KEY_PATTERN = r'''cutcaptcha\.net/captcha/([0-9a-zA-Z]+)\.js'''
    POW_CAPTCHA_PATTERN = r'''<div class="pow-captcha" id="pow-captcha" .*>\n'''

    CAPTCHA_PATTERNS = [
        POWCaptcha.POW_CHALLENGE_PATTERN,
        INTERNAL_CAPTCHA_PATTERN,
        CIRCLE_CAPTCHA_PATTERN,
        KEY_CAPTCHA_PATTERN,
        SOLVEMEDIA_CAPTCHA_PATTERN,
        CUTCAPTCHA_CAPTCHA_KEY_PATTERN,
    ]

    def setup(self):
        self.urls = []
        self.package_name = None

        try:
            self.req.http.close()
        except Exception:
            pass

        self.req.http = HTTPRequest(
            cookies=self.req.cj,
            options=self.pyload.request_factory.get_options(),
            limit=2_000_000,
        )

    def decrypt(self, pyfile):
        self.pyfile = pyfile
        pyfile.url = replace_patterns(pyfile.url, self.URL_REPLACEMENTS)

        self.data = self._filecrypt_load_url(pyfile.url)
        #self.log_info("self.data[:1000]", self.data[:1000])

        if re.search(self.OFFLINE_PATTERN, self.data):
            self.offline()

        self.log_info("handle_password_protection")
        self.handle_password_protection()

        self.site_with_links = self.handle_captcha(pyfile.url)
        #self.log_info("self.site_with_links", repr(self.site_with_links)[:1000])

        if self.site_with_links is None:
            # FIXME why? captcha should be solved
            self.log_info("retry_captcha")
            self.retry_captcha()

        elif self.site_with_links == "":
            self.log_info("retry")
            self.retry()

        if self.config.get("handle_mirror_pages"):
            self.handle_mirror_pages()

        package_name = self.package_name or self.get_package_name()

        for handle in (
            self.handle_CNL,
            self.handle_weblinks,
            self.handle_dlc_container,
        ):
            handle()
            if self.urls:
                self.packages = [
                    (package_name, self.urls, package_name)
                ]
                return

    def get_package_name(self):
        m = re.search(self.PACKAGE_NAME_PATTERN, self.site_with_links)
        if m:
            name = m.group(1).strip()
            if name:
                return name
        # keep the pyload package name
        return self.pyfile.package().name

    def handle_mirror_pages(self):
        if "mirror=" not in self.site_with_links:
            return

        mirror = re.findall(self.MIRROR_PAGE_PATTERN, self.site_with_links)

        self.log_info(self._("Found {} mirrors").format(len(mirror)))

        for i in mirror[1:]:
            self.site_with_links = self.site_with_links + self._filecrypt_load_url(i)

    def handle_password_protection(self):
        # <input type="text" name="password" id="p4assw0rt"  autofocus autocomplete="off" placeholder="Passwort eingeben">
        if (
            re.search(
                r'name="password" id="p4assw0rt"',
                self.data,
            )
            is None
            or
            re.search(
                r'<!--\s*<input[^>]+name="password" id="p4assw0rt"',
                self.data,
            )
        ):
            self.log_info("not found password input")
            return

        self.log_info(self._("Folder is password protected"))

        password = self.get_password()

        if not password:
            self.fail(
                self._("Please enter the password in package section and try again")
            )

        # <input type="text" name="password" id="p4assw0rt"  autofocus autocomplete="off" placeholder="Passwort eingeben">
        self.data = self._filecrypt_load_url(
            self.pyfile.url, post={"password": password}
        )

    def search_captcha(self, html):
        for pattern in self.CAPTCHA_PATTERNS:
            if match := re.search(pattern, html, flags=re.DOTALL):
                self.log_info("search_captcha: found captcha", repr(match.group(0)))
                return True
        return False

    def handle_captcha(self, submit_url):
        if self.search_captcha(self.data):
            for handle in (
                self._handle_pow_captcha,
                self._handle_internal_captcha,
                self._handle_circle_captcha,
                self._handle_solvemedia_captcha,
                self._handle_keycaptcha_captcha,
                self._handle_coinhive_captcha,
                self._handle_recaptcha_captcha,
                self._handle_cutcaptcha_captcha,
            ):
                res = handle(submit_url)
                # res: html code
                if res is None:
                    continue
                elif res == "":
                    return res
                if self.search_captcha(res):
                    self.log_info("found another captcha in res")
                    return None

                else:
                    return res

            else:
                self.log_warning(self._("Unknown captcha found, retrying"))
                return ""

        else:
            self.log_info(self._("No captcha found"))
            return self.data

    def _handle_pow_captcha(self, url):
        retry_max = 10
        data = self.data
        self.captcha = POWCaptcha(self.pyfile)
        for retry_idx in range(retry_max):
            m = re.search(POWCaptcha.POW_CHALLENGE_PATTERN, data, flags=re.DOTALL)
            if not m:
                if retry_idx == 0:
                    self.log_error("POWCaptcha: Not found POW_CHALLENGE_PATTERN")
                    return None
                else:
                    # solved captchas
                    return data
            if retry_idx > 0:
                self.log_debug(f"POWCaptcha: try {retry_idx + 1} of {retry_max}")
            # the user has to click the captcha
            # to start the POW calculation
            time.sleep(2)
            params = self.captcha.challenge(data)
            data = self._filecrypt_load_url(url, post=params)
        # no. this is handled in "def handle_captcha"
        # else:
        #     # reached retry_max
        #     m = re.search(POWCaptcha.POW_CHALLENGE_PATTERN, data, flags=re.DOTALL)
        #     if m:
        #         # failed to solve captcha
        return data

    def _handle_internal_captcha(self, url):
        m = re.search(self.INTERNAL_CAPTCHA_PATTERN, self.data)
        if m is None:
            return
        captcha_url = urllib.parse.urljoin(self.pyfile.url, m.group(1))

        self.log_debug(f"Internal Captcha URL: {captcha_url}")

        captcha_code = self.captcha.decrypt(captcha_url, input_type="gif")

        return self._filecrypt_load_url(
            url, post={"recaptcha_response_field": captcha_code}
        )

    def _handle_circle_captcha(self, url):
        m = re.search(self.CIRCLE_CAPTCHA_PATTERN, self.data)
        if m is None:
            return
        # Please click into the open circle to continue.
        self.log_debug(
            "Circle Captcha URL: {}".format(
                urllib.parse.urljoin(self.pyfile.url, m.group(1))
            )
        )
        captcha_url = urllib.parse.urljoin(self.pyfile.url, m.group(1))
        self.log_debug(f"Circle Captcha URL: {captcha_url}")
        captcha_image = self._filecrypt_load_url(captcha_url, decode=False)
        self.captcha = CircleCaptcha(self.pyfile)
        captcha_coords = self.captcha.challenge(captcha_image)
        return self._filecrypt_load_url(
            # TODO parse dynamic input name: "button" or "buttonx" or ...
            #url, post={"button.x": captcha_coords[0], "button.y": captcha_coords[1]}
            url, post={"buttonx.x": captcha_coords[0], "buttonx.y": captcha_coords[1]}
        )

    def _handle_solvemedia_captcha(self, url):
        m = re.search(self.SOLVEMEDIA_CAPTCHA_PATTERN, self.data)
        if m is None:
            return
        self.log_debug(
            "Solvemedia Captcha URL: {}".format(
                urllib.parse.urljoin(self.pyfile.url, m.group(1))
            )
        )

        solvemedia = SolveMedia(self.pyfile)
        captcha_key = solvemedia.detect_key()

        if captcha_key:
            self.captcha = solvemedia
            response, challenge = solvemedia.challenge(captcha_key)

            return self._filecrypt_load_url(
                url,
                post={"adcopy_response": response, "adcopy_challenge": challenge},
            )

    def _handle_keycaptcha_captcha(self, url):
        m = re.search(self.KEY_CAPTCHA_PATTERN, self.data)
        if m is None:
            return
        self.log_debug(
            "Keycaptcha Captcha URL: {} unsupported, retrying".format(m.group(1))
        )
        return ""

    def _handle_coinhive_captcha(self, url):
        coinhive = CoinHive(self.pyfile)

        coinhive_key = coinhive.detect_key()
        if coinhive_key:
            self.captcha = coinhive
            token = coinhive.challenge(coinhive_key)

            return self._filecrypt_load_url(url, post={"coinhive-captcha-token": token})

        else:
            return None

    def _handle_recaptcha_captcha(self, url):
        recaptcha = ReCaptcha(self.pyfile)
        captcha_key = recaptcha.detect_key()

        if captcha_key:
            self.captcha = recaptcha
            response = recaptcha.challenge(captcha_key)

            return self._filecrypt_load_url(
                url, post={"g-recaptcha-response": response}
            )

        else:
            return None

    def _handle_cutcaptcha_captcha(self, url):
        # based on jdownloader
        # src/org/jdownloader/captcha/v2/challenge/cutcaptcha/AbstractCaptchaHelperCutCaptcha.java
        m = re.search(self.CUTCAPTCHA_CAPTCHA_KEY_PATTERN, self.data)
        if not m:
            return None
        captcha_key = m.group(1)
        m = re.search(self.CUTCAPTCHA_API_KEY_PATTERN, self.data)
        if not m:
            self.log_error("Cutcaptcha: Not found CUTCAPTCHA_API_KEY_PATTERN")
            return None
        api_key = m.group(1)
        # jd: CutCaptchaChallenge(plugin, siteKey, apiKey)
        self.captcha = CutCaptcha(self.pyfile)
        captcha_token = self.captcha.challenge(captcha_key, api_key)
        self.log_debug(f"Cutcaptcha: captcha_token={captcha_token}")
        return self._filecrypt_load_url(url, post={"cap_token": captcha_token})

    def handle_dlc_container(self):
        m = re.search(r"const (\w+) = DownloadDLC;", self.site_with_links)
        if m is not None:
            self.site_with_links = self.site_with_links.replace(m.group(1), "DownloadDLC")
        dlcs = re.findall(self.DLC_LINK_PATTERN, self.site_with_links)

        if not dlcs:
            return

        for dlc in dlcs:
            self.urls.append(
                urllib.parse.urljoin(self.pyfile.url, "/DLC/{}.dlc".format(dlc))
            )

    def handle_weblinks(self):
        try:
            links = re.findall(self.WEBLINK_PATTERN, self.site_with_links)

            for link in links:
                link = "https://filecrypt.cc/Link/{}.html".format(link)
                for i in range(5):
                    self.data = self._filecrypt_load_url(link)
                    m = re.search(r'https://filecrypt\.cc/index\.php\?Action=Go&id=\w+', self.data)
                    if m is not None:
                        headers = self._filecrypt_load_url(m.group(0), just_header=True)
                        url = headers["location"]
                        url = url.replace("\x10", "") # remove "Data Link Escape" chars
                        self.urls.append(url)
                        break

                else:
                    self.log_error(self._("Weblink could not be found"))

        except Exception as exc:
            self.log_debug(f"Error decrypting weblinks: {exc}")

    def handle_CNL(self):
        # based on https://filecrypt.cc/helper.html
        try:
            m = re.search(r"const (\w+) = CNLPOP;", self.site_with_links)
            if m is not None:
                self.site_with_links = self.site_with_links.replace(m.group(1), "CNLPOP")

            cnl_data_list = re.findall(
                self.CNL_PATTERN,
                self.site_with_links,
            )
            for cnl_data in cnl_data_list:
                # jk = cnl_data[0] # jk return value: "A397C71436" # noise?
                key_hexstr = cnl_data[1] # 32 char hex string
                assert len(key_hexstr) == 32, f"bad key_hexstr: {key_hexstr!r}"
                assert re.fullmatch(r"[0-9a-fA-F]+", key_hexstr), f"bad key_hexstr: {key_hexstr!r}"
                crypted = cnl_data[2] # long base64 string
                # NOTE self.package_name is the package name of the last cnl_data
                # but usually there is only one cnl_data
                if cnl_data[3]:
                    self.package_name = cnl_data[3]
                links = clicknload_decrypt2(crypted, key_hexstr)
                self.urls.extend(links)

        except Exception as exc:
            self.log_debug(f"Error decrypting CNL: {type(exc).__name__}: {exc}")

    def _filecrypt_load_url(self, *args, **kwargs):
        try:
            return self.load(*args, **kwargs)
        except BadHeader as exc:
            if exc.code == 500:
                return exc.content
            else:
                raise
```

(...currently this filecrypt.cc plugin for pyload is broken, because pyload is using the curl http client library, but that is getting blocked by cloudflare, but otherwise, the request/response logic of filecrypt.cc should be mostly the same)

the scraper can be based on this filecrypt.cc scraper:

`https://github.com/dayate/FilecryptScraper_MkvDrama/blob/main/core/scraper.py`

``` python
"""
Modul utama untuk scraping data dari FileCrypt
"""

import time
import logging
import re
from typing import List, Optional
from playwright.sync_api import Page
from models.data_models import ScrapedData
from core.database import DatabaseHandler
from config import DEFAULT_CONFIG
from .logger import BatchLogger

class FileCryptScraper:
    def __init__(self, page: Page):
        self.page = page
        self.timeouts = DEFAULT_CONFIG.timeouts
        self.providers = DEFAULT_CONFIG.providers
        self.pixeldrain = DEFAULT_CONFIG.pixeldrain
        self.user_agents = DEFAULT_CONFIG.user_agents
        self.scraper_config = DEFAULT_CONFIG.scraper
        self.database_handler = DatabaseHandler()
        self.container_title = "N/A"

    def detect_password(self) -> bool:
        try:
            return bool(self.page.query_selector("h2:has-text('Password required')"))
        except Exception as e:
            logging.error(f"[ERROR] Error deteksi password: {str(e)}")
            return False

    def handle_password(self) -> bool:
        if not self.detect_password():
            logging.info("🔓⠀URL tidak membutuhkan password")
            return True
        logging.info("🔐⠀Menunggu input password...")
        start_time = time.time()
        timeout = self.timeouts.password
        while self.detect_password():
            if time.time() - start_time > timeout:
                logging.error(f"[ERROR] Timeout password setelah {timeout} detik")
                return False
            time.sleep(self.timeouts.password_check)
        logging.info("🔓⠀Password berhasil ditangani")
        return True

    def detect_captcha(self) -> bool:
        try:
            return bool(self.page.query_selector("h2:has-text('Security prompt')"))
        except Exception as e:
            logging.error(f"[ERROR] Error deteksi captcha: {str(e)}")
            return False

    def handle_captcha(self) -> bool:
        if not self.detect_captcha():
            logging.info("🔓⠀CAPTCHA tidak terdeteksi")
            return True
        logging.info("🔐⠀Menunggu penyelesaian CAPTCHA...")
        start_time = time.time()
        timeout = self.timeouts.captcha
        while self.detect_captcha():
            if time.time() - start_time > timeout:
                logging.error(f"[ERROR] Timeout CAPTCHA setelah {timeout} detik")
                return False
            time.sleep(self.timeouts.captcha_check)
        logging.info("🔓⠀CAPTCHA berhasil diselesaikan")
        return True

    def get_available_providers(self) -> List[str]:
        try:
            # Tunggu elemen select provider muncul
            self.page.wait_for_selector("select#x_h", timeout=self.timeouts.selector_wait)
            select_element = self.page.query_selector("select#x_h")

            providers = set()
            if select_element:
                options = select_element.query_selector_all("option")
                for option in options:
                    provider_text = option.text_content().strip()
                    # Abaikan opsi default seperti "Select Provider" atau yang kosong
                    if not provider_text or "select" in provider_text.lower():
                        continue

                    providers.add(provider_text)

            return sorted(providers)
        except Exception as e:
            logging.error(f"[ERROR] Gagal mendapatkan provider: {str(e)}")
            return []

    def get_additional_info(self) -> tuple[str, str]:
        """
        Mengambil judul dan total episode dari halaman
        Mengembalikan (judul, total_episodes)
        """
        try:
            # Tunggu hingga elemen judul muncul
            self.page.wait_for_selector("h1#x_t", timeout=self.timeouts.selector_wait)
            title_element = self.page.query_selector("h1#x_t")
            title = title_element.text_content().strip() if title_element else "Unknown"
            self.container_title = (
                title
                if title and title.lower() not in ("n/a", "", "unknown")
                else "Unknown"
            )

            # Hitung total episode dari jumlah option di select#x_e
            total_episodes = 0
            select_element = self.page.query_selector("select#x_e")
            if select_element:
                options = select_element.query_selector_all("option")
                total_episodes = max(0, len(options) - 1)

            total_episodes_str = f"{total_episodes} Episode"

            return self.container_title, total_episodes_str
        except Exception as e:
            logging.debug(f"[MAIN] Gagal mengambil info tambahan: {str(e)}")
            self.container_title = "Unknown"
            return "Unknown", "0 Episode"

    def scrape_file_info(
        self,
        selected_provider: Optional[str] = None,
        all_providers: Optional[List[str]] = None,
    ) -> List[ScrapedData]:
        final_data = []
        try:
            self.page.wait_for_selector("tr.kwj3", timeout=self.timeouts.selector_wait)
            rows = self.page.query_selector_all("tr.kwj3")
            target_code = (
                self.page.url.strip("/").split("/")[-1].replace(".html", "").strip()
                if self.page.url
                else "unknown"
            )
            total_rows = len(rows)
            process_logger = BatchLogger(
                total_items=total_rows * 2,
                actual_items=total_rows,
                process_name="SCRAPER",
            )
            all_items = []
            items_to_scrape = []
            skipped_items = 0
            progress_count = 0
            pixeldrain_bypass_index = 0  # Tambahkan indeks untuk round-robin

            # Fase 1: Proses baris
            for idx, row in enumerate(rows, 1):
                try:
                    provider_element = row.query_selector("td[title] a.external_link")
                    provider = (
                        provider_element.text_content().strip().lower()
                        if provider_element
                        else "N/A"
                    )
                    if any(p in provider for p in self.providers.send_aliases):
                        provider = "send"
                    provider = provider.capitalize()

                    if (
                        not selected_provider
                        or provider.lower() == selected_provider.lower()
                    ):
                        title = (
                            row.query_selector("td[title]").get_attribute("title")
                            if row.query_selector("td[title]")
                            else "N/A"
                        )

                        if self.database_handler.is_data_exists(
                            title, provider, target_code
                        ):
                            skipped_items += 1
                            existing_item = (
                                self.database_handler.get_data_by_title_provider(
                                    title, provider, target_code
                                )
                            )
                            if existing_item:
                                existing_item.container_title = self.container_title
                                all_items.append(existing_item)
                            continue

                        item = ScrapedData(
                            title=title,
                            provider=provider,
                            size=(
                                row.query_selector("td:nth-of-type(3)")
                                .text_content()
                                .strip()
                                if row.query_selector("td:nth-of-type(3)")
                                else "N/A"
                            ),
                            status=(
                                " ".join(
                                    row.query_selector("td.status i")
                                    .get_attribute("class")
                                    .split()
                                )
                                if row.query_selector("td.status i")
                                else "offline"
                            ),
                            download_url="N/A",
                            bypass_url="N/A",
                            target_code=target_code,
                            container_title=self.container_title,
                            download_button=row.query_selector("td button.download"),
                            row_element=row,
                        )
                        all_items.append(item)
                        items_to_scrape.append(item)

                    progress_count += 1
                    process_logger.log_progress(progress_count)
                except Exception as e:
                    logging.debug(f"[MAIN] Baris {idx} gagal: {str(e)}")
                    continue

            if not items_to_scrape:
                process_logger.log_complete(skipped_items)
                return all_items

            # Fase 2: Proses batch
            batch_size = self.scraper_config.max_batch_size
            total_batches = (len(items_to_scrape) + batch_size - 1) // batch_size
            for batch_start in range(0, len(items_to_scrape), batch_size):
                batch_end = min(batch_start + batch_size, len(items_to_scrape))
                current_batch = items_to_scrape[batch_start:batch_end]

                popups = []
                for item in current_batch:
                    try:
                        with self.page.expect_popup(
                            timeout=self.timeouts.popup
                        ) as popup_info:
                            if item.download_button:
                                item.download_button.click()
                            else:
                                logging.debug(
                                    f"[MAIN] Tidak ada tombol download untuk {item.title}"
                                )
                                item.download_url = "ERROR"
                                item.bypass_url = "ERROR"
                                continue
                        popups.append((item, popup_info.value))
                    except Exception as e:
                        logging.debug(
                            f"[MAIN] Gagal membuka popup untuk {item.title}: {str(e)}"
                        )
                        item.download_url = "ERROR"
                        item.bypass_url = "ERROR"

                for item, popup in popups:
                    try:
                        popup.wait_for_load_state(
                            "domcontentloaded", timeout=self.timeouts.page_load
                        )
                        item.download_url = popup.url

                        if "pixeldrain.com" in item.download_url.lower():
                            code = item.download_url.split("/")[-1]
                            # Gunakan URL bypass secara bergilir
                            selected_bypass = self.pixeldrain.bypass_urls[
                                pixeldrain_bypass_index
                                % len(self.pixeldrain.bypass_urls)
                            ]
                            item.bypass_url = selected_bypass.replace("CODE-FILE", code)
                            pixeldrain_bypass_index += 1  # Increment indeks

                        # Bersihkan atribut sementara segera setelah selesai digunakan
                        for attr in ["row_element", "download_button"]:
                            if hasattr(item, attr):
                                delattr(item, attr)

                        popup.close()
                    except Exception as e:
                        logging.debug(
                            f"[MAIN] Gagal memproses popup untuk {item.title}: {str(e)}"
                        )
                        item.download_url = "ERROR"
                        item.bypass_url = "ERROR"

                progress_count += len(current_batch)
                process_logger.log_progress(min(progress_count, total_rows * 2))
                time.sleep(self.timeouts.batch_delay)

            process_logger.log_complete(skipped_items)

            # Gabungkan data
            scraped_keys = {
                (item.title.lower().strip(), item.provider.lower().strip())
                for item in items_to_scrape
                if item.download_url != "ERROR"
            }

            for item in all_items:
                item_key = (item.title.lower().strip(), item.provider.lower().strip())
                if item_key in scraped_keys:
                    for scraped_item in items_to_scrape:
                        if (
                            scraped_item.title.lower().strip()
                            == item.title.lower().strip()
                            and scraped_item.provider.lower().strip()
                            == item.provider.lower().strip()
                            and scraped_item.download_url != "ERROR"
                        ):
                            scraped_item.container_title = self.container_title
                            final_data.append(scraped_item)
                            break
                else:
                    item.container_title = self.container_title
                    final_data.append(item)

            return final_data

        except Exception as e:
            logging.error(f"[ERROR] Gagal scrape di luar proses utama: {str(e)}")
            return final_data if final_data else []
```

## Response:

10/31/2026, 6:58:12 PM

> **Searched 7 websites**
>
> Worked for 12s

Below is a standalone Python CLI scraper using `patchright`'s synchronous API. It launches Chrome, loads a Filecrypt container, extracts links from the page, follows Filecrypt redirect pages when possible, and prints one download URL per line to stdout.

It follows the main extraction strategies from the supplied pyLoad implementation:

- **CNL links:** decrypts Filecrypt's Click'n'Load payload using AES.
- **Weblinks:** follows Filecrypt `/Link/...html` pages and resolves redirects.
- **Download buttons:** clicks buttons and captures popup URLs, as in the second scraper.
- **Mirror pages:** optionally follows additional container pages.
- **Password and CAPTCHA prompts:** allows you to solve them manually in the browser instead of attempting to bypass CAPTCHA protections.

## 1. Install dependencies

Patchright supports a synchronous Python API and can install its own Chromium browser; for an installed Google Chrome, you can instead launch with `channel="chrome"`. \<Cite refs={\["turn718384search0","turn718384search11"\]}/\>

Save the following script as `filecrypt_scraper.py`.

## 2. Python script

This version extracts ordinary links, resolves Filecrypt weblinks, captures popup URLs opened by download buttons, follows mirror containers, and waits for you to complete password or CAPTCHA challenges when needed. It deliberately does not automate CAPTCHA solving.

<CodeBlock language="python" editable>
#!/usr/bin/env python3
"""Extract download links from a Filecrypt container using Patchright."""

import argparse  
import re  
import sys  
import time  
from urllib.parse import urljoin, urlparse

from patchright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

FILECRYPT_HOSTS = {"filecrypt.cc", "[www.filecrypt.cc](http://www.filecrypt.cc)", "filecrypt.co", "[www.filecrypt.co"}](http://www.filecrypt.co"})

MIRROR_RE = re.compile(  
r"""https?://(?:www.)?filecrypt.(?:cc\|co)/Container/  
\[\w\]+.html?mirror=\d+""",  
re.IGNORECASE \| re.VERBOSE,  
)

GO_RE = re.compile(  
r"""https://filecrypt.cc/index.php?Action=Go&id=\[\w\]+""",  
re.IGNORECASE,  
)

def is_filecrypt_url(url):  
parsed = urlparse(url)  
return parsed.scheme in {"http", "https"} and (  
parsed.hostname or ""  
).lower() in FILECRYPT_HOSTS

def unique(items):  
return list(dict.fromkeys(item for item in items if item))

def collect_page_links(page):  
"""Collect links exposed by the current page's HTML and DOM."""  
links = page.evaluate(  
"""() =\> {  
const result = new Set();

            for (const el of document.querySelectorAll(
                'a[href], area[href], iframe[src]'
            )) {
                const value = el.href || el.src;
                if (value) result.add(value);
            }

            // Filecrypt's encrypted Click'n'Load payload is not a URL.
            // Capture explicit DLC links when present.
            for (const el of document.querySelectorAll('[onclick]')) {
                const text = el.getAttribute('onclick') || '';
                const match = text.match(
                    /DownloadDLC\$['"]([^'"]+)['"]\$/
                );
                if (match) {
                    result.add(
                        new URL('/DLC/' + match[1] + '.dlc', location.href).href
                    );
                }
            }

            return [...result];
        }"""
    )

    return unique(links)

def wait_for_manual_challenge(page, timeout):  
"""Wait for the user to complete a password or CAPTCHA challenge."""  
try:  
page.wait_for_function(  
"""() =\> {  
const text = document.body?.innerText \|\| '';  
const passwordForm = document.querySelector(  
'input\[name="password"\], \#p4assw0rt'  
);  
const captcha = /security check\|security prompt\|captcha/i.test(text);  
return !passwordForm && !captcha;  
}""",  
timeout=timeout \* 1000,  
)  
except PlaywrightTimeoutError:  
print(  
"Warning: challenge may still be present; continuing with "  
"whatever links are available.",  
file=sys.stderr,  
)

def resolve_filecrypt_weblink(page, url):  
"""Open a Filecrypt /Link page and look for its outbound destination."""  
try:  
page.goto(url, wait_until="domcontentloaded", timeout=45000)  
page.wait_for_timeout(1200)

        # Filecrypt may expose the redirect URL in its HTML or navigate
        # directly to the target.
        html = page.content()
        match = GO_RE.search(html)
        if match:
            page.goto(match.group(0), wait_until="domcontentloaded", timeout=30000)
            page.wait_for_timeout(1000)

        current = page.url
        if current and not is_filecrypt_url(current):
            return current

        # Also inspect links and redirect hints in the rendered document.
        for candidate in collect_page_links(page):
            if not is_filecrypt_url(candidate):
                return candidate

    except Exception as exc:
        print(f"Warning: could not resolve {url}: {exc}", file=sys.stderr)

    return None

def main():  
parser = argparse.ArgumentParser(  
description="Extract download links from a Filecrypt container."  
)  
parser.add_argument("url", help="Filecrypt container URL")  
parser.add_argument(  
"--headful",  
action="store_true",  
help="Show the browser window (headful mode)",  
)  
parser.add_argument(  
"--challenge-timeout",  
type=int,  
default=180,  
help="Seconds to wait for manual password/CAPTCHA completion (default: 180)",  
)  
args = parser.parse_args()

    if not is_filecrypt_url(args.url):
        parser.error("URL must be an http(s) Filecrypt container URL")

    discovered = []
    visited_containers = set()
    pending_containers = [args.url]

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=not args.headful,
            # To use installed Google Chrome instead, uncomment:
            # channel="chrome",
        )
        context = browser.new_context()
        page = context.new_page()
        page.set_default_timeout(10000)

        try:
            while pending_containers:
                container_url = pending_containers.pop(0)
                if container_url in visited_containers:
                    continue
                visited_containers.add(container_url)

                print(f"Opening {container_url}", file=sys.stderr)
                try:
                    page.goto(
                        container_url,
                        wait_until="domcontentloaded",
                        timeout=60000,
                    )
                    page.wait_for_timeout(1500)
                except Exception as exc:
                    print(f"Warning: page load failed: {exc}", file=sys.stderr)
                    continue

                body_text = page.locator("body").inner_text(timeout=10000)
                needs_challenge = (
                    re.search(
                        r"security check|security prompt|captcha|password required",
                        body_text,
                        re.IGNORECASE,
                    )
                    or page.locator(
                        'input[name="password"], #p4assw0rt'
                    ).count() > 0
                )

                if needs_challenge:
                    print(
                        "Complete any password/CAPTCHA challenge in the browser.",
                        file=sys.stderr,
                    )
                    if not args.headful:
                        print(
                            "Rerun with --headful to interact with the browser.",
                            file=sys.stderr,
                        )
                    else:
                        wait_for_manual_challenge(page, args.challenge_timeout)
                        page.wait_for_timeout(1000)

                # Collect links and mirror pages from the current container.
                page_links = collect_page_links(page)
                discovered.extend(
                    link for link in page_links if not is_filecrypt_url(link)
                )

                html = page.content()
                for mirror in MIRROR_RE.findall(html):
                    if mirror not in visited_containers:
                        pending_containers.append(mirror)

                # Follow Filecrypt Link pages.
                link_pages = [
                    link for link in page_links
                    if re.search(r"/Link/[^/?#]+\.html", urlparse(link).path, re.I)
                ]

                # Also look for links encoded in onclick handlers.
                onclick_values = page.locator("[onclick]").evaluate_all(
                    "(els) => els.map(el => el.getAttribute('onclick') || '')"
                )
                for onclick in onclick_values:
                    match = re.search(
                        r"""['"]([\w/-]+)['"]\s*,\s*""",
                        onclick,
                    )
                    if match and "DownloadDLC" not in onclick:
                        token = match.group(1).strip("/")
                        if token and not token.startswith("http"):
                            link_pages.append(
                                f"https://filecrypt.cc/Link/{token}.html"
                            )

                # Resolve each Link page in a separate tab so the container
                # stays available for further button clicks.
                resolver = context.new_page()
                try:
                    for link_url in unique(link_pages):
                        resolved = resolve_filecrypt_weblink(resolver, link_url)
                        if resolved:
                            discovered.append(resolved)
                finally:
                    resolver.close()

                # Click download buttons and capture popup destinations.
                buttons = page.locator("button.download")
                count = buttons.count()
                for index in range(count):
                    try:
                        button = buttons.nth(index)
                        if not button.is_visible():
                            continue

                        with page.expect_popup(timeout=5000) as popup_info:
                            button.click()
                        popup = popup_info.value

                        try:
                            popup.wait_for_load_state(
                                "domcontentloaded", timeout=15000
                            )
                        except PlaywrightTimeoutError:
                            pass

                        if popup.url and popup.url != "about:blank":
                            discovered.append(popup.url)
                        else:
                            # Some sites open a popup before navigating.
                            popup.wait_for_timeout(1500)
                            if popup.url and popup.url != "about:blank":
                                discovered.append(popup.url)

                        popup.close()
                    except PlaywrightTimeoutError:
                        # Button did not open a popup; it may use another flow.
                        continue
                    except Exception as exc:
                        print(
                            f"Warning: download button {index + 1}: {exc}",
                            file=sys.stderr,
                        )

                # Keep only URLs that look like actual destinations. Filecrypt
                # container and Link pages are navigation, not final links.
                discovered = unique(
                    url for url in discovered
                    if urlparse(url).scheme in {"http", "https"}
                    and not (
                        is_filecrypt_url(url)
                        and re.search(
                            r"/(?:Container|Link)/",
                            urlparse(url).path,
                            re.IGNORECASE,
                        )
                    )
                )

        finally:
            browser.close()

    # stdout contains URLs only; diagnostics go to stderr.
    for url in unique(discovered):
        print(url)

if **name** == "**main**":  
main()  
</CodeBlock>

## 3. Usage

Headless mode (default):

Visible Chrome window:

Increase the manual challenge timeout to five minutes:

Save the links to a file:

The script sends diagnostics to stderr, so stdout contains only the extracted URLs.

## 4. Important limitations

One clarification about the implementation above: **it does not yet decrypt Click'n'Load (CNL) payloads**. It extracts ordinary links, DLC links, Filecrypt weblinks, and popup destinations, but encrypted CNL payloads need an additional decryption implementation based on pyLoad's `clicknload_decrypt2` function.

Other limitations:

- CAPTCHA challenges require manual interaction with `--headful`.
- Some download hosts use intermediate redirects or JavaScript flows that may need host-specific handling.
- Filecrypt can change its HTML structure, so selectors such as `button.download` may need updating.
- I haven't run the script against a live Filecrypt container, so it should be treated as a starting point rather than a verified, complete decrypter.

For the closest match to pyLoad's behavior, the next improvement would be to port `clicknload_decrypt2` and its AES decryption logic, then merge those decrypted URLs with the browser-extracted results.

## Prompt:

10/31/2026, 7:11:49 PM

in headful mode, i cannot solve the proof-of-work captcha. this just works in my normal browser, but fails in the patchright browser. maybe i have to add an adblocker extension to my patchright browser instance? the filecrypt.cc website is full of nasty ads, and my normal browser has an adblocker (ublock origin). how can i add the "ublock origin" extension to my patchright chromium browser?

in my xx i have implemented the "ublock origin" extension like this:

`https://github.com/milahu/aiohttp_chromium/blob/main/src/aiohttp_chromium/extensions.py`


    class ChromiumExtension:

        name = None
        source = None
        session = None
        id = None
        cachedir = None
        pinned = False

        def __init__(self, session, pinned=None):

            self.session = session

            if pinned != None:
                self.pinned = pinned

            self._logger = logging.getLogger(self.__class__.__name__)
            self.log = self._logger.debug

            self.cachedir = f"{self.session._extensions_cache_path}/{self.name}"
            self.path = f"{self.session._extensions_path}/{self.name}"

            self.id = get_extension_id(self.path)

            self.settings_cache = f"{self.session._extensions_cache_path}/{self.name}/settings"
            self.settings_path = f"{self.session._chromium_user_data_dir}/Default/Local Extension Settings/{self.id}"

            self.log(f"init done: path: {self.path} id: {self.id}")

        def __await__(self):

            return self.async_init().__await__()

        async def async_init(self):

            if os.path.exists(self.path):
                return

            await self.download()

            await self.unpack()

            await self.fix_path()

            await self.load_state()

            await self.patch()

            self.session._chromium_options.add_argument(f"--load-extension={self.path}")

            if self.pinned:
                self.session._chromium_config["extensions"]["pinned_extensions"].append(self.id)

            self.log(f"async_init done")

            return self

        async def close(self):

            await self.save_state()

            self.log(f"close done")

        async def download(self):

            source_url = self.source["url"]
            source_sha256 = self.source["sha256"]
            source_filename = self.source.get("filename") or os.path.basename(source_url)
            self.cache_filepath = f"{self.cachedir}/{source_filename}"

            os.makedirs(self.cachedir, exist_ok=True)

            if os.path.exists(self.cache_filepath):
                sha256 = sha256sum(self.cache_filepath).hex()
                if sha256 != source_sha256:
                    # delete invalid cache file
                    print(f"deleting invalid cache file: {self.cache_filepath}. checksum mismatch: {sha256} != {source_sha256}")
                    os.unlink(self.cache_filepath)

            if not os.path.exists(self.cache_filepath):
                print(f"downloading {source_url}")
                async with aiohttp.ClientSession() as session:
                    async with session.get(source_url) as resp:
                        print(resp.status)
                        #print(await resp.text())
                        with open(self.cache_filepath, 'wb') as fd:
                            chunk_size = 65536
                            async for chunk in resp.content.iter_chunked(chunk_size):
                                fd.write(chunk)

            sha256 = sha256sum(self.cache_filepath).hex()
            if sha256 != source_sha256:
                raise Exception(f"invalid cache file: {self.cache_filepath}. checksum mismatch: {sha256} != {source_sha256}")

        async def unpack(self):

            if self.cache_filepath[-4:].lower() == ".zip":
                with zipfile.ZipFile(self.cache_filepath, "r") as z:
                    z.extractall(self.path)
                return

            # TODO extract tar.gz archives

            raise NotImplementedError(f"unpack file {self.cache_filepath}")

        async def fix_path(self):

            # find manifest.json
            # fix self.path
            if os.path.exists(f"{self.path}/manifest.json"):
                return
            path_files = os.listdir(self.path)
            if len(path_files) == 1:
                # no. changing path would change id
                #self.path += "/" + path_files[0]
                os.rename(self.path, self.path + ".tmp")
                os.rename(self.path + ".tmp/" + path_files[0], self.path)
                os.rmdir(self.path + ".tmp")
            if not os.path.exists(f"{self.path}/manifest.json"):
                raise Exception(f"no manifest.json in {self.path}")

        async def patch(self):

            pass

        async def load_state(self):

            if os.path.exists(self.settings_cache):
                self.log(f"load_state: loading settings from {self.settings_cache}")
                os.makedirs(os.path.dirname(self.settings_path), exist_ok=True)
                shutil.copytree(self.settings_cache, self.settings_path)

        async def save_state(self):

            if os.path.exists(self.settings_path):
                self.log(f"save_state: saving settings to {self.settings_cache}")
                os.makedirs(os.path.dirname(self.settings_cache), exist_ok=True)
                # FIXME use "rsync" to reduce disk writes
                # FIXME FileExistsError: [Errno 17] File exists: '/home/user/.cache/aiohttp_chromium/extensions/ublock/settings'
                try:
                    shutil.copytree(self.settings_path, self.settings_cache)
                except FileExistsError as e:
                    self.log(f"FIXME FileExistsError {e}")

        async def pre_start(self):

            pass

        async def post_start(self):

            pass

    def get_extension_id(path: str):
        # FIXME On Windows, the path needs to be encoded as utf-16-le
        # https://stackoverflow.com/questions/26053434
        t = str.maketrans(string.hexdigits[:16], string.ascii_lowercase[:16])
        return hashlib.sha256(path.encode('utf8')).hexdigest()[:32].translate(t)

    """
    class EditThisCookie(ChromiumExtension):
        pass
    """

    def sha256sum(file_path=None, data=None):
        if data:
            return hashlib.sha256(data).digest()
        assert file_path
        # https://stackoverflow.com/questions/22058048/hashing-a-file-in-python
        # BUF_SIZE is totally arbitrary, change for your app!
        BUF_SIZE = 65536  # lets read stuff in 64KB chunks
        hash = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while data := f.read(BUF_SIZE):
                hash.update(data)
        return hash.digest()
        #print("SHA1: {0}".format(hash.hexdigest()))

    class Ublock(ChromiumExtension):

        name = "ublock"
        website = "https://github.com/gorhill/uBlock"
        source = {
            "url": "https://github.com/gorhill/uBlock/releases/download/1.55.0/uBlock0_1.55.0.chromium.zip",
            "sha256": "00cec043e4e30e758a9d8194a018121ac689345fde4d4d02baaac60b954f2d7d",
        }
        pinned = True

        async def patch(self):

            self.log(f"patch: patching /js/background.js")

            # TODO refactor patching of files
            with open(self.path + "/js/background.js", "r") as f:
                text = f.read()

            # enable: Suspend network activity until all filter lists are loaded
            text = text.replace(
                "suspendUntilListsAreLoaded: vAPI.Net.canSuspend(),",
                "suspendUntilListsAreLoaded: true,",
            )

            # if state was loaded
            if os.path.exists(self.settings_path):
                # disable: Auto-update filter lists
                text = text.replace(
                    "autoUpdate: true,",
                    "autoUpdate: false,",
                )

            with open(self.path + "/js/background.js", "w") as f:
                f.write(text)

        async def post_start(self):
            # TODO dynamic. wait until ublock is ready
            # otherwise the first request fails at Network.getResponseBody
            # try to get the status from
            # url = f"chrome-extension://{self.id}/dashboard.html"
            self.log(f"waiting until ublock is ready")
            await asyncio.sleep(10)

## Response:

10/31/2026, 7:11:52 PM

> **Fixing extension loading**
>
> I’m correcting the launch flags and persistent-context handling. I’ll also account for Chromium’s changing Manifest V2 support: classic uBlock Origin may work in bundled Chromium, while uBlock Origin Lite is the fallback if loading fails.
>
> **Searched 4 websites**
>
> Worked for 5s

Yes, adding uBlock Origin is a reasonable thing to try. There are two separate issues worth distinguishing:

1.  **Ads and third-party scripts:** uBlock Origin can block advertising, tracking, and potentially disruptive third-party resources.
2.  **Filecrypt's proof-of-work CAPTCHA:** this may depend on JavaScript execution, browser storage, cookies, and other browser capabilities. Blocking the wrong script or resource can actually prevent the challenge from completing.

Patchright supports Chromium extensions, but you need to launch Chromium with a persistent browser context rather than using `p.chromium.launch()` followed by `browser.new_context()`.

The important change is to use `launch_persistent_context()`.

## 1. Download and unpack uBlock Origin

I recommend keeping the extension in a local directory rather than downloading it every time the scraper runs.

One important compatibility detail: Google's extension support has changed. Chrome removed Manifest V2 extensions from the Chrome Web Store, while uBlock Origin's full Chromium version has historically used MV2. The latest uBlock releases provide signed Chromium packages, but you should check the manifest version before choosing a package. \<Cite refs={\["turn598610search1","turn598610search2"\]}/\>

For the original extension implementation you supplied, you can use its 1.55.0 ZIP as a starting point:

You should end up with:

Note that this is an old release, not a recommendation to use it permanently. Prefer a current, signed release compatible with your Chromium build.

## 2. Modify the Patchright browser initialization

Replace:

With:

And replace:

With:

**Why persistent context?**

Chromium extensions require a persistent context in Playwright-compatible automation. A normal isolated browser context does not support loading extensions this way. \<Cite refs={\["turn598610search3"\]}/\>

## 3. Make the extension optional with a CLI flag

I'd actually add a `--ublock` flag so you can compare behavior with and without the extension.

Add this argument:

Then construct the arguments conditionally:

Usage:

## 4. Troubleshooting the proof-of-work CAPTCHA

I'd test these combinations:

| Browser       | uBlock   | Purpose                     |
|---------------|----------|-----------------------------|
| Patchright    | Disabled | Baseline                    |
| Patchright    | Enabled  | Check whether ads interfere |
| Normal Chrome | Enabled  | Compare behavior            |

If uBlock makes the CAPTCHA worse:

1.  Open uBlock's dashboard.
2.  Temporarily disable cosmetic filtering for Filecrypt.
3.  Check the uBlock logger for blocked scripts and requests.
4.  Consider allowlisting Filecrypt temporarily to determine whether a filter is responsible.

One additional caveat: if your extension's `manifest.json` declares Manifest V2, it may not load in newer Chrome builds. Google's extension changes make this particularly relevant in 2026. See the <Link url="https://github.com/gorhill/uBlock/releases" title="official uBlock Origin releases"/>.

**My recommendation:** First get the persistent Patchright context working without extensions. Then add uBlock and compare the CAPTCHA behavior. This will help distinguish an extension/filter problem from a browser compatibility problem.

## Prompt:

10/31/2026, 7:35:05 PM

no, patchright just ignores the `load-extension` argument. how can i debug this? i tried to add `verbose=True` or `debug=True` to the kwargs of the call to p.chromium.launch_persistent_context, but that does not work...

## Response:

10/31/2026, 7:35:08 PM

> **Searched 8 websites**
>
> Worked for 6s

The first thing I'd investigate is whether Chromium is actually receiving the extension arguments, and whether it accepts the extension at startup.

There are three different things that can go wrong:

1.  Patchright doesn't pass `--load-extension` to Chromium.
2.  Chromium receives the argument but rejects the extension (manifest version, invalid path, etc.).
3.  The extension loads, but its background service worker fails to start.

`verbose=True` and `debug=True` aren't supported arguments to `launch_persistent_context()`. Playwright/Patchright uses environment variables and Python logging for diagnostics instead.

## 1. Enable Patchright and Playwright debugging

Run your script like this:

For more detailed logging:

On Windows PowerShell:

Look for:

- `--load-extension`
- `--disable-extensions-except`
- Chromium startup errors
- Extension loading errors
- Browser launch arguments

## 2. Enable Chromium's own logging

Patchright's `DEBUG=pw:*` logging shows what the automation library does, but it doesn't necessarily show why Chromium rejected an extension.

Add Chromium's native logging flags:

Capture stderr:

Then search the log:

This should help distinguish a rejected extension from an extension that loaded but failed during initialization.

## 3. Check the actual Chromium command line

This is probably the most useful test.

Immediately after launching the persistent context, open:

Look for these two arguments:

If they aren't present, the issue is in browser startup.

If they are present, the issue is likely on the Chromium side.

Also verify the extension directory:

Make sure the path points directly to the directory containing `manifest.json`, not the ZIP file or its parent directory.

## 4. Check whether the extension actually loaded

You can inspect extension background pages and service workers directly through Patchright.

Add this after launching:

For uBlock Origin 1.55.0, which uses Manifest V2, I'd particularly look for a background page URL resembling:

You can also visit:

Enable Developer mode in the UI and inspect uBlock Origin. Chromium should show loading errors if the extension was rejected.

## 5. Important: Are you launching Google Chrome or bundled Chromium?

I suspect this might be the actual problem.

The current Playwright documentation explicitly warns:

> Google Chrome and Microsoft Edge removed the command-line flags needed to side-load extensions.

It recommends using Playwright's bundled Chromium instead. \<Cite refs={\["turn715674search0","turn715674search4"\]}/\>

In particular, if you have:

try removing it.

Use:

And make sure you have installed Patchright's Chromium:

Patchright's own documentation describes its Chromium installation and browser-launch behavior: <Link ref="turn715674search15" title="Patchright README"/>.

## 6. Minimal standalone extension-loading test

Before debugging your Filecrypt scraper, I'd isolate the problem with this small script.

<CodeBlock language="python" editable>
from pathlib import Path
from patchright.sync_api import sync_playwright

EXTENSION = Path("extensions/ublock").resolve()  
PROFILE = Path(".test-chromium-profile").resolve()

assert (EXTENSION / "manifest.json").is_file(), (  
f"Missing manifest.json: {EXTENSION}"  
)

print("Extension:", EXTENSION)  
print("Manifest:")  
print((EXTENSION / "manifest.json").read_text()\[:2000\])

with sync_playwright() as p:  
context = p.chromium.launch_persistent_context(  
str(PROFILE),  
headless=False,  
args=\[  
f"--disable-extensions-except={EXTENSION}",  
f"--load-extension={EXTENSION}",  
"--enable-logging=stderr",  
"--log-level=0",  
"--v=1",  
\],  
)

    page = context.new_page()
    page.goto("chrome://version")

    print("\n=== Chromium command line ===")
    print(page.locator("#command_line").inner_text())

    print("\n=== Background pages ===")
    for bg in context.background_pages:
        print(bg.url)

    print("\n=== Service workers ===")
    for worker in context.service_workers:
        print(worker.url)

    page.goto("chrome://extensions")
    print("\nInspect the extension loading status in the browser.")

    input("\nPress Enter to close Chromium...")
    context.close()

</CodeBlock>

Run:

------------------------------------------------------------------------

**One question that would help narrow this down:** Are you launching Patchright's bundled Chromium, or Google Chrome using `channel="chrome"`?

That distinction is particularly important here because the extension-loading command-line flags are no longer supported by current Google Chrome builds.

## Prompt:

10/31/2026, 7:37:49 PM

ah, patchright is launching chromium with `--disable-extensions`. how can i disable that?

## Response:

10/31/2026, 7:37:51 PM

> **Searched 10 websites**
>
> Worked for a couple of seconds

Interesting: **Patchright is specifically designed to remove `--disable-extensions` from Chromium's default arguments.** Its documentation explicitly lists this as one of its patches. \<Cite refs={\["turn841930search0","turn841930search3"\]}/\>

So if you're seeing that flag, I'd first check your installed Patchright version.

### 1. Check your version

Upgrade if necessary:

### 2. Explicitly remove the flag using `ignore_default_args`

Patchright inherits Playwright's `ignore_default_args` option.

Try:

This is the most direct solution if the flag is being added as a default argument.

### 3. If that doesn't work, inspect the actual arguments

Try:

**Warning:** `ignore_default_args=True` disables *all* Playwright/Patchright default arguments, not just `--disable-extensions`. This can break browser initialization or other automation behavior. Use it only as a diagnostic experiment.

### 4. My preferred solution

I'd start with:

It preserves the rest of Patchright's carefully selected browser arguments.

If the flag still appears, please share:

And the complete Chromium command line from:

That will help identify whether the flag is injected by Patchright, a custom launcher, or the Chromium executable itself.

## Prompt:

10/31/2026, 7:44:37 PM

no...

now `--disable-extensions` is no longer passed to chromium, but chromium still silently ignores my ublock extension

this is how i launch chromium:

        with sync_playwright() as p:
            context_args = [
                # f"--disable-extensions-except={EXTENSION_PATH}",
                f"--load-extension={EXTENSION_PATH}", # TODO comma-separated list of extension dirs
            ]
            print("context_args:", context_args)
            context = p.chromium.launch_persistent_context(
                user_data_dir=str(USER_DATA_DIR),
                headless=not args.headful,
                args=context_args,
                ignore_default_args=[
                    "--disable-extensions",
                    "--disable-component-extensions-with-background-pages",
                ],
            )
            page = context.pages[0] if context.pages else context.new_page()

            page.set_default_timeout(10000)

            page.goto("chrome://version")
            print("chrome version command_line:", page.locator("#command_line").inner_text())

## Response:

10/31/2026, 7:44:41 PM

> **Searched 7 websites**
>
> Worked for a few seconds

Right - removing `--disable-extensions` only fixes the first problem. Your launch code is now asking Chromium to load the extension, but that does **not** prove Chromium accepted it.

The first thing I’d check is whether the extension is actually loaded into that persistent context. `--load-extension` is a Chromium startup flag; it needs to point to the **unpacked extension directory**, not the ZIP file and not a parent directory containing the unpacked extension.

There are two important things in your snippet:

1.  You're missing `--disable-extensions-except`. I'd include it alongside `--load-extension`. It restricts loading to the extension directory you specify.
2.  You haven't checked `context.service_workers` or `context.background_pages`. Those tell us whether Chromium actually loaded the extension's background component.

Try this diagnostic version:

**How to interpret the result:**

- No service worker and no background page: the extension probably didn't load, or its manifest/background configuration isn't supported.
- A `chrome-extension://...` service worker: an MV3 extension loaded.
- A `chrome-extension://...` background page: an MV2 extension loaded.
- An extension listed on `chrome://extensions` with an error: inspect its error details.

One important detail: you previously mentioned uBlock Origin **1.55.0, Manifest V2**. Check its `manifest.json` and whether your Chromium build still supports that manifest version. MV2 and MV3 use different background mechanisms. \<Cite refs={\["turn476876search0","turn476876search1","turn476876search2"\]}/\>

**Could you share these three things?**

1.  The output of `context.service_workers` and `context.background_pages`.
2.  The `manifest.json` from your unpacked uBlock directory (especially `manifest_version` and `background`).
3.  The Chromium version shown in `chrome://version`.

That will tell us whether this is an extension-loading problem or an incompatibility with that uBlock build.

## Prompt:

10/31/2026, 7:48:12 PM

both ublock versions (1.55.0 and 1.75.1rc4) fail to load:

    Extension path: /home/user/src/milahu/pyload/filecrypt_scraper_patchright/extensions/ublock/uBlock0_1.55.0.chromium
    Manifest exists: True
    Service workers: []
    Background pages: []

and

    Extension path: /home/user/src/milahu/pyload/filecrypt_scraper_patchright/extensions/ublock/uBlock0_1.75.1rc4.chromium
    Manifest exists: True
    Service workers: []
    Background pages: []

## Response:

10/31/2026, 7:48:14 PM

> **Searched 10 websites**
>
> Worked for a couple of seconds

That narrows it down: **neither extension is registering a background context at all**. This points to Chromium not loading the extension, rather than uBlock loading but failing to filter requests.

There are two things I'd investigate next.

### 1. Check whether Chromium accepted the extension

Navigate to `chrome://extensions` and inspect the page. In particular, look for:

- Whether uBlock appears in the installed extensions list.
- Whether there's an error shown for it.
- Whether Developer mode is enabled.

You can dump the page with:

Also try opening:

If uBlock isn't listed at all, Chromium rejected or ignored the load request. If it is listed with an error, that error is the useful clue.

### 2. Check the actual manifest and browser version

Run this against both extension directories:

For MV2, Chromium uses background pages/scripts; for MV3, it uses extension service workers. So empty `service_workers` and `background_pages` alone don't prove an extension wasn't loaded - but combined with an absent entry on `chrome://extensions`, they strongly suggest it wasn't. \<Cite refs={\["turn569603search1","turn569603search2","turn569603search0"\]}/\>

### 3. One potentially important Chrome restriction

If you're launching Google Chrome rather than Playwright's bundled Chromium, Chrome can ignore `--load-extension` under certain security configurations, including Enhanced Safe Browsing. The Playwright documentation recommends its bundled Chromium for extension testing. \<Cite refs={\["turn569603search1","turn569603search13"\]}/\>

For a clean test, try the bundled Chromium with a fresh profile directory and no `channel="chrome"`.

------------------------------------------------------------------------

**The most useful next output is the contents of `chrome://extensions` and the two manifests' `manifest_version` and `background` fields.** That should distinguish a rejected command-line load from a manifest compatibility issue.

## Prompt:

10/31/2026, 7:50:01 PM

# Selected text:

## Selection 1

Run this against both extension directories:

## My request:

    $ ./ublock_versions.py 

     extensions/ublock/uBlock0_1.55.0.chromium
    manifest_version: 2
    name: uBlock Origin
    version: 1.55.0
    background: {'page': 'background.html'}

     extensions/ublock/uBlock0_1.75.1rc4.chromium
    manifest_version: 2
    name: uBlock Origin development build
    version: 1.75.1.104
    background: {'page': 'background.html'}

> If you're launching Google Chrome rather than Playwright's bundled Chromium

no, i am using Playwright's bundled Chromium

the page `chrome://extensions` is alwas empty

## Response:

10/31/2026, 7:50:03 PM

> **Searched 10 websites**
>
> Worked for a couple of seconds

Thanks. That rules out a missing `manifest.json` and makes an MV2/MV3 mismatch unlikely: **both uBlock builds are Manifest V2, and neither is appearing in Chromium's extension manager.**

I spotted one thing missing from your original launch code: you're using `--load-extension`, but had commented out `--disable-extensions-except`.

More importantly, there's a relevant detail in Playwright's current extension documentation: for headless extension support, it recommends `channel="chromium"`. Without that, `headless=True` may launch the separate headless-shell binary, which doesn't support extensions. \<Cite refs={\["turn138982search1","turn138982search0"\]}/\>

Try this exact minimal test, with a **new temporary profile** and no other browser arguments:

If this works, add your original settings back one at a time.

If it still doesn't work, I want to check one more thing: **what exact Chromium binary is Patchright launching?**

Add this to your original code:

And please share:

One other possible cause worth checking: Chromium has historically ignored `--load-extension` when Enhanced Safe Browsing is enabled, even in cases where the browser otherwise accepts the flag. \<Cite refs={\["turn138982search13"\]}/\>

I wouldn't spend more time changing uBlock versions yet. We need to establish why Chromium isn't loading *any* unpacked extension first.

## Prompt:

10/31/2026, 7:53:46 PM

    Browser version: 149.0.7827.55
    Executable: /nix/store/wv98g96qwd1vcr5h9dbgpbfh2gvcy1qr-playwright-browsers/chromium-1228/chrome-linux64/chrome

and

    $ python -c 'import patchright; print(patchright.__file__)'
    /nix/store/pz4d51856hp7xdysz97syrkkrcd2nq29-python3-3.14.7-env/lib/python3.14/site-packages/patchright/__init__.py

    $ readlink /nix/store/pz4d51856hp7xdysz97syrkkrcd2nq29-python3-3.14.7-env/lib/python3.14/site-packages/patchright
    /nix/store/jvnaqh8ykyfnggdrh08z02196pbq6mc7-python3.14-patchright-1.61.0/lib/python3.14/site-packages/patchright

## Response:

10/31/2026, 7:53:48 PM

> **Searched 11 websites**
>
> Worked for 4s

This is useful. You're running:

- **Patchright 1.61.0**, packaged by Nix.
- **Bundled Chromium 149.0.7827.55**, from Playwright's `chromium-1228` directory.
- Both uBlock packages have valid-looking MV2 manifests.

I don't see evidence yet that this is a uBlock compatibility problem. The fact that **both extensions are absent from `chrome://extensions`** suggests the browser isn't accepting the extension-loading request.

One important lead: Chromium's command-line extension-loading behavior has changed in recent releases. There are reports of `--load-extension` being ignored in newer Chromium builds, even when the argument is present. \<Cite refs={\["turn618606search3","turn618606search8"\]}/\>

### Can you run one more diagnostic?

Please print the *actual* command line from `chrome://version`, and check whether both extension flags are present:

Also, what is the value of `args.headful` when you reproduce this?

### A useful isolation test

Try the same launch with a tiny, known-good MV2 extension rather than uBlock. For example, create a temporary directory containing:

`manifest.json`:

Then launch with that directory as the extension path.

If it also fails to appear in `chrome://extensions`, we've isolated the issue to Chromium/Patchright rather than uBlock.

### One version-related note

Patchright 1.61.0 is behind the currently published 1.64.2 release. Its documentation explicitly says Patchright removes `--disable-extensions` to permit extension loading, but that alone doesn't guarantee compatibility with every Chromium revision. \<Cite refs={\["turn618606search0","turn618606search1"\]}/\>

I wouldn't change your Nix setup or upgrade blindly yet. The actual command line and the tiny-extension test will tell us whether Chromium is ignoring the switch or whether something else is wrong.

## Prompt:

10/31/2026, 7:59:09 PM

    Command line: /nix/store/wv98g96qwd1vcr5h9dbgpbfh2gvcy1qr-playwright-browsers/chromium-1228/chrome-linux64/chrome --disable-field-trial-config --disable-background-networking --disable-background-timer-throttling --disable-backgrounding-occluded-windows --disable-back-forward-cache --disable-breakpad --disable-client-side-phishing-detection --disable-component-update --no-default-browser-check --disable-default-apps --disable-dev-shm-usage --disable-edgeupdater --disable-features=AvoidUnnecessaryBeforeUnloadCheckSync,BoundaryEventDispatchTracksNodeRemoval,DestroyProfileOnBrowserClose,DialMediaRouteProvider,GlobalMediaControls,HttpsUpgrades,LensOverlay,MediaRouter,PaintHolding,ThirdPartyStoragePartitioning,Translate,AutoDeElevate,RenderDocument,OptimizationHints,msForceBrowserSignIn,msEdgeUpdateLaunchServicesPreferredVersion --enable-features=CDPScreenshotNewSurface --allow-pre-commit-input --disable-hang-monitor --disable-ipc-flooding-protection --disable-popup-blocking --disable-prompt-on-repost --disable-renderer-backgrounding --force-color-profile=srgb --metrics-recording-only --no-first-run --password-store=basic --use-mock-keychain --no-service-autorun --export-tagged-pdf --disable-search-engine-choice-screen --unsafely-disable-devtools-self-xss-warnings --edge-skip-compat-layer-relaunch --disable-infobars --disable-search-engine-choice-screen --disable-sync --enable-unsafe-swiftshader --no-sandbox --disable-extensions-except=/home/user/src/milahu/pyload/filecrypt_scraper_patchright/extensions/ublock/uBlock0_1.75.1rc4.chromium --load-extension=/home/user/src/milahu/pyload/filecrypt_scraper_patchright/extensions/ublock/uBlock0_1.75.1rc4.chromium --user-data-dir=/home/user/src/milahu/pyload/filecrypt_scraper_patchright/.filecrypt-chrome-profile --remote-debugging-pipe --ozone-platform=wayland --flag-switches-begin --flag-switches-end --render-node-override=/dev/dri/renderD128 --enable-unsafe-swiftshader about:blank
    --load-extension= True
    --disable-extensions-except= True

your minimal extension is ignored. if i load it manually, i get the error "Cannot install extension because it uses an unsupported manifest version."

i get the same error for both ublock versions, so apparently this version of chromium no longer supports MV2 extensions : (

## Response:

10/31/2026, 7:59:11 PM

Ah, that explains it! We've found the actual cause. 🙂

Your command line contains both extension flags, and Chromium is rejecting the extensions because **Chromium 149 no longer supports Manifest V2 extensions**.

So:

- Patchright is passing the flags correctly.
- The extension directory and manifest are being found.
- Both uBlock versions are MV2 (`"manifest_version": 2`).
- Even a minimal MV2 extension is rejected with the same error.

This is not a Patchright configuration problem.

### What you can do

1.  **Use an older Chromium build that still supports MV2**, if you can obtain one with MV2 support enabled. This may require a version-specific policy or flag, depending on the Chromium release.
2.  **Find an MV3-compatible content blocker.** uBlock Origin Lite is the official MV3-based alternative, though it has fewer capabilities than full uBlock Origin.
3.  **Use a separate browser/profile for the CAPTCHA step**, if you need full uBlock Origin's filtering capabilities there.

For your scraper, I'd try **uBlock Origin Lite** first, since it avoids downgrading Chromium and should work with the current extension-loading setup.

And importantly, you can stop debugging Patchright's `--load-extension` flags: they're working.

## Prompt:

10/31/2026, 8:00:33 PM

nah, i want to use the full "uBlock Origin" extension, so let me just switch from chromium to firefox (or librewolf), where "uBlock Origin" is still supported. how do i have to change my python script to switch to firefox?

## Response:

10/31/2026, 8:00:35 PM

> **Searched 9 websites**
>
> Worked for a couple of seconds

Yes. The good news is that **Playwright supports Firefox directly**, and its Python API is almost identical to Chromium's.

One important catch: **Patchright does not support Firefox**. You'll need to switch the import from `patchright` to the standard `playwright` package. \<Cite refs={\["turn360749search0","turn360749search1"\]}/\>

## 1. Install Playwright Firefox

On NixOS, you may need to provide Firefox's runtime libraries through your Nix environment.

## 2. Change your browser launch code

For Firefox, use a persistent context and install uBlock Origin through Firefox's normal extension mechanism.

The simplest approach is to use a Firefox profile where uBlock Origin is already installed.

## 3. Install uBlock Origin

For Firefox, the easiest option is to install the official extension manually into that profile:

<row align="center" gap={3}>
  <AsyncImage query="uBlock Origin Firefox extension logo" aspectRatio="1:1" maxWidth="56px"/>
  <box flex="1" gap={1}>
    **<Entity value="uBlock Origin" category="software"/>**

    <Link url="https://addons.mozilla.org/firefox/addon/ublock-origin/" title="Install from Firefox Add-ons"/>

  </box>
</row>

1.  Start Firefox with the profile you intend to use.
2.  Install uBlock Origin from the official add-ons page.
3.  Close Firefox.
4.  Launch your Playwright persistent context using that same profile directory.

**Important:** Don't run two Firefox processes against the same profile simultaneously.

## 4. What changes in the rest of your scraper?

Almost nothing:

| Chromium / Patchright         | Firefox / Playwright  |
|-------------------------------|-----------------------|
| `p.chromium`                  | `p.firefox`           |
| `patchright.sync_api`         | `playwright.sync_api` |
| `--load-extension`            | Not needed            |
| `--disable-extensions-except` | Not needed            |
| Chromium profile              | Firefox profile       |

Your existing `page.goto()`, locators, clicks, waits, and popup handling can mostly remain unchanged.

One caveat: Firefox has different popup and browser behavior in a few cases, so test your Filecrypt link-resolution logic separately.

**My recommendation:** Start with Firefox rather than LibreWolf. Once the scraper works, you can try LibreWolf by specifying its executable path with `executable_path=...` in `launch_persistent_context()`.

## Prompt:

10/31/2026, 8:02:14 PM

# Selected text:

## Selection 1

Patchright does not support Firefox

## My request:

hmm. are there similar projects for firefox? (forks of playwright to make it bypass anti-bot protections like cloudflare)

## Response:

10/31/2026, 8:02:16 PM

> **Searched 9 websites**
>
> Worked for a couple of seconds

Yes. There are a few Firefox-based projects that aim to make Playwright automation less detectable. The closest matches to Patchright are **invisible_playwright** and **Camoufox**.

## Projects worth looking at

<box gap={4}>
  <row align=start gap={3}>
    <AsyncImage query="invisible_playwright feder-cr GitHub Firefox project logo" aspectRatio="1:1" maxWidth="88px" />
    <box flex="1" gap={1}>
      **1. <Entity value="invisible_playwright" category="software" disambig="Firefox-based stealth browser for Playwright"/>**

      <badge color="success">Closest to your request</badge>

      <text color="secondary" size="sm">Python · Playwright-compatible · Firefox</text>

      A Firefox-based project with browser-engine-level fingerprint modifications, aiming to reduce automation detection. Its README describes it as a drop-in alternative for existing Playwright scripts. <Cite refs={["turn789326search10","turn789326search12"]}/>

      <text><Link url="https://github.com/feder-cr/invisible_playwright" title="GitHub repository"/></text>
    </box>

  </row>
  <divider color="subtle" />
  <row align=start gap={3}>
    <AsyncImage query="Camoufox anti detect Firefox browser fox logo" aspectRatio="1:1" maxWidth="88px" />
    <box flex="1" gap={1}>
      **2. <Entity value="Camoufox" category="software" disambig="Open-source anti-detection Firefox browser"/>**

      <text color="secondary" size="sm">Python · Playwright-compatible · Firefox fork</text>

      Modifies Firefox at the browser-engine level rather than relying only on JavaScript stealth patches. It also offers fingerprint configuration and browser automation support. Its documentation notes that detection resistance isn't guaranteed and can regress as detection systems change. <Cite refs={["turn789326search7","turn789326search2"]}/>

      <text><Link url="https://github.com/daijro/camoufox" title="GitHub repository"/> · <Link url="https://camoufox.com/" title="Documentation"/></text>
    </box>

  </row>
  <divider color="subtle" />
  <row align=start gap={3}>
    <AsyncImage query="Camofox browser jo-inc GitHub logo Firefox" aspectRatio="1:1" maxWidth="88px" />
    <box flex="1" gap={1}>
      **3. <Entity value="camofox-browser" category="software" disambig="Browser automation server built on Camoufox"/>**

      <text color="secondary" size="sm">Node.js service · Camoufox backend · HTTP API</text>

      Wraps Camoufox in a browser automation server. It's more of a service/API than a Python Playwright fork, so integrating it into your current scraper would take more changes. <Cite refs={["turn789326search1"]}/>

      <text><Link url="https://github.com/jo-inc/camofox-browser" title="GitHub repository"/></text>
    </box>

  </row>
</box>

## What I'd try for your Filecrypt scraper

I'd evaluate **invisible_playwright first**, then Camoufox. Both are closer to your existing Python workflow than introducing a separate Node.js browser service.

Your existing calls such as `page.goto()`, `page.locator()`, `locator.click()`, and popup handling should be familiar, but check each project's compatibility notes before assuming every Playwright feature behaves identically.

Since you want full uBlock Origin too, verify extension support separately: a Firefox engine doesn't automatically mean that a project supports loading arbitrary Firefox extensions into its managed profile. You may need to use a regular Firefox/LibreWolf profile with uBlock installed, depending on the project's launch model.

One caveat: these projects aim to reduce automation detection, but none can guarantee that Cloudflare or another anti-bot service will allow a session through. For a legitimate scraping workflow, keep a manual challenge path available.

------------------------------------------------------------------------

Powered by [ChatGPT Exporter](https://www.chatgptexporter.com)
