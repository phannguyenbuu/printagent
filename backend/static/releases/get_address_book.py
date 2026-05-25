#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Ricoh Copier Address Book Extractor
-----------------------------------
Standalone script to run directly on the technician PC (kythuat02) to log into
the Ricoh copier at 192.168.1.226 with user 'admin' (empty password) and fetch the full Address Book.

Requirements:
    pip install requests
"""

import sys
import time
import json
import logging
import re
from html import unescape
from dataclasses import dataclass, asdict
from urllib.parse import urljoin
import requests

# Configure logging to display detailed extraction progress to console
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
LOGGER = logging.getLogger("RicohExtractor")

@dataclass
class AddressEntry:
    type: str
    registration_no: str
    name: str
    user_code: str
    date_last_used: str
    email_address: str
    folder: str
    entry_id: str = ""

class RicohStandaloneExtractor:
    def __init__(self, ip: str, username: str = "admin", password: str = "") -> None:
        self.ip = ip
        self.username = username
        self.password = password
        self.base_url = f"http://{ip}"
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "printer-agent/0.1"})

    def reset_and_logout(self) -> None:
        """
        Clears the current browser cookies and triggers logouts to free copier sessions.
        Highly critical for Ricoh copiers to prevent session lockout/overload.
        """
        LOGGER.info("Step 1: Clearing cookies and resetting pre-existing web sessions on copier...")
        self.session.cookies.clear()
        
        urls = [
            "/web/entry/en/websys/webArch/logout.cgi",
            "/web/guest/en/websys/webArch/logout.cgi",
            "/web/entry/en/websys/webArch/mainFrame.cgi",
            "/web/guest/en/websys/webArch/mainFrame.cgi",
        ]
        
        for path in urls:
            url = urljoin(self.base_url, path)
            try:
                LOGGER.info(f"Sending cleanup probe: GET {path}")
                # Increased timeout to 10 seconds to accommodate slower printer wakeups
                resp = self.session.get(url, timeout=10)
                LOGGER.info(f"Probe {path} returned status code: {resp.status_code}")
            except Exception as e:
                LOGGER.debug(f"Skipped reset probe {path} error: {e}")

        self.session.cookies.clear()
        LOGGER.info("Initial session reset completed.")

    def _extract_wim_token(self, html: str) -> str:
        match = re.search(r'wimToken\s*=\s*"([^"]+)"', html)
        if match:
            return match.group(1)
        match = re.search(r'name="wimToken"\s*value="([^"]+)"', html)
        return match.group(1) if match else ""

    def _extract_hidden_inputs(self, html: str) -> dict[str, str]:
        """Simple regex extraction of hidden input fields."""
        fields: dict[str, str] = {}
        for match in re.finditer(
            r'<input\s+[^>]*?type=["\']hidden["\'][^>]*?>', html, re.IGNORECASE | re.DOTALL
        ):
            tag = match.group(0)
            name_m = re.search(r'name=["\']([^"\']+)["\']', tag, re.IGNORECASE)
            value_m = re.search(r'value=["\']([^"\']*)["\']', tag, re.IGNORECASE)
            if name_m:
                fields[name_m.group(1)] = unescape(value_m.group(1)) if value_m else ""
        # Also check for wimToken variable in script
        if "wimToken" not in fields:
            token = self._extract_wim_token(html)
            if token:
                fields["wimToken"] = token
        return fields

    def login(self) -> bool:
        """
        Authenticates against the secure Ricoh administrative endpoints.
        Loads the login form first to extract wimToken and other hidden fields for a highly robust login.
        Only performs the authenticating POST requests to the administrative entry endpoints.
        """
        LOGGER.info(f"Step 2: Logging in as '{self.username}' (empty password) to {self.ip}...")
        
        # 1. Fetch the login form first to extract wimToken and hidden inputs.
        # Try administrative /web/entry/ first, and fallback to /web/guest/.
        get_urls = [
            "/web/entry/en/websys/webArch/authForm.cgi",
            "/web/guest/en/websys/webArch/authForm.cgi",
        ]
        
        wim_token = ""
        fetched_url = ""
        hidden_inputs = {}
        
        for get_path in get_urls:
            url = urljoin(self.base_url, get_path)
            # Try up to 2 times to handle cookieOnOffChecker setting/refresh logic
            for pass_num in (1, 2):
                try:
                    LOGGER.info(f"Fetching login form to extract wimToken: GET {get_path} (pass {pass_num})...")
                    get_resp = self.session.get(url, timeout=15)
                    if get_resp.status_code == 200:
                        fetched_url = get_resp.url
                        
                        # Extract all hidden inputs first
                        hidden_inputs = self._extract_hidden_inputs(get_resp.text)
                        wim_token = hidden_inputs.get("wimToken", "")
                        
                        # Fallback direct regex check if not found in hidden inputs
                        if not wim_token:
                            match = re.search(r'wimToken\s*=\s*["\']([^"\']+)["\']', get_resp.text)
                            if match:
                                wim_token = match.group(1)
                            else:
                                match2 = re.search(r'wimToken["\']\s*[^>]*value=["\']([^"\']+)["\']', get_resp.text, re.IGNORECASE)
                                if not match2:
                                    match2 = re.search(r'value=["\']([^"\']+)["\']\s*[^>]*wimToken', get_resp.text, re.IGNORECASE)
                                if match2:
                                    wim_token = match2.group(1)
                        
                        if wim_token:
                            LOGGER.info(f"wimToken DETECTED: {wim_token}")
                            break  # Successfully found wimToken, break the pass loop
                        else:
                            LOGGER.info(f"wimToken NOT DETECTED (pass {pass_num}, cookies: {self.session.cookies.get_dict()})")
                except Exception as e:
                    LOGGER.debug(f"Failed to fetch GET page {get_path} (pass {pass_num}): {e}")
            if wim_token:
                break
        
        if not fetched_url:
            LOGGER.warning("Could not load any login form via GET. Proceeding with default POST attempts without wimToken.")
        
        # 2. Perform authenticating POST requests
        # Method A: Standard credentials to entry endpoints
        post_paths = [
            "/web/entry/en/websys/webArch/login.cgi",
            "/web/entry/en/websys/webArch/authForm.cgi",
        ]
        
        for path in post_paths:
            url = urljoin(self.base_url, path)
            LOGGER.info(f"Sending standard credentials (Method A): POST {path}...")
            
            # Build data payload starting with extracted hidden fields
            data = {}
            if hidden_inputs:
                data.update(hidden_inputs)
                
            data.update({
                "username": self.username,
                "password": self.password,
            })
            if wim_token:
                data["wimToken"] = wim_token
            
            # Build headers. Always include Referer if we successfully fetched the GET form page.
            headers = {}
            if fetched_url:
                headers["Referer"] = fetched_url
                
            try:
                resp = self.session.post(
                    url,
                    data=data,
                    headers=headers,
                    timeout=15
                )
                
                LOGGER.info(f"Cookies after standard login attempt: {self.session.cookies.get_dict()}")
                
                is_login_page = any(indicator in resp.text for indicator in ["Login User Name", "Login Password"])
                is_still_login_form = 'name="username"' in resp.text or 'name=\'username\'' in resp.text
                wim_session = self.session.cookies.get("wimsesid", "")
                real_session = bool(wim_session) and wim_session != "--"
                
                if resp.status_code == 200 and not is_login_page and not is_still_login_form and real_session:
                    LOGGER.info(f"Successfully logged in via standard credentials: {path}!")
                    return True
                else:
                    LOGGER.warning(f"Endpoint {path} rejected login (Status: {resp.status_code}, Login indicators found: {is_login_page or is_still_login_form}, Real Session: {real_session})")
            except Exception as e:
                LOGGER.error(f"Failed to connect to standard login endpoint {path}: {e}")
                
        # Method B: Base64-encoded credentials (required for some models like MP 6503 with empty password)
        LOGGER.info("Method A standard login was rejected or not fully authenticated. Trying Base64 fallback (Method B)...")
        try:
            import base64
            # GET the guest authForm page to extract wimToken and form action
            auth_form_url = urljoin(self.base_url, "/web/guest/en/websys/webArch/authForm.cgi?open=websys/webArch/authForm.cgi")
            auth_resp = self.session.get(auth_form_url, timeout=15)
            if auth_resp.status_code == 200:
                token = self._extract_wim_token(auth_resp.text)
                action_match = re.search(r'<form[^>]+action=["\']([^"\']+)["\']', auth_resp.text, re.IGNORECASE)
                action = action_match.group(1) if action_match else "login.cgi"
                
                # Base64-encode credentials
                encoded_user = base64.b64encode(self.username.encode()).decode()
                encoded_pass = base64.b64encode(self.password.encode()).decode()
                
                login_post_url = urljoin(auth_resp.url, action)
                payload = {
                    "userid": encoded_user,
                    "password": encoded_pass,
                    "wimToken": token,
                    "open": "websys/webArch/authForm.cgi"
                }
                
                LOGGER.info(f"Sending base64 credentials (Method B) to {login_post_url}...")
                resp = self.session.post(login_post_url, data=payload, headers={"Referer": auth_resp.url}, timeout=15)
                LOGGER.info(f"Cookies after base64 login attempt: {self.session.cookies.get_dict()}")
                
                is_login_page = any(indicator in resp.text for indicator in ["Login User Name", "Login Password"])
                wim_session = self.session.cookies.get("wimsesid", "")
                real_session = bool(wim_session) and wim_session != "--"
                
                if resp.status_code == 200 and not is_login_page and real_session:
                    LOGGER.info("Successfully logged in via Base64 Method B!")
                    return True
                else:
                    LOGGER.warning(f"Base64 fallback rejected (Status: {resp.status_code}, Login indicators: {is_login_page}, Real Session: {real_session})")
        except Exception as e:
            LOGGER.error(f"Failed in Base64 fallback (Method B): {e}")

        return False

    def authenticate_and_get(self, path: str) -> str:
        url = urljoin(self.base_url, path)
        LOGGER.info(f"Requesting data from URL: GET {path}...")
        resp = self.session.get(url, timeout=15)
        resp.raise_for_status()
        html = resp.text

        is_login_page = any(indicator in html for indicator in ["authForm.cgi", "login.cgi", "Login User Name"])
        if is_login_page:
            LOGGER.info("Your session has expired or was disconnected. Re-authenticating...")
            if self.login():
                LOGGER.info(f"Re-connection successful. Reloading: GET {path}...")
                resp = self.session.get(url, timeout=15)
                resp.raise_for_status()
                html = resp.text
            else:
                raise RuntimeError("Failed to re-authenticate web session")
                
        return html

    @staticmethod
    def parse_javascript_array_fields(data: str) -> list[str]:
        fields = []
        current = []
        in_quotes = False
        quote_char = ""
        escaped = False
        
        for char in data:
            if escaped:
                current.append(char)
                escaped = False
                continue
            if char == "\\":
                current.append(char)
                escaped = True
                continue
            if char in {"'", '"'}:
                if not in_quotes:
                    in_quotes = True
                    quote_char = char
                elif char == quote_char:
                    in_quotes = False
                else:
                    current.append(char)
                continue
            if char == "," and not in_quotes:
                fields.append("".join(current).strip())
                current = []
            else:
                current.append(char)
        if current:
            fields.append("".join(current).strip())
        return fields

    def parse_ajax_address_list(self, data: str) -> list[AddressEntry]:
        entries = []
        raw = str(data or "").strip()
        if not raw:
            return entries

        if not (raw.startswith("[") and raw.endswith("]")):
            first = raw.find("[")
            last = raw.rfind("]")
            if first < 0 or last <= first:
                return entries
            raw = raw[first : last + 1]

        raw_entries = re.findall(r"\[([^\]]+)\]", raw)
        for entry_raw in raw_entries:
            fields = self.parse_javascript_array_fields(entry_raw)
            if len(fields) < 8:
                continue
            last_used = fields[5]
            if "#" in last_used:
                last_used = last_used.split("#", 1)[1]
            type_map = {"1": "User", "2": "Group"}
            raw_entry_id = fields[0].strip().lstrip("[").strip("'\"")
            entry = AddressEntry(
                type=type_map.get(fields[1], f"Type_{fields[1]}"),
                registration_no=fields[2].strip("'\""),
                name=fields[3].strip("'\""),
                user_code=fields[4].strip("'\""),
                date_last_used=last_used.strip("'\""),
                email_address=fields[6].strip("'\""),
                folder=fields[7].strip("'\""),
                entry_id=raw_entry_id,
            )
            if entry.name or entry.registration_no:
                entries.append(entry)
        return entries

    @staticmethod
    def _strip_html(input_value: str) -> str:
        text = re.sub(r"<[^>]*>", "", input_value)
        text = re.sub(r"\s+", " ", text)
        return unescape(text.strip())

    def parse_html_address_list(self, html: str) -> list[AddressEntry]:
        entries = []
        tbody_match = re.search(r'<tbody id="ReportListArea_TableBody">(.*?)</tbody>', html, re.S)
        if not tbody_match:
            return entries

        rows = re.findall(r"<tr(?:\s+[^>]*)?>(?:\s*<td[^>]*>.*?</td>\s*){7,}</tr>", tbody_match.group(1), re.S)
        for row in rows:
            if "reportListDummyRow" in row:
                continue
            cells = re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)
            if len(cells) < 8:
                continue
            entry = AddressEntry(
                type=self._strip_html(cells[1]),
                registration_no=self._strip_html(cells[2]),
                name=self._strip_html(cells[3]),
                user_code=self._strip_html(cells[4]),
                date_last_used=self._strip_html(cells[5]),
                email_address=self._strip_html(cells[6]),
                folder=self._strip_html(cells[7]),
            )
            if entry.name and entry.name != "-" and entry.registration_no:
                entries.append(entry)
        return entries

    def get_address_book(self) -> list[AddressEntry]:
        self.reset_and_logout()

        if not self.login():
            LOGGER.error("Login failed. Please verify your LAN connection, IP address, or admin credentials.")
            return []

        # 1. Fetch the HTML list page first to establish session and get the wimToken
        html_targets = [
            "/web/entry/en/address/adrsList.cgi?modeIn=LIST_ALL",
            "/web/guest/en/address/adrsList.cgi?modeIn=LIST_ALL",
        ]
        
        adrs_wim_token = ""
        for path in html_targets:
            try:
                LOGGER.info(f"Fetching address list HTML to extract wimToken: GET {path}...")
                html_data = self.authenticate_and_get(path)
                if html_data.strip():
                    adrs_wim_token = self._extract_hidden_inputs(html_data).get("wimToken", "")
                    if adrs_wim_token:
                        LOGGER.info(f"Address list wimToken DETECTED: {adrs_wim_token}")
                        break
            except Exception as e:
                LOGGER.debug(f"Failed to fetch {path} for wimToken: {e}")

        if not adrs_wim_token:
            LOGGER.info("Address list wimToken NOT DETECTED or page failed to load. Will try AJAX without token.")

        # 2. Attempt AJAX targets
        ajax_targets = [
            "/web/entry/en/address/adrsListLoadEntry.cgi?listCountIn=200&getCountIn=1",
            "/web/entry/en/address/adrsListLoadEntry.cgi?listCountIn=50&getCountIn=1",
            "/web/guest/en/address/adrsListLoadEntry.cgi?listCountIn=200&getCountIn=1",
        ]
        
        for path in ajax_targets:
            sub_paths = []
            if adrs_wim_token:
                sub_paths.append(f"{path}&wimToken={adrs_wim_token}")
            sub_paths.append(path)
            
            for sub_path in sub_paths:
                try:
                    LOGGER.info(f"Attempting to fetch address book via AJAX endpoint {sub_path}...")
                    raw_data = self.authenticate_and_get(sub_path)
                    if "[" in raw_data and "]" in raw_data and "login.cgi" not in raw_data:
                        entries = self.parse_ajax_address_list(raw_data)
                        if entries:
                            LOGGER.info(f"Success! Retrieved and parsed {len(entries)} entries from AJAX ({sub_path})!")
                            return entries
                except Exception as e:
                    LOGGER.warning(f"Error fetching from AJAX endpoint {sub_path}: {e}")

        # 3. Fallback to HTML table parsing if AJAX fails
        for path in html_targets:
            try:
                LOGGER.info(f"Attempting fallback parsing of HTML table from {path}...")
                html_data = self.authenticate_and_get(path)
                entries = self.parse_html_address_list(html_data)
                if entries:
                    LOGGER.info(f"Success! Extracted {len(entries)} entries from HTML table ({path})!")
                    return entries
            except Exception as e:
                LOGGER.warning(f"Error extracting HTML table from {path}: {e}")

        LOGGER.error("Could not retrieve address book entries from any endpoints.")
        return []

def main():
    COPIER_IP = "192.168.1.226"
    USER = "admin"
    PASS = ""
    
    LOGGER.info("=== STARTING ADDRESS BOOK EXTRACTION ===")
    LOGGER.info(f"Printer IP address: {COPIER_IP}")
    LOGGER.info(f"Login credentials: Username: {USER} / Password: <empty>")
    
    extractor = RicohStandaloneExtractor(COPIER_IP, USER, PASS)
    try:
        entries = extractor.get_address_book()
        
        if entries:
            print("\n" + "="*80)
            print(f" RESULT: SUCCESSFULLY EXTRACTED {len(entries)} ADDRESS BOOK ENTRIES")
            print("="*80)
            
            print("\n--- JSON FORMATTED DATA ---")
            json_data = [asdict(e) for e in entries]
            print(json.dumps(json_data, indent=2, ensure_ascii=False))
            
            print("\n--- TABLE SUMMARY ---")
            header = f"{'Reg No':<8} | {'Type':<6} | {'Display Name':<25} | {'User Code':<10} | {'Email':<25} | {'Folder/FTP Path'}"
            print(header)
            print("-" * len(header))
            for e in entries:
                print(f"{e.registration_no:<8} | {e.type:<6} | {e.name:<25} | {e.user_code:<10} | {e.email_address:<25} | {e.folder}")
            print("="*80)
        else:
            LOGGER.error("Address book is empty or connection/login was rejected by the device.")
            
    except Exception as e:
        LOGGER.exception(f"Unexpected error occurred during extraction: {e}")

if __name__ == "__main__":
    main()
