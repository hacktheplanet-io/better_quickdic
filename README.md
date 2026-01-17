better_quickdic is a lightweight Pwnagotchi plugin that automatically attempts
dictionary attacks on newly captured WPA/WPA2 handshakes using aircrack-ng.

When a valid handshake is detected, the plugin:
- Runs aircrack-ng using all *.txt wordlists in a configured folder
- Avoids crashing on malformed or partial handshakes
- Saves cracked credentials to a local cracked.txt log (deduplicated)
- Optionally sends the cracked SSID and password to Telegram (plain text)

This plugin is designed for stability on low-power devices (Pi Zero / Zero 2 W),
avoids repeated cracking of the same network, and does not interfere with normal
Pwnagotchi behavior such as passive capture or whitelisting.

Quick dictionary scan against captured handshakes using aircrack-ng.
- Saves cracked results to `/home/pi/handshakes/cracked.txt`
- Optional Telegram notification (plain text)

## Requirements
```bash
sudo apt-get update
sudo apt-get install -y aircrack-ng
pip3 install python-telegram-bot --break-system-packages

main.plugins.better_quickdic.enabled = true
main.plugins.better_quickdic.wordlist_folder = "/home/pi/wordlists/"
main.plugins.better_quickdic.face = "(·ω·)"

# Optional Telegram:
# main.plugins.better_quickdic.api = "YOUR_BOT_TOKEN"
# main.plugins.better_quickdic.id  = 123456789
