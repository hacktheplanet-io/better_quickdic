# better_quickdic (Pwnagotchi)

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
