# better_quickdic (Pwnagotchi)

Quick dictionary scan against captured handshakes using aircrack-ng.
- Saves cracked results to `/home/pi/handshakes/cracked.txt`
- Optional Telegram notification (plain text)

## Requirements
```bash
sudo apt-get update
sudo apt-get install -y aircrack-ng
pip3 install python-telegram-bot --break-system-packages
