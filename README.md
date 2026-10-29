# ShieldNet

A lightweight **network anomaly / DDoS detection** tool. ShieldNet sniffs local
network traffic and raises alerts on flood patterns such as SYN-Flood and
SYN-ACK-Flood, with a small web dashboard to view recent events.

> Defensive security project — built to **detect** attacks against a host, not to perform them.

## Tech
Python · Scapy · Flask · WebSockets

## Run
```bash
pip install -r requirements.txt
sudo python3 shieldnet.py   # raw sockets need elevated privileges
```
Then open the dashboard served by `app.py`.

## Notes
Academic project at SCE. Run only on networks you own or are authorized to monitor.
