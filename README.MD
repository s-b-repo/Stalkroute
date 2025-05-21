# stalkroute

> ⚡️ **Stealthy, Spoofing, Anti-Detection Traceroute for Advanced Pentesters & Red Teams**

![stalkroute](https://user-images.githubusercontent.com/your-gh-user/stalkroute-banner.png)

---

**stalkroute** is an advanced, stealth-focused for tracing the whole routeno more hiding the traceroute tool for ethical hackers, red teams, and penetration testers.  
It stalks the network path to a target while evading firewalls, detection systems, and network monitoring.

- 🚩 **Bypasses firewalls and rate-limiters with randomized probes**
- 🦑 **Spoofs source IP and mimics common OS packet signatures**
- 🎭 **Rotates protocols: ICMP, UDP, TCP SYN — not just boring ICMP**
- 🔍 **Detects and reports blocked, filtered, or stealthed hops**
- 🕵️ **Anti-detection: jitter, decoy payloads, randomized timing**
- 💾 **Fully open source, customizable for your ops**

---

## Features

- **Stealth Probing**: Random source port, ID, TTL, TOS, and timing
- **Protocol Obfuscation**: Each hop may receive ICMP, UDP, or TCP packets
- **Source IP Spoofing**: Internal subnet spoof support (root required)
- **Detection Evasion**: Jitter between probes, randomized OS fingerprints, and more
- **Blocked Hop Reporting**: Clearly shows which hops are filtered or blocked
- **Interactive**: Asks for a target on startup
- **Colorful Output**: Easy to follow, real-time results

---

## Demo

```

sudo python3 stalkroute.py

\[?] Enter the target IP or domain: example.com
\[+] Traceroute to example.com (max 30 hops)
\[\*] Resolved example.com to 93.184.216.34
\[TTL= 1] 192.168.1.1      time-exceeded (icmp) 0.8ms
\[TTL= 2] 197.155.24.1     time-exceeded (udp) 1.2ms
\[TTL= 3] BLOCKED / FILTERED
\[TTL= 4] 41.13.62.241     time-exceeded (tcp) 7.7ms
...
\[+] Target reached: 93.184.216.34

````

---

## Install

```
pip install scapy colorama
````

---

## Usage

```
sudo python3 stalkroute.py
```

**Note:**

* Must be run as root for raw socket spoofing and source IP spoofing.
* Works on Linux, macOS (with sudo), WSL2 (with limitations).

---

## Options

* Edit the config at the top of `stalkroute.py` to tune:

  * `MAX_TTL`: Maximum hops to scan
  * `PROBE_COUNT`: Number of probes per hop
  * `JITTER_RANGE`: Stealth delay between probes
  * `DECOY_PROB`: Probability to send non-ICMP probes
  * `SPOOF_SRC_IP`: Spoof internal IP (e.g. `192.168.1.222`), or leave `None`
  * `USE_RANDOM_OS_SIG`: Emulate random OS fingerprints for each probe

---

## Ethical Use

This tool is intended **strictly for authorized security testing, research, and learning**.
**Do not use on networks or targets you do not own or have explicit written permission to test.**

---

## License

[MIT](LICENSE)

---

## Credits

* Developed by [Suicidalteddy](https://github.com/your-gh-user)
* Powered by [Scapy](https://scapy.net/) and [Colorama](https://pypi.org/project/colorama/)

---

## Screenshots

![screenshot](https://user-images.githubusercontent.com/s-b-repo/Stalkroute/main/Screenshot_20250521_225036.png)
---



## Contributing

PRs and issues welcome!
Hacker improvements, OS fingerprint tweaks, and extra evasion logic especially appreciated.

```
