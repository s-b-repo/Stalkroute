#!/usr/bin/env python3

import random, time, sys, socket, struct
from scapy.all import *
from colorama import Fore, Style

# Stealth config
USE_RANDOM_OS_SIG = True
SPOOF_SRC_IP = None        # Set to None for real IP, or e.g. '192.168.1.222'
JITTER_RANGE = (0.2, 1.1)
MAX_TTL = 30
PROBE_COUNT = 3
DECOY_PROB = 0.35
print("by suicidalteddy")
print("github.com/s-b-repo")
print("medium.com/@suicdalteddy/about")
def os_sig():
    if not USE_RANDOM_OS_SIG:
        return {}
    sigs = [
        {'id': random.randint(0x4000, 0xffff), 'ttl': random.choice([128, 64, 255]), 'tos': 0, 'flags': 'DF'},
        {'id': random.randint(0, 0xffff), 'ttl': 64, 'tos': 0, 'flags': ''},
        {'id': random.randint(0, 0xffff), 'ttl': 255, 'tos': 0, 'flags': 'DF'},
        {'id': random.randint(0, 0xffff), 'ttl': 128, 'tos': 0x10, 'flags': ''},
    ]
    return random.choice(sigs)

def stealth_probe(dst, ttl, src_ip=None):
    sig = os_sig()
    proto = 'icmp'
    if random.random() < DECOY_PROB:
        proto = random.choice(['udp', 'tcp'])
    sport = random.randint(33434, 65535)
    dport = random.randint(33434, 65535)
    pkt_ip = IP(dst=dst, ttl=ttl, id=sig.get('id', 0), tos=sig.get('tos', 0))
    if src_ip: pkt_ip.src = src_ip
    if 'flags' in sig: pkt_ip.flags = sig['flags']
    if proto == 'icmp':
        pkt = pkt_ip/ICMP(id=sport, seq=ttl)/Raw(load=RandString(size=random.randint(24,56)))
    elif proto == 'udp':
        pkt = pkt_ip/UDP(sport=sport, dport=dport)/Raw(load=RandString(size=random.randint(24,56)))
    else:
        pkt = pkt_ip/TCP(sport=sport, dport=dport, flags='S')/Raw(load=RandString(size=random.randint(24,56)))
    return pkt, proto

def trace(target, max_ttl=MAX_TTL, probes=PROBE_COUNT):
    print(f"{Fore.CYAN}[+] Traceroute to {target} (max {max_ttl} hops){Style.RESET_ALL}")
    try:
        dst_ip = socket.gethostbyname(target)
    except Exception as e:
        print(f"{Fore.RED}[-] Could not resolve target: {e}{Style.RESET_ALL}")
        sys.exit(1)
    print(f"{Fore.GREEN}[*] Resolved {target} to {dst_ip}{Style.RESET_ALL}")

    for ttl in range(1, max_ttl + 1):
        line = f"{Fore.YELLOW}[TTL={ttl:2d}] "
        responded = False
        hop_ips = set()
        for probe in range(probes):
            pkt, proto = stealth_probe(dst_ip, ttl, src_ip=SPOOF_SRC_IP)
            t0 = time.time()
            ans = sr1(pkt, verbose=0, timeout=2)
            elapsed = (time.time() - t0)*1000

            if ans:
                responded = True
                hop_ip = ans.src
                hop_ips.add(hop_ip)
                rtt = f"{elapsed:.1f}ms"
                info = ""
                if ans.haslayer(ICMP):
                    icmp_type = ans.getlayer(ICMP).type
                    if icmp_type == 11:
                        info = f"{Fore.BLUE}time-exceeded"
                    elif icmp_type == 0:
                        info = f"{Fore.GREEN}echo-reply"
                    elif icmp_type == 3:
                        info = f"{Fore.RED}unreachable"
                elif ans.haslayer(TCP):
                    info = f"{Fore.MAGENTA}tcp"
                elif ans.haslayer(UDP):
                    info = f"{Fore.MAGENTA}udp"
                else:
                    info = f"{Fore.WHITE}unknown"
                print(f"{line}{Style.BRIGHT}{hop_ip:<16}{Style.RESET_ALL} {info}{Style.RESET_ALL} ({proto}) {rtt}")
                if hop_ip == dst_ip:
                    print(f"{Fore.GREEN}[+] Target reached: {hop_ip}{Style.RESET_ALL}")
                    return
            time.sleep(random.uniform(*JITTER_RANGE))

        if not responded:
            print(f"{line}{Fore.RED}{Style.BRIGHT}BLOCKED / FILTERED{Style.RESET_ALL}")
        # Optionally: print a summary per hop if multiple IPs reply (rare)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This must be run as root (for raw socket spoofing!)")
        sys.exit(1)
    try:
        target = input(Fore.CYAN + "[?] Enter the target IP or domain: " + Style.RESET_ALL).strip()
        if not target:
            print(Fore.RED + "[-] No target provided." + Style.RESET_ALL)
            sys.exit(1)
        trace(target)
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Exiting..." + Style.RESET_ALL)
        sys.exit(0)
