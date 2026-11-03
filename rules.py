from scapy.all import sniff, TCP, IP


def make_event(rule, packet):
    return {
        "rule": rule,
        "severity": "HIGH",
        "src": packet[IP].src,
        "sport": packet[TCP].sport,
        "dst": packet[IP].dst,
        "dport": packet[TCP].dport,
        "flags": str(packet[TCP].flags),
        "ip_id": packet[IP].id,          # ← добавили
        "seq":   packet[TCP].seq,        # ← добавили
        "extra": {},
    }


def detect_null_scan(packet):
    if packet[TCP].flags == 0:
        return make_event("NULL_SCAN", packet)
    return None

def detect_xmas_scan(packet):
    if packet[TCP].flags == 'FPU':
        return make_event("XMAS_SCAN", packet)
    return None

#def detect_maimon_scan(packet):
#    if packet[TCP].flags == 'FA':
#        return make_event("MAIMON_SCAN", packet)
#    return None

def detect_sf_scan(packet):
    if packet[TCP].flags == 'SF':
        return make_event("SYN_FIN_SCAN", packet)
    return None

def detect_sfp_scan(packet):
    if packet[TCP].flags == 'SFP':
        return make_event("SYN_FIN_PSH_SCAN", packet)
    return None

def detect_sfr_scan(packet):
    if packet[TCP].flags == 'SFR':
        return make_event("SYN_FIN_RST_SCAN", packet)
    return None

def detect_sr_scan(packet):
    if packet[TCP].flags == 'SR':
        return make_event("SYN_RST_SCAN", packet)
    return None

def detect_fullxmas_scan(packet):
    if packet[TCP].flags == 'UAPRSF':
        return make_event("FULL_XMAS_SCAN", packet)
    return None