from scapy.all import sniff
from rules import (
    detect_null_scan,
    detect_xmas_scan,
    detect_sf_scan,
    detect_sfp_scan,
    detect_sfr_scan,
    detect_sr_scan,
    detect_fullxmas_scan,
)

RULES = [
    ("NULL_SCAN", detect_null_scan),
    ("XMAS_SCAN", detect_xmas_scan),
    ("SYN_FIN_SCAN", detect_sf_scan),
    ("SYN_FIN_PSH_SCAN", detect_sfp_scan),
    ("SYN_FIN_RST_SCAN", detect_sfr_scan),
    ("SYN_RST_SCAN", detect_sr_scan),
    ("FULL_XMAS_SCAN", detect_fullxmas_scan),
]

def dispatcher(packet):
    for name, rule_func in RULES:
        try:
            event = rule_func(packet)
            if event is not None:
                print(f"Detected {name}: {event}")
        except Exception as e:
            print(f"Rule {name} failed: {e}")

if __name__ == "__main__":
    sniff(filter="tcp and ip", prn=dispatcher, store=0, iface="lo")  # Change "eth0" to your network interface