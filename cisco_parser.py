# cisco_parser.py

from cisco_mib import CISCO_TRAPS, CISCO_ENTERPRISE_PREFIX

def parse_cisco_trap(snmp_log, analysis):
    trap_oid = snmp_log.get("trapOID")

    if not trap_oid:
        return analysis

    # Not Cisco
    if not trap_oid.startswith(CISCO_ENTERPRISE_PREFIX):
        return analysis

    cisco_def = CISCO_TRAPS.get(trap_oid)

    if not cisco_def:
        analysis.vendor = "CISCO"
        analysis.health = "WARNING"
        analysis.reason = "Unknown Cisco Trap"
        return analysis

    # Known Cisco trap
    analysis.vendor = "CISCO"
    analysis.health = cisco_def["severity"]
    analysis.reason = cisco_def["name"]
    analysis.category = cisco_def["category"]

    return analysis
