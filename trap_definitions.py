# trap_definitions.py

TRAP_EVENTS = {
    "1.3.6.1.6.3.1.1.5.1": {
        "name": "Cold Start",
        "severity": "WARNING",
        "score_delta": -10,
        "reason": "Device rebooted (cold start)",
    },
    "1.3.6.1.6.3.1.1.5.2": {
        "name": "Warm Start",
        "severity": "WARNING",
        "score_delta": -5,
        "reason": "Device restarted (warm start)",
    },
    "1.3.6.1.6.3.1.1.5.3": {
        "name": "Link Down",
        "severity": "CRITICAL",
        "score_delta": -30,
        "reason": "Network interface went down",
    },
    "1.3.6.1.6.3.1.1.5.4": {
        "name": "Link Up",
        "severity": "INFO",
        "score_delta": +5,
        "reason": "Network interface is up",
    },
    "1.3.6.1.6.3.1.1.5.5": {
        "name": "Authentication Failure",
        "severity": "CRITICAL",
        "score_delta": -40,
        "reason": "SNMP authentication failure detected",
    },
}
