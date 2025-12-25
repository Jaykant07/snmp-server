# cisco_mib.py

CISCO_ENTERPRISE_PREFIX = "1.3.6.1.4.1.9"

CISCO_TRAPS = {
    # Power Supply
    "1.3.6.1.4.1.9.9.13.3.0.1": {
        "name": "Power Supply Failure",
        "severity": "CRITICAL",
        "category": "HARDWARE"
    },

    # Temperature
    "1.3.6.1.4.1.9.9.13.3.0.2": {
        "name": "Temperature Alarm",
        "severity": "CRITICAL",
        "category": "ENVIRONMENT"
    },

    # Fan Failure
    "1.3.6.1.4.1.9.9.13.3.0.3": {
        "name": "Fan Failure",
        "severity": "CRITICAL",
        "category": "HARDWARE"
    },

    # CPU High
    "1.3.6.1.4.1.9.9.109.2.0.1": {
        "name": "CPU High Utilization",
        "severity": "WARNING",
        "category": "PERFORMANCE"
    },

    # Memory High
    "1.3.6.1.4.1.9.9.48.2.0.1": {
        "name": "Memory Pool Low",
        "severity": "WARNING",
        "category": "PERFORMANCE"
    }
}
