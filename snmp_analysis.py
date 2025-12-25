# snmp_analysis.py

from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, Dict, Any, List


@dataclass
class DeviceSnapshot:
    ip: str
    sys_name: str
    sys_descr: str
    sys_uptime_ticks: Optional[int] = None
    cpu_load: Optional[float] = None
    mem_used_percent: Optional[float] = None


@dataclass
class DeviceAnalysis:
    ip: str
    name: str
    device_type: str
    uptime_str: str
    health: str
    health_score: int
    reasons: List[str]


def classify_device(sys_descr: str) -> str:
    d = (sys_descr or "").lower()

    if "cisco" in d or "ios software" in d or "router" in d:
        return "router"
    if "switch" in d:
        return "switch"
    if any(os_word in d for os_word in ["windows", "linux", "ubuntu", "debian", "centos"]):
        return "server/pc"
    if any(pr in d for pr in ["printer", "laserjet", "officejet"]):
        return "printer"
    return "unknown"


def ticks_to_uptime_str(ticks: Optional[int]) -> str:
    if ticks is None:
        return "unknown"

    total_seconds = ticks // 100
    days = total_seconds // 86400
    rem = total_seconds % 86400
    hours = rem // 3600
    rem %= 3600
    minutes = rem // 60
    seconds = rem % 60

    if days > 0:
        return f"{days}d {hours:02d}:{minutes:02d}:{seconds:02d}"
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


def compute_health(snapshot: DeviceSnapshot) -> tuple[str, int, List[str]]:
    score = 100
    reasons: List[str] = []

    # Uptime
    if snapshot.sys_uptime_ticks is None:
        reasons.append("No uptime information from SNMP")
        score -= 10
    else:
        seconds = snapshot.sys_uptime_ticks / 100.0
        if seconds < 5 * 60:
            reasons.append("Device just booted (<5 minutes uptime)")
            score -= 5
        elif seconds < 60 * 60:
            reasons.append("Device uptime <1 hour")
            score -= 2

    # CPU & memory usually not in traps → just mark as not present
    if snapshot.cpu_load is None:
        reasons.append("CPU usage not included in this SNMP notification")
    if snapshot.mem_used_percent is None:
        reasons.append("Memory usage not included in this SNMP notification")

    score = max(0, min(100, score))

    if score >= 90:
        health = "OK"
    elif score >= 70:
        health = "WARN"
    else:
        health = "CRITICAL"

    if not reasons:
        reasons.append("All monitored parameters within normal range")

    return health, score, reasons


def analyze_snmp_log(snmp_log: Dict[str, Any]) -> DeviceAnalysis:
    snapshot = DeviceSnapshot(
        ip=snmp_log.get("ip", "unknown"),
        sys_name=snmp_log.get("sysName", "unknown"),
        sys_descr=snmp_log.get("sysDescr", ""),
        sys_uptime_ticks=snmp_log.get("sysUpTime"),
        cpu_load=snmp_log.get("cpuLoad"),
        mem_used_percent=snmp_log.get("memUsedPercent"),
    )

    device_type = classify_device(snapshot.sys_descr)
    uptime_str = ticks_to_uptime_str(snapshot.sys_uptime_ticks)
    health, score, reasons = compute_health(snapshot)

    return DeviceAnalysis(
        ip=snapshot.ip,
        name=snapshot.sys_name,
        device_type=device_type,
        uptime_str=uptime_str,
        health=health,
        health_score=score,
        reasons=reasons,
    )

from trap_definitions import TRAP_EVENTS


def analyze_trap_event(snmp_log, analysis):
    trap_oid = snmp_log.get("trapOID")

    if not trap_oid:
        return analysis

    event = TRAP_EVENTS.get(trap_oid)
    if not event:
        analysis.reasons.append(f"Unknown SNMP trap received: {trap_oid}")
        return analysis

    analysis.reasons.append(event["reason"])
    analysis.health = event["severity"]
    analysis.health_score = max(0, analysis.health_score + event["score_delta"])

    return analysis
