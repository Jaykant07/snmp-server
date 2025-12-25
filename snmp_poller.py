# snmp_poller.py

import asyncio
from pysnmp.hlapi.asyncio import (
    SnmpEngine,
    CommunityData,
    ContextData,
    ObjectType,
    ObjectIdentity,
    get_cmd,
    UdpTransportTarget,
)
from device_inventory import DEVICES
from snmp_analysis import analyze_snmp_log

POLL_INTERVAL = 5

OIDS = {
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysDescr": "1.3.6.1.2.1.1.1.0",
}


async def snmp_get(ip, community, oid):
    engine = SnmpEngine()
    target = await UdpTransportTarget.create((ip, 161), timeout=1.0, retries=1)

    errInd, errStat, _, varBinds = await get_cmd(
        engine,
        CommunityData(community),
        target,
        ContextData(),
        ObjectType(ObjectIdentity(oid)),
    )

    if errInd or errStat:
        return None

    for _, val in varBinds:
        return val.prettyPrint()


async def poll_loop():
    while True:
        for dev in DEVICES:
            snmp_log = {"ip": dev["ip"]}

            for k, oid in OIDS.items():
                val = await snmp_get(dev["ip"], dev["community"], oid)
                if k == "sysUpTime" and val:
                    try:
                        snmp_log[k] = int(val)
                    except ValueError:
                        snmp_log[k] = None
                else:
                    snmp_log[k] = val

            analysis = analyze_snmp_log(snmp_log)
            print(f"[POLL] {analysis.ip} → {analysis.health}")

        await asyncio.sleep(POLL_INTERVAL)
