from pysnmp.hlapi.v3arch.asyncio import (
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    get_cmd
)

SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_NAME  = "1.3.6.1.2.1.1.5.0"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"

async def enrich_device(ip):
    engine = SnmpEngine()

    transport = await UdpTransportTarget.create(
        (ip, 516), timeout=1, retries=1
    )

    errorIndication, errorStatus, _, varBinds = await get_cmd(
        engine,
        CommunityData("public", mpModel=1),
        transport,
        ContextData(),
        ObjectType(ObjectIdentity(SYS_DESCR)),
        ObjectType(ObjectIdentity(SYS_NAME)),
        ObjectType(ObjectIdentity(SYS_UPTIME)),
    )

    if errorIndication or errorStatus:
        return {}

    result = {}
    for oid, val in varBinds:
        oid_str = oid.prettyPrint()
        val_str = val.prettyPrint()

        if oid_str == SYS_DESCR:
            result["sysDescr"] = val_str
        elif oid_str == SYS_NAME:
            result["sysName"] = val_str
        elif oid_str == SYS_UPTIME:
            result["sysUpTime"] = int(val)

    return result
