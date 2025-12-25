import asyncio
from pysnmp.hlapi.v3arch.asyncio import (
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    NotificationType,
    ObjectIdentity,
    OctetString,
    TimeTicks,
    send_notification,
)
    

async def send_test_trap():
    print("Sending SNMP trap...")

    # Create async transport
    transport = await UdpTransportTarget.create(("127.0.0.1", 516))

    errorIndication, errorStatus, errorIndex, varBinds = await send_notification(
        SnmpEngine(),
        CommunityData("public", mpModel=1),    # SNMPv2c
        transport,                             # correct transport target
        ContextData(),
        "trap",
        NotificationType(
            ObjectIdentity("1.3.6.1.6.3.1.1.5.3")  # linkDown OID
        ).addVarBinds(
            ("1.3.6.1.2.1.1.5.0", OctetString("test-device")),               # sysName.0
            ("1.3.6.1.2.1.1.1.0", OctetString("Linux ubuntu-lab test system testing")),  # sysDescr.0
            ("1.3.6.1.2.1.1.3.0", TimeTicks(9876543)),                        # sysUpTime.0
        ),
    )

    if errorIndication:
        print("ERROR:", errorIndication)
    elif errorStatus:
        print(
            f"{errorStatus.prettyPrint()} at "
            f"{errorIndex and varBinds[int(errorIndex)-1][0] or '?'}"
        )
    else:
        print("Trap sent successfully!")


if __name__ == "__main__":
    asyncio.run(send_test_trap())
