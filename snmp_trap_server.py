# snmp_trap_server.py

import asyncio

from pysnmp.carrier.asyncio.dispatch import AsyncioDispatcher
from pysnmp.carrier.asyncio.dgram import udp
from pyasn1.codec.ber import decoder
from pysnmp.proto import api

from snmp_analysis import analyze_snmp_log, analyze_trap_event
from cisco_parser import parse_cisco_trap
from snmp_enricher import enrich_device


TRAP_PORT = 516   # single source of truth


def trap_callback(dispatcher, domain, address, whole_msg):
    while whole_msg:
        msg_ver = int(api.decodeMessageVersion(whole_msg))
        if msg_ver not in api.PROTOCOL_MODULES:
            return whole_msg

        p_mod = api.PROTOCOL_MODULES[msg_ver]
        req_msg, whole_msg = decoder.decode(
            whole_msg, asn1Spec=p_mod.Message()
        )

        src_ip = address[0]
        req_pdu = p_mod.apiMessage.get_pdu(req_msg)

        is_inform = req_pdu.isSameTypeWith(p_mod.InformRequestPDU())

        # ---- VARBINDS ----
        if req_pdu.isSameTypeWith(p_mod.TrapPDU()) and msg_ver == api.SNMP_VERSION_1:
            var_binds = p_mod.apiTrapPDU.get_varbinds(req_pdu)
        else:
            var_binds = p_mod.apiPDU.get_varbinds(req_pdu)

        raw = {oid.prettyPrint(): val.prettyPrint() for oid, val in var_binds}

        # ---- INITIAL LOG ----
        snmp_log = {
            "ip": src_ip,
            "sysDescr": raw.get("1.3.6.1.2.1.1.1.0"),
            "sysName": raw.get("1.3.6.1.2.1.1.5.0"),
            "trapOID": raw.get("1.3.6.1.6.3.1.1.4.1.0"),
        }

        uptime = raw.get("1.3.6.1.2.1.1.3.0")
        snmp_log["sysUpTime"] = int(uptime) if uptime and uptime.isdigit() else None

        # ---- IMMEDIATE ANALYSIS ----
        analysis = analyze_snmp_log(snmp_log)
        analysis = analyze_trap_event(snmp_log, analysis)
        analysis = parse_cisco_trap(snmp_log, analysis)

        kind = "INFORM" if is_inform else "TRAP"
        print(f"[{kind}] {analysis.ip} → {analysis.health}")

        # ---- ASYNC ENRICHMENT ----
        if not snmp_log.get("sysName") or not snmp_log.get("sysUpTime"):

            async def enrich_and_report():
                try:
                    enriched = await enrich_device(src_ip)
                    snmp_log.update(enriched)

                    enriched_analysis = analyze_snmp_log(snmp_log)
                    enriched_analysis = analyze_trap_event(snmp_log, enriched_analysis)
                    enriched_analysis = parse_cisco_trap(snmp_log, enriched_analysis)

                    print(
                        f"[ENRICHED] {enriched_analysis.ip} "
                        f"{enriched_analysis.name} "
                        f"Uptime={enriched_analysis.uptime_str} "
                        f"Health={enriched_analysis.health}"
                    )

                except Exception as e:
                    print(f"[ENRICH ERROR] {src_ip}: {e}")

            asyncio.get_running_loop().create_task(enrich_and_report())

    return whole_msg


def start_trap_server():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    dispatcher = AsyncioDispatcher(loop=loop)
    dispatcher.register_recv_callback(trap_callback)

    dispatcher.register_transport(
        udp.DOMAIN_NAME,
        udp.UdpAsyncioTransport().open_server_mode(("0.0.0.0", TRAP_PORT)),
    )

    dispatcher.job_started(1)
    print(f"SNMP Trap Server listening on UDP/{TRAP_PORT}")

    try:
        loop.run_forever()
    finally:
        dispatcher.close_dispatcher()
        loop.close()
