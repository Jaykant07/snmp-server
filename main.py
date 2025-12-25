# main.py

import asyncio
import threading
from snmp_trap_server import start_trap_server
from snmp_poller import poll_loop


if __name__ == "__main__":
    # Start trap server in background thread
    t = threading.Thread(target=start_trap_server, daemon=True)
    t.start()

    # Start async polling loop
    asyncio.run(poll_loop())
