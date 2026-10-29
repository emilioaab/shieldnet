import time
import asyncio
from shieldnet import *
from datetime import datetime
from quart import Quart, websocket, request, render_template

app = Quart(__name__)
sniffer = ShieldNet()

@app.route('/', methods=['GET'])
async def index():
    global sniffer
    return await render_template(
        'homepage.html',
        config=[sniffer.network_interface, sniffer.local_ip, sniffer.local_mac],
        flags=sniffer.anomaly_tracking
    )

async def WS_receiver():
    global sniffer
    while sniffer.websocket_connection is not None:
        data = await sniffer.websocket_connection.receive()
        if data == 'CMD::START':
            if sniffer.monitor_active:
                await sniffer.websocket_connection.send('LOG::Already Running')
            else:
                await sniffer.websocket_connection.send(f'LOG::Started Sniffer @ {str(datetime.now()).split(".")[0]}')
                sniffer.start()
        elif data == 'CMD::STOP':
            if sniffer.monitor_active:
                await sniffer.websocket_connection.send(f'LOG::Stopped Sniffer @ {str(datetime.now()).split(".")[0]}')
                sniffer.stop()
            else:
                await sniffer.websocket_connection.send('LOG::Already Stopped')
        elif data == 'CMD::FATTACKERS':
            if any([sniffer.anomaly_tracking[category]['flag'] for category in sniffer.anomaly_tracking]):
                await sniffer.websocket_connection.send(f"FA0::{sniffer.find_attackers('TCP-SYN')}{sniffer.find_attackers('TCP-SYNACK')}{sniffer.find_attackers('ICMP-POD')}{sniffer.find_attackers('ICMP-SMURF')}")
            else:
                await sniffer.websocket_connection.send('FA0::No DDOS attack detected yet. Try again later.')
        else:
            await sniffer.websocket_connection.send('LOG::Invalid CMD')

async def WS_sender():
    global sniffer
    while sniffer.websocket_connection is not None:
        if sniffer.recent_logs:
            data = []
            for pkt in sniffer.recent_logs[::-1]:
                msg = f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(pkt[0]))} <{'|'.join(pkt[1])}> {pkt[2]}:{pkt[6]} ({pkt[4]}) => {pkt[3]}:{pkt[7]} ({pkt[5]})"
                if pkt[8]:
                    msg += f" [{pkt[8]} bytes]"
                if pkt[9]:
                    msg += f" <{pkt[9]}>"
                data.append(msg)
            await sniffer.websocket_connection.send("PKT::" + "\n".join(data))
        await sniffer.websocket_connection.send(f"FLAG:{sniffer.anomaly_tracking['TCP-SYN']['flag']},{sniffer.anomaly_tracking['TCP-SYNACK']['flag']},{sniffer.anomaly_tracking['ICMP-POD']['flag']},{sniffer.anomaly_tracking['ICMP-SMURF']['flag']}")

@app.websocket('/ws')
async def ws():
    global sniffer
    try:
        if not sniffer.websocket_connection:
            sniffer.websocket_connection = websocket
            await websocket.accept()
        else:
            return "Already connect to WS", 400
        producer = asyncio.create_task(WS_sender())
        consumer = asyncio.create_task(WS_receiver())
        await asyncio.gather(producer, consumer)
    except asyncio.CancelledError:
        sniffer.websocket_connection = None
        sniffer.stop()
        raise

if not is_admin():
    sys.exit("[-] Please execute the script with root or administrator priviledges.\n[-] Exiting.")
else:
    try:
        app.run()
    except KeyboardInterrupt:
        sys.exit("[-] Ctrl + C triggered.\n[-] Shutting Down")