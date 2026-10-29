import os
import sys
import ctypes
import threading
from scapy.all import *
from queue import Queue

banner = '''-----------------------
ShieldNet
-----------------------
'''


class ShieldNet():
    def __init__(self):
        self.network_interface = conf.iface
        self.local_ip = [x[4] for x in conf.route.routes if x[2] != '0.0.0.0' and x[3] == self.network_interface][0]
        self.local_mac = get_if_hwaddr(self.network_interface)
        self.websocket_connection = None
        self.packet_queue = Queue()
        self.device_mac_map = {}
        self.recent_logs = []
        self.anomaly_tracking = {
            'SYN-Flood': {'alert': False, 'events': [], 'attacker_macs': []},
            'SYN-ACK-Flood': {'alert': False, 'events': [], 'attacker_macs': []},
            'ICMP-POD': {'alert': False, 'events': [], 'attacker_macs': []},
            'ICMP-SMURF': {'alert': False, 'events': [], 'attacker_macs': []},
        }
        self.monitor_active = False

    def capture_packets(self):
        while self.monitor_active:
            packet = sniff(count=1)
            with threading.Lock():
                self.packet_queue.put(packet[0])

    def process_packets(self):
        while self.monitor_active:
            packet = self.packet_queue.get()
            self.analyze_packet(packet)
            self.packet_queue.task_done()

    def compute_average_interval(self, event_log):
        interval_sum = 0
        index = -1
        while index > -31:
            interval_sum += event_log[index][0] - event_log[index - 1][0]
            index -= 1
        interval_sum /= len(event_log)
        return (interval_sum < 2 and self.recent_logs[-1][0] - event_log[-1][0] < 10)

    def identify_attack_sources(self, attack_type):
        attackers = []
        for mac in self.anomaly_tracking[attack_type]['attacker_macs']:
            attackers.append(
                f"({self.device_mac_map[mac]}, {mac})" if mac in self.device_mac_map else f"(Unknown IP, {mac})")
        return attack_type + ' Attackers Sources:<br>' + "<br>".join(attackers) + '<br><br>'

    def update_alert_flags(self):
        for attack_type in self.anomaly_tracking:
            if len(self.anomaly_tracking[attack_type]['events']) > 20:
                self.anomaly_tracking[attack_type]['alert'] = self.compute_average_interval(
                    self.anomaly_tracking[attack_type]['events'])
                if self.anomaly_tracking[attack_type]['alert']:
                    self.anomaly_tracking[attack_type]['attacker_macs'] = list(
                        set([event[3] for event in self.anomaly_tracking[attack_type]['activities']]))

    def analyze_packet(self, packet):
        source_ip, dest_ip, source_port, dest_port, tcp_flags, icmp_type = None, None, None, None, None, None
        protocol_detected = []

        if len(self.recent_logs) > 15:
            self.recent_logs = self.recent_logs[-15:]

        for attack_type in self.anomaly_tracking:
            if len(self.anomaly_tracking[attack_type]['events']) > 30:
                self.anomaly_tracking[attack_type]['events'] = self.anomaly_tracking[attack_type]['events'][-30:]

        self.update_alert_flags()

        source_mac = packet[Ether].src if Ether in packet else None
        dest_mac = packet[Ether].dst if Ether in packet else None

        if IP in packet:
            source_ip = packet[IP].src
            dest_ip = packet[IP].dst
        elif IPv6 in packet:
            source_ip = packet[IPv6].src
            dest_ip = packet[IPv6].dst

        if TCP in packet:
            protocol_detected.append("TCP")
            source_port = packet[TCP].sport
            dest_port = packet[TCP].dport
            tcp_flags = packet[TCP].flags.flagrepr()
        if UDP in packet:
            protocol_detected.append("UDP")
            source_port = packet[UDP].sport
            dest_port = packet[UDP].dport
        if ICMP in packet:
            protocol_detected.append("ICMP")
            icmp_type = packet[ICMP].type

        if ARP in packet and packet[ARP].op in (1, 2):
            protocol_detected.append("ARP")
            if packet[ARP].hwsrc in self.device_mac_map.keys() and self.device_mac_map[packet[ARP].hwsrc] != packet[ARP].psrc:
                self.device_mac_map[packet[ARP].hwsrc] = packet[ARP].psrc
            if packet[ARP].hwsrc not in self.device_mac_map.keys():
                self.device_mac_map[packet[ARP].hwsrc] = packet[ARP].psrc

        payload_size = len(packet[Raw].load) if Raw in packet else None

        attack_type = None

        if ICMP in packet:
            if source_ip == self.local_ip and source_mac != self.local_mac:
                self.anomaly_tracking['ICMP-SMURF']['activities'].append([
                                                                            packet.time, ])
                attack_type = 'ICMP-SMURF PACKET'

            if payload_size and payload_size > 1024:
                self.anomaly_tracking['ICMP-POD']['activities'].append([
                                                                          packet.time, ])
                attack_type = 'ICMP-PoD PACKET'

        if dest_ip == self.local_ip:
            if TCP in packet:
                if tcp_flags == "S":
                    self.anomaly_tracking['TCP-SYN']['activities'].append([
                                                                             packet.time, ])
                    attack_type = 'TCP-SYN PACKET'

                elif tcp_flags == "SA":
                    self.anomaly_tracking['TCP-SYNACK']['activities'].append([
                                                                                packet.time, ])
                    attack_type = 'TCP-SYNACK PACKET'

        self.recent_logs.append(
            [packet.time, protocol_detected, source_ip, dest_ip, source_mac, dest_mac, source_port, dest_port, payload_size, attack_type])

    def start(self):
        if not self.monitor_active:
            self.monitor_active = True
            sniff_thread = threading.Thread(target=self.capture_packets)
            sniff_thread.daemon = True
            sniff_thread.start()
            analyze_thread = threading.Thread(target=self.process_packets)
            analyze_thread.daemon = True
            analyze_thread.start()
        return self.monitor_active

    def stop(self):
        self.monitor_active = False
        self.packet_queue = Queue()
        self.recent_logs = []
        self.anomaly_tracking = {
            'TCP-SYN': {'flag': False, 'activities': [], 'attacker-mac': []},
            'TCP-SYNACK': {'flag': False, 'activities': [], 'attacker-mac': []},
            'ICMP-POD': {'flag': False, 'activities': [], 'attacker-mac': []},
            'ICMP-SMURF': {'flag': False, 'activities': [], 'attacker-mac': []},
        }
        return self.monitor_active


def clear_screen():
    if "linux" in sys.platform:
        os.system("clear")
    elif "win32" in sys.platform:
        os.system("cls")
    else:
        pass


def is_admin():
    try:
        return os.getuid() == 0
    except AttributeError:
        pass
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() == 1
    except AttributeError:
        return False