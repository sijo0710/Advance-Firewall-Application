from flask import Flask, request, jsonify, send_from_directory
import re

app = Flask(__name__)

class Settings:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Settings, cls).__new__(cls)
            cls._instance.default_policy = "allow"
        return cls._instance

    def get_default_policy(self):
        return self.default_policy

from abc import ABC, abstractmethod

class FirewallStrategy(ABC):
    @abstractmethod
    def filter(self, packet: dict) -> bool:
        pass

class IPFilter(FirewallStrategy):
    def __init__(self):
        self.whitelist = set()
        self.blacklist = set()

    def add_to_whitelist(self, ip):
        self.whitelist.add(ip)

    def add_to_blacklist(self, ip):
        self.blacklist.add(ip)

    def filter(self, packet: dict) -> bool:
        ip = packet.get("ip")
        if ip in self.blacklist:
            return False
        if self.whitelist and ip not in self.whitelist:
            return False
        return True

class PortFilter(FirewallStrategy):
    def __init__(self):
        self.allowed_ports = set()

    def allow_port(self, port):
        self.allowed_ports.add(port)

    def filter(self, packet: dict) -> bool:
        port = packet.get("port")
        if self.allowed_ports and port not in self.allowed_ports:
            return False
        return True

class ProtocolFilter(FirewallStrategy):
    def __init__(self):
        self.allowed_protocols = set()

    def allow_protocol(self, protocol):
        self.allowed_protocols.add(protocol)

    def filter(self, packet: dict) -> bool:
        protocol = packet.get("protocol")
        if self.allowed_protocols and protocol not in self.allowed_protocols:
            return False
        return True

class StrategyFactory:
    @staticmethod
    def get_strategy(strategy_type: str):
        if strategy_type == "ip_filter":
            return IPFilter()
        elif strategy_type == "port_filter":
            return PortFilter()
        elif strategy_type == "protocol_filter":
            return ProtocolFilter()
        else:
            raise ValueError(f"Unknown strategy type: {strategy_type}")

settings = Settings()
default_policy = settings.get_default_policy()

ip_filter = StrategyFactory.get_strategy("ip_filter")
port_filter = StrategyFactory.get_strategy("port_filter")
protocol_filter = StrategyFactory.get_strategy("protocol_filter")

ip_filter.add_to_whitelist("192.168.1.1")
ip_filter.add_to_blacklist("10.0.0.1")

port_filter.allow_port(80)
port_filter.allow_port(443)

protocol_filter.allow_protocol("TCP")
protocol_filter.allow_protocol("UDP")

allowed_protocols = {"TCP", "UDP"}

def is_valid_ip(ip):
    pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    return pattern.match(ip) is not None

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/check', methods=['POST'])
def check_packet():
    data = request.json
    ip = data.get('ip')
    port = data.get('port')
    protocol = data.get('protocol')

    errors = []

    if not is_valid_ip(ip):
        errors.append("Invalid IP format. Please enter a valid IP address (e.g., 192.168.1.1).")

    try:
        port = int(port)
    except ValueError:
        errors.append("Invalid port number. Please enter a numeric port value.")

    if protocol not in allowed_protocols:
        errors.append(f"Invalid protocol. Please enter a valid protocol (e.g., {', '.join(allowed_protocols)}).")

    if errors:
        return jsonify({"message": " | ".join(errors)})

    packet = {
        "ip": ip,
        "port": port,
        "protocol": protocol
    }

    if ip_filter.filter(packet) and port_filter.filter(packet) and protocol_filter.filter(packet):
        return jsonify({"message": "Packet allowed"})
    else:
        return jsonify({"message": "Packet denied"})

if __name__ == "__main__":
    app.run(debug=True)
