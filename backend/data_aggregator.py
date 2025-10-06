# backend/data_aggregator.py
"""
Sistema de Agregação de Dados de Tráfego COM DRILL DOWN
Versão com tolerância a erros e sniffer dummy para testes locais.
"""

import time
import os
import pandas as pd
from typing import List, Dict, Any
import logging
from datetime import datetime, timedelta
import json
import sys

# 🔧 CORREÇÃO DO IMPORT
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# tenta importar o PacketSniffer e as configs; se falhar, usa defaults/test doubles
try:
    from backend.packet_sniffer import PacketSniffer
except Exception:
    PacketSniffer = None

try:
    from config import SERVER_IP, CAPTURE_INTERFACE, TIME_WINDOW, OUTPUT_TRAFFIC_CSV, OUTPUT_PROTOCOL_CSV
except Exception:
    # valores padrão para teste local
    SERVER_IP = "127.0.0.1"
    CAPTURE_INTERFACE = None
    TIME_WINDOW = 5
    OUTPUT_TRAFFIC_CSV = "data/window_aggregates_today.csv"
    OUTPUT_PROTOCOL_CSV = "data/protocol_details_today.csv"

# import persistence
from backend.persistence import Persistence

# Configuração de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("data_aggregator")


class DummyPacketSniffer:
    """Gerador de pacotes fake para testes locais."""
    def __init__(self, server_ip, interface=None):
        self.server_ip = server_ip
        self.interface = interface

    def start_capture(self, duration=5):
        # retorna lista de dicionários simulando pacotes
        logger.info("🔬 Usando DummyPacketSniffer (modo de teste).")
        fake = [
            {"timestamp": datetime.utcnow().isoformat() + "Z", "client_ip": "192.168.0.10", "server_ip": self.server_ip, "direction": "IN", "protocol": "HTTP", "size": 500, "src_port": 54321, "dst_port": 80},
            {"timestamp": datetime.utcnow().isoformat() + "Z", "client_ip": "192.168.0.10", "server_ip": self.server_ip, "direction": "OUT", "protocol": "HTTP", "size": 1200, "src_port": 80, "dst_port": 54321},
            {"timestamp": datetime.utcnow().isoformat() + "Z", "client_ip": "192.168.0.15", "server_ip": self.server_ip, "direction": "IN", "protocol": "DNS", "size": 60, "src_port": 54322, "dst_port": 53},
            {"timestamp": datetime.utcnow().isoformat() + "Z", "client_ip": "192.168.0.20", "server_ip": self.server_ip, "direction": "IN", "protocol": "TCP", "size": 1500, "src_port": 54323, "dst_port": 443},
            {"timestamp": datetime.utcnow().isoformat() + "Z", "client_ip": "192.168.0.20", "server_ip": self.server_ip, "direction": "OUT", "protocol": "TCP", "size": 800, "src_port": 443, "dst_port": 54323},
        ]
        time.sleep(min(duration, 2))
        return fake


class TrafficAggregator:
    """
    Agrega dados de tráfego em janelas de tempo COM DRILL DOWN
    """

    def __init__(self, server_ip: str, interface: str = None, time_window: int = 5, db_path: str = "data/traffic.db", csv_dir: str = "data"):
        self.server_ip = server_ip
        self.interface = interface
        self.time_window = time_window

        if PacketSniffer:
            try:
                self.sniffer = PacketSniffer(server_ip, interface)
                logger.info("✅ Usando PacketSniffer real")
            except Exception as e:
                logger.warning(f"⚠️ Falha ao instanciar PacketSniffer real: {e} — usando DummyPacketSniffer.")
                self.sniffer = DummyPacketSniffer(server_ip, interface)
        else:
            self.sniffer = DummyPacketSniffer(server_ip, interface)
            logger.info("✅ Usando DummyPacketSniffer para testes")

        self.persistence = Persistence(db_path, csv_dir)

        logger.info(f"✅ TrafficAggregator COM DRILL DOWN inicializado")
        logger.info(f"   Janela de tempo: {time_window}s")
        logger.info(f"   Servidor: {server_ip}")

    def _identify_service(self, protocol: str, port: int) -> str:
        service_map = {80:'HTTP',443:'HTTPS',21:'FTP',22:'SSH',53:'DNS',25:'SMTP',110:'POP3',143:'IMAP'}
        if protocol in ['TCP','UDP'] and port in service_map:
            return service_map[port]
        elif protocol == 'ICMP':
            return 'ICMP'
        else:
            return f'{protocol}_Other'

    def aggregate_traffic(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        aggregation = {}
        if not packets:
            return []

        protocol_details = []

        for packet in packets:
            client_ip = packet.get('client_ip') or packet.get('src_ip') or "unknown"
            direction = (packet.get('direction') or packet.get('dir') or "IN").upper()
            protocol = packet.get('protocol') or packet.get('proto') or "UNKNOWN"
            src_port = int(packet.get('src_port') or 0)
            dst_port = int(packet.get('dst_port') or 0)
            try:
                size = int(packet.get('size',0))
            except (ValueError, TypeError):
                size = 0

            # timestamp ISO
            ts = packet.get('timestamp')
            if isinstance(ts,(float,int)):
                timestamp_iso = datetime.utcfromtimestamp(float(ts)).strftime("%Y-%m-%dT%H:%M:%SZ")
            else:
                try:
                    if not isinstance(ts,str) or 'T' not in ts:
                        timestamp_iso = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
                    else:
                        timestamp_iso = ts
                except Exception:
                    timestamp_iso = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

            service = self._identify_service(protocol, dst_port if direction=='IN' else src_port)

            protocol_details.append({
                'timestamp': timestamp_iso,
                'client_ip': client_ip,
                'direction': direction,
                'protocol': protocol,
                'service': service,
                'src_port': src_port,
                'dst_port': dst_port,
                'size': size,
                'flags': packet.get('flags',''),
                'server_ip': self.server_ip
            })

            if client_ip not in aggregation:
                aggregation[client_ip] = {'client_ip':client_ip,'traffic_in':0,'traffic_out':0,'protocols':{},'services':{},'ports':{}}

            if direction=='IN':
                aggregation[client_ip]['traffic_in'] += size
            else:
                aggregation[client_ip]['traffic_out'] += size

            aggregation[client_ip]['protocols'][protocol] = aggregation[client_ip]['protocols'].get(protocol,0)+size
            aggregation[client_ip]['services'][service] = aggregation[client_ip]['services'].get(service,0)+size

            if protocol in ['TCP','UDP']:
                port_key = f"{dst_port if direction=='IN' else src_port}"
                aggregation[client_ip]['ports'][port_key] = aggregation[client_ip]['ports'].get(port_key,0)+size

        # resultado final
        result = []
        for client_ip, data in aggregation.items():
            result.append({
                'window_start': None,
                'window_end': None,
                'client_ip': client_ip,
                'traffic_in': data['traffic_in'],
                'traffic_out': data['traffic_out'],
                'total_traffic': data['traffic_in']+data['traffic_out'],
                'protocols_json': json.dumps(data['protocols']),
                'services_json': json.dumps(data['services']),
                'ports_json': json.dumps(data['ports'])
            })
        return result, protocol_details

    def run_aggregation_cycle(self) -> None:
        logger.info(f"🔄 Iniciando ciclo de agregação ({self.time_window}s)")
        window_end = datetime.utcnow()
        window_start = window_end - timedelta(seconds=self.time_window)
        try:
            packets = self.sniffer.start_capture(duration=self.time_window)
            if hasattr(packets,"__iter__") and not isinstance(packets,list):
                packets = list(packets)
        except Exception as e:
            logger.error(f"❌ Erro na captura de pacotes: {e}")
            packets = []

        if packets:
            aggregated_data, protocol_details = self.aggregate_traffic(packets)
            for row in aggregated_data:
                row['window_start'] = window_start.strftime("%Y-%m-%dT%H:%M:%SZ")
                row['window_end'] = window_end.strftime("%Y-%m-%dT%H:%M:%SZ")

            # Persistência e export CSV
            try:
                self.persistence.insert_protocol_details(protocol_details)
                self.persistence.insert_window_aggregates(aggregated_data)
                date_tag = window_start.strftime("%Y%m%d")
                self.persistence.export_csv_for_date(date_tag)
            except Exception as e:
                logger.error(f"❌ Erro ao persistir/exportar dados: {e}")

            total_traffic = sum(d['traffic_in']+d['traffic_out'] for d in aggregated_data)
            unique_protocols = set()
            for data in aggregated_data:
                try:
                    protocols = json.loads(data['protocols_json'])
                    unique_protocols.update(protocols.keys())
                except Exception:
                    pass
            logger.info(f"📊 Ciclo completo: {len(aggregated_data)} clientes, {total_traffic} bytes, {len(unique_protocols)} protocolos")
        else:
            logger.info("📊 Nenhum pacote capturado neste ciclo")

    def continuous_monitoring(self, max_cycles:int=None):
        logger.info(f"🚀 Iniciando monitoramento contínuo...")
        cycle_count = 0
        try:
            while True:
                if max_cycles and cycle_count>=max_cycles:
                    break
                self.run_aggregation_cycle()
                cycle_count+=1
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("⏹️ Monitoramento interrompido pelo usuário")
        except Exception as e:
            logger.error(f"❌ Erro no monitoramento: {e}")


def test_drill_down():
    print("🧪 Testando TrafficAggregator COM DRILL DOWN...")
    aggregator = TrafficAggregator(server_ip=SERVER_IP, interface=CAPTURE_INTERFACE, time_window=2, db_path="data/traffic.db", csv_dir="data")
    print("Executando 2 ciclos de agregação com drill down...")
    aggregator.continuous_monitoring(max_cycles=2)


if __name__=="__main__":
    test_drill_down()
