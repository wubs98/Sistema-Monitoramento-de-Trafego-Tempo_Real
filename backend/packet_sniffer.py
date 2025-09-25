# backend/packet_sniffer.py
"""
Capturador de Pacotes de Rede
Monitora o tráfego de e para um servidor específico
"""

import time
from scapy.all import sniff, IP, TCP, UDP, ICMP
from scapy.config import conf
import logging
from typing import List, Dict, Any

# Configuração de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("packet_sniffer")

class PacketSniffer:
    """
    Classe para captura e análise de pacotes de rede
    """
    
    def __init__(self, server_ip: str, interface: str = None):
        """
        Inicializa o capturador de pacotes
        
        Args:
            server_ip: IP do servidor a ser monitorado
            interface: Interface de rede (None para automático)
        """
        self.server_ip = server_ip
        self.interface = interface
        self.packet_buffer = []
        self.is_capturing = False
        
        logger.info(f"PacketSniffer inicializado para servidor: {server_ip}")
        logger.info(f"Interface: {interface or 'Automática'}")
    
    def packet_handler(self, packet) -> None:
        """
        Processa cada pacote capturado
        """
        try:
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                
                # Verifica se o pacote é relacionado ao servidor
                if ip_layer.src == self.server_ip or ip_layer.dst == self.server_ip:
                    packet_info = self._extract_packet_info(packet)
                    self.packet_buffer.append(packet_info)
                    
                    # Log a cada 10 pacotes para não poluir
                    if len(self.packet_buffer) % 10 == 0:
                        logger.info(f"Pacotes capturados: {len(self.packet_buffer)}")
                        
        except Exception as e:
            logger.error(f"Erro ao processar pacote: {e}")
    
    def _extract_packet_info(self, packet) -> Dict[str, Any]:
        """
        Extrai informações relevantes do pacote
        """
        ip_layer = packet[IP]
        
        # Determina direção
        if ip_layer.src == self.server_ip:
            direction = "OUT"
            client_ip = ip_layer.dst
        else:
            direction = "IN" 
            client_ip = ip_layer.src
        
        # Informações básicas
        packet_info = {
            'timestamp': time.time(),
            'direction': direction,
            'client_ip': client_ip,
            'server_ip': self.server_ip,
            'protocol': 'IP',
            'size': len(packet),
            'src_ip': ip_layer.src,
            'dst_ip': ip_layer.dst
        }
        
        # Detalhes específicos por protocolo
        if packet.haslayer(TCP):
            packet_info.update({
                'protocol': 'TCP',
                'src_port': packet[TCP].sport,
                'dst_port': packet[TCP].dport,
                'flags': str(packet[TCP].flags)
            })
        elif packet.haslayer(UDP):
            packet_info.update({
                'protocol': 'UDP', 
                'src_port': packet[UDP].sport,
                'dst_port': packet[UDP].dport
            })
        elif packet.haslayer(ICMP):
            packet_info.update({
                'protocol': 'ICMP',
                'type': packet[ICMP].type,
                'code': packet[ICMP].code
            })
        
        return packet_info
    
    def start_capture(self, duration: int = 30) -> List[Dict[str, Any]]:
        """
        Inicia a captura de pacotes por um período
        
        Args:
            duration: Duração em segundos
            
        Returns:
            Lista de pacotes capturados
        """
        logger.info(f"Iniciando captura por {duration} segundos...")
        self.packet_buffer.clear()
        self.is_capturing = True
        
        try:
            # Captura pacotes com filtro para IP do servidor
            sniff(
                filter=f"host {self.server_ip}",
                prn=self.packet_handler,
                timeout=duration,
                iface=self.interface,
                store=False  # Não armazena pacotes completos, só processa
            )
            
        except Exception as e:
            logger.error(f"Erro durante captura: {e}")
        finally:
            self.is_capturing = False
            logger.info(f"Captura finalizada. {len(self.packet_buffer)} pacotes capturados.")
        
        return self.packet_buffer.copy()
    
    def get_buffer_stats(self) -> Dict[str, Any]:
        """
        Retorna estatísticas do buffer atual
        """
        if not self.packet_buffer:
            return {'total_packets': 0}
        
        in_packets = [p for p in self.packet_buffer if p['direction'] == 'IN']
        out_packets = [p for p in self.packet_buffer if p['direction'] == 'OUT']
        
        return {
            'total_packets': len(self.packet_buffer),
            'in_packets': len(in_packets),
            'out_packets': len(out_packets),
            'total_bytes': sum(p['size'] for p in self.packet_buffer)
        }

# Função de teste
def test_sniffer():
    """Testa o capturador de pacotes"""
    print("🧪 Testando PacketSniffer...")
    
    # ALTERE ESTE IP PARA O SEU SERVIDOR!
    sniffer = PacketSniffer(server_ip="192.168.0.10", interface="Ethernet")
    
    print("Capturando pacotes por 10 segundos...")
    print("Gere algum tráfego no seu servidor (acesse HTTP/FTP)")
    
    packets = sniffer.start_capture(duration=10)
    stats = sniffer.get_buffer_stats()
    
    print(f"\n📊 Estatísticas da captura:")
    print(f"Total de pacotes: {stats['total_packets']}")
    print(f"Pacotes de entrada: {stats['in_packets']}")
    print(f"Pacotes de saída: {stats['out_packets']}")
    print(f"Bytes totais: {stats['total_bytes']}")
    
    if packets:
        print(f"\n📦 Primeiro pacote capturado:")
        for key, value in list(packets[0].items())[:6]:
            print(f"  {key}: {value}")

if __name__ == "__main__":
    test_sniffer()