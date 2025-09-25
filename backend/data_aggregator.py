# backend/data_aggregator.py
"""
Sistema de Agregação de Dados de Tráfego
Agrupa pacotes em janelas de tempo e gera relatórios para o dashboard
"""

import time
import pandas as pd
from typing import List, Dict, Any
import logging
from datetime import datetime
import json

from backend.packet_sniffer import PacketSniffer
from backend.config import SERVER_IP, CAPTURE_INTERFACE, TIME_WINDOW, OUTPUT_TRAFFIC_CSV

# Configuração de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("data_aggregator")

class TrafficAggregator:
    """
    Agrega dados de tráfego em janelas de tempo
    """
    
    def __init__(self, server_ip: str, interface: str = None, time_window: int = 5):
        self.server_ip = server_ip
        self.interface = interface
        self.time_window = time_window
        self.sniffer = PacketSniffer(server_ip, interface)
        
        # Dados agregados
        self.traffic_data = []
        self.protocol_data = []
        
        logger.info(f"✅ TrafficAggregator inicializado")
        logger.info(f"   Janela de tempo: {time_window}s")
    
    def aggregate_traffic(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Agrupa pacotes por IP do cliente e direção
        """
        aggregation = {}
        
        for packet in packets:
            client_ip = packet['client_ip']
            direction = packet['direction']
            protocol = packet['protocol']
            size = packet['size']
            
            if client_ip not in aggregation:
                aggregation[client_ip] = {
                    'client_ip': client_ip,
                    'traffic_in': 0,
                    'traffic_out': 0,
                    'protocols': {}
                }
            
            # Soma tráfego por direção
            if direction == 'IN':
                aggregation[client_ip]['traffic_in'] += size
            else:
                aggregation[client_ip]['traffic_out'] += size
            
            # Contagem por protocolo
            if protocol not in aggregation[client_ip]['protocols']:
                aggregation[client_ip]['protocols'][protocol] = 0
            aggregation[client_ip]['protocols'][protocol] += size
        
        # Converte para formato final
        result = []
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        for client_ip, data in aggregation.items():
            result.append({
                'timestamp': timestamp,
                'client_ip': client_ip,
                'traffic_in': data['traffic_in'],
                'traffic_out': data['traffic_out'],
                'protocols': json.dumps(data['protocols'])  # Salva como JSON para drill-down
            })
        
        return result
    
    def save_to_csv(self, data: List[Dict[str, Any]]) -> None:
        """
        Salva dados agregados em CSV
        """
        if not data:
            return
            
        df = pd.DataFrame(data)
        
        try:
            # Tenta carregar CSV existente e adicionar novos dados
            existing_df = pd.read_csv(OUTPUT_TRAFFIC_CSV)
            df = pd.concat([existing_df, df], ignore_index=True)
        except FileNotFoundError:
            # Primeira execução - cria novo arquivo
            pass
        
        # Salva CSV
        df.to_csv(OUTPUT_TRAFFIC_CSV, index=False)
        logger.info(f"💾 Dados salvos em {OUTPUT_TRAFFIC_CSV} - {len(data)} registros")
    
    def run_aggregation_cycle(self) -> None:
        """
        Executa um ciclo completo de captura e agregação
        """
        logger.info(f"🔄 Iniciando ciclo de agregação ({self.time_window}s)")
        
        # Captura pacotes
        packets = self.sniffer.start_capture(duration=self.time_window)
        
        if packets:
            # Agrega dados
            aggregated_data = self.aggregate_traffic(packets)
            
            # Salva em CSV
            self.save_to_csv(aggregated_data)
            
            # Log estatísticas
            total_traffic = sum(d['traffic_in'] + d['traffic_out'] for d in aggregated_data)
            logger.info(f"📊 Ciclo completo: {len(aggregated_data)} clientes, {total_traffic} bytes")
        else:
            logger.info("📊 Nenhum pacote capturado neste ciclo")
    
    def continuous_monitoring(self, max_cycles: int = None):
        """
        Monitoramento contínuo
        """
        logger.info(f"🚀 Iniciando monitoramento contínuo...")
        cycle_count = 0
        
        try:
            while True:
                if max_cycles and cycle_count >= max_cycles:
                    break
                    
                self.run_aggregation_cycle()
                cycle_count += 1
                
                # Pequena pausa entre ciclos
                time.sleep(1)
                
        except KeyboardInterrupt:
            logger.info("⏹️ Monitoramento interrompido pelo usuário")
        except Exception as e:
            logger.error(f"❌ Erro no monitoramento: {e}")

def test_aggregator():
    """Testa o agregador de dados"""
    print("🧪 Testando TrafficAggregator...")
    
    aggregator = TrafficAggregator(
        server_ip=SERVER_IP,
        interface=CAPTURE_INTERFACE,
        time_window=5  # 5 segundos para teste
    )
    
    print("Executando 2 ciclos de agregação (10 segundos total)...")
    aggregator.continuous_monitoring(max_cycles=2)
    
    # Verifica se o CSV foi criado
    try:
        df = pd.read_csv(OUTPUT_TRAFFIC_CSV)
        print(f"\n✅ CSV criado com sucesso!")
        print(f"📁 Arquivo: {OUTPUT_TRAFFIC_CSV}")
        print(f"📊 Registros: {len(df)}")
        print(f"👥 Clientes únicos: {df['client_ip'].nunique()}")
        
        print("\n📈 Últimos registros:")
        print(df.tail()[['timestamp', 'client_ip', 'traffic_in', 'traffic_out']])
        
    except FileNotFoundError:
        print("❌ CSV não foi criado - verifique as permissões")

if __name__ == "__main__":
    test_aggregator()