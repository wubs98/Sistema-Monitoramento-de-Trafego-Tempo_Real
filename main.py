# main.py
"""
Sistema Principal de Monitoramento de Tráfego
Integra captura, agregação e geração de dados para o dashboard
"""

import time
import logging
from datetime import datetime
import signal
import sys

from backend.packet_sniffer import PacketSniffer
from backend.data_aggregator import TrafficAggregator
from backend.config import SERVER_IP, CAPTURE_INTERFACE, TIME_WINDOW, OUTPUT_TRAFFIC_CSV, validate_config

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('data/system.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("main")

class TrafficMonitor:
    """
    Classe principal do sistema de monitoramento
    """
    
    def __init__(self):
        self.running = False
        self.aggregator = None
        
        # Configura tratamento de sinais para graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def signal_handler(self, signum, frame):
        """Manipula sinais de interrupção"""
        logger.info(f"Recebido sinal {signum}. Encerrando...")
        self.running = False
    
    def initialize_system(self):
        """Inicializa e valida o sistema"""
        logger.info("🚀 Inicializando Sistema de Monitoramento de Tráfego")
        
        # Valida configurações
        config_status = validate_config()
        
        if not config_status['valid']:
            logger.error("❌ Erros de configuração encontrados:")
            for error in config_status['errors']:
                logger.error(f"   - {error}")
            return False
        
        if config_status['warnings']:
            logger.warning("⚠️  Avisos de configuração:")
            for warning in config_status['warnings']:
                logger.warning(f"   - {warning}")
        
        # Cria agregador
        self.aggregator = TrafficAggregator(
            server_ip=SERVER_IP,
            interface=CAPTURE_INTERFACE,
            time_window=TIME_WINDOW
        )
        
        logger.info("✅ Sistema inicializado com sucesso")
        logger.info(f"   Servidor: {SERVER_IP}")
        logger.info(f"   Interface: {CAPTURE_INTERFACE}")
        logger.info(f"   Janela de tempo: {TIME_WINDOW}s")
        logger.info(f"   Arquivo de dados: {OUTPUT_TRAFFIC_CSV}")
        
        return True
    
    def run(self):
        """Executa o monitoramento principal"""
        if not self.initialize_system():
            logger.error("❌ Falha na inicialização. Encerrando.")
            return
        
        self.running = True
        cycle_count = 0
        start_time = time.time()
        
        logger.info("📊 Iniciando monitoramento contínuo...")
        logger.info("Pressione Ctrl+C para parar")
        
        try:
            while self.running:
                cycle_start = time.time()
                cycle_count += 1
                
                logger.info(f"--- Ciclo #{cycle_count} ---")
                
                # Executa ciclo de agregação
                self.aggregator.run_aggregation_cycle()
                
                # Log de estatísticas a cada 5 ciclos
                if cycle_count % 5 == 0:
                    elapsed = time.time() - start_time
                    logger.info(f"📈 Estatísticas: {cycle_count} ciclos em {elapsed:.1f}s")
                
                # Pequena pausa entre ciclos
                time.sleep(1)
                
        except Exception as e:
            logger.error(f"❌ Erro durante execução: {e}")
        finally:
            self.shutdown()
    
    def shutdown(self):
        """Encerra o sistema gracefulmente"""
        logger.info("🛑 Encerrando sistema...")
        self.running = False
        
        # Estatísticas finais
        try:
            import pandas as pd
            df = pd.read_csv(OUTPUT_TRAFFIC_CSV)
            logger.info(f"📊 Dados finais: {len(df)} registros capturados")
            logger.info(f"👥 Clientes únicos: {df['client_ip'].nunique()}")
        except:
            pass
        
        logger.info("✅ Sistema encerrado")

def main():
    """Função principal"""
    print("=" * 60)
    print("🌐 SISTEMA DE MONITORAMENTO DE TRÁFEGO EM TEMPO REAL")
    print("=" * 60)
    
    monitor = TrafficMonitor()
    monitor.run()

if __name__ == "__main__":
    main()