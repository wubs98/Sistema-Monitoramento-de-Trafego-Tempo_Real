import os
from typing import Dict, Any

SERVER_IP = "192.168.0.10"

CAPTURE_INTERFACE = "Ethernet"  # Altere para sua interface

# Porta espelhada (mirror port) - se aplicável
MIRROR_PORT = None  

TIME_WINDOW = 5

# Tamanho máximo do buffer de pacotes em memória
MAX_BUFFER_SIZE = 10000

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


OUTPUT_TRAFFIC_CSV = os.path.join(BASE_DIR, "data", "traffic_data.csv")
OUTPUT_PROTOCOL_CSV = os.path.join(BASE_DIR, "data", "protocol_data.csv")
LOG_FILE = os.path.join(BASE_DIR, "data", "system.log")

MONITORED_PROTOCOLS = {
    "TCP": 6,
    "UDP": 17, 
    "ICMP": 1,
    "HTTP": 80,
    "HTTPS": 443,
    "FTP": 21,
    "SSH": 22,
    "DNS": 53
}

COMMON_PORTS = {
    80: "HTTP",
    443: "HTTPS", 
    21: "FTP",
    22: "SSH",
    53: "DNS",
    25: "SMTP",
    110: "POP3",
    143: "IMAP"
}


IGNORED_IPS = [
    "127.0.0.1",      
    "255.255.255.255", 
    "224.0.0.0",      
    "fe80::",         
]


CAPTURE_TIMEOUT = 30

PROMISCUOUS_MODE = False


SNAPLEN = 65535

# =============================================================================
# CONFIGURAÇÕES DO DASHBOARD
# =============================================================================

MAX_DISPLAY_CLIENTS = 20

COLORS = {
    "tcp": "#FF6B6B",
    "udp": "#4ECDC4", 
    "icmp": "#45B7D1",
    "http": "#96CEB4",
    "https": "#FECA57",
    "ftp": "#FF9FF3",
    "other": "#54A0FF"
}

# =============================================================================
# VALIDAÇÕES E FUNÇÕES AUXILIARES
# =============================================================================

def validate_config() -> Dict[str, Any]:
    """
    Valida as configurações e retorna status
    """
    errors = []
    warnings = []
    
    # Validação do IP do servidor
    if not SERVER_IP or SERVER_IP == "192.168.1.100":
        warnings.append("SERVER_IP está com valor padrão - altere para o IP real do seu servidor")
    
    # Validação do diretório de dados
    data_dir = os.path.join(BASE_DIR, "data")
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)
        warnings.append(f"Diretório 'data' criado em: {data_dir}")
    
    # Validação da janela de tempo
    if TIME_WINDOW < 1 or TIME_WINDOW > 60:
        errors.append("TIME_WINDOW deve estar entre 1 e 60 segundos")
    
    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings
    }

def get_config_summary() -> Dict[str, Any]:
    """
    Retorna um resumo das configurações
    """
    return {
        "server_ip": SERVER_IP,
        "capture_interface": CAPTURE_INTERFACE,
        "time_window": TIME_WINDOW,
        "output_files": {
            "traffic_data": OUTPUT_TRAFFIC_CSV,
            "protocol_data": OUTPUT_PROTOCOL_CSV
        },
        "monitored_protocols": len(MONITORED_PROTOCOLS),
        "validation": validate_config()
    }

# =============================================================================
# EXECUÇÃO DE TESTE (quando o arquivo é executado diretamente)
# =============================================================================

if __name__ == "__main__":
    """
    Teste das configurações - execute este arquivo para validar
    """
    print("=== CONFIGURAÇÕES DO SISTEMA ===")
    summary = get_config_summary()
    
    for key, value in summary.items():
        if key != "validation":
            print(f"{key.upper()}: {value}")
    
    print("\n=== VALIDAÇÃO ===")
    validation = summary["validation"]
    
    if validation["errors"]:
        print("❌ ERROS ENCONTRADOS:")
        for error in validation["errors"]:
            print(f"  - {error}")
    else:
        print("✅ Configurações válidas")
    
    if validation["warnings"]:
        print("⚠️  AVISOS:")
        for warning in validation["warnings"]:
            print(f"  - {warning}")
    
    print(f"\n📁 Arquivo de dados: {OUTPUT_TRAFFIC_CSV}")