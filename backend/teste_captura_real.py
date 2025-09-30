# teste_captura_real.py
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from packet_sniffer import PacketSniffer

print("🎯 CAPTURA DE PACOTES REAIS - 15 SEGUNDOS")
print("=" * 50)

sniffer = PacketSniffer(server_ip="192.168.0.10", interface="Ethernet 2")

print("📡 GERE TRÁFEGO REAL AGORA:")
print("   - Acesse: http://192.168.0.10:8080")
print("   - Execute: ping 192.168.0.10") 
print("   - Ou qualquer tráfego para seu servidor")
print()

packets = sniffer.start_capture(duration=15)

if packets:
    print(f"✅ CAPTURADOS {len(packets)} PACOTES REAIS!")
    
    # Filtra IPs válidos (remove multicast)
    valid_ips = [p for p in packets if not p['client_ip'].startswith('224.') and p['client_ip'] != '192.168.0.10']
    
    print(f"📊 PACOTES VÁLIDOS: {len(valid_ips)}")
    
    for i, pkt in enumerate(valid_ips[:5]):  # Mostra os 5 primeiros válidos
        print(f"   {i+1}. {pkt['client_ip']} -> {pkt['protocol']} ({pkt['size']} bytes)")
        
else:
    print("❌ NENHUM PACOTE CAPTURADO")
    print("   Verifique se está gerando tráfego para 192.168.0.10")