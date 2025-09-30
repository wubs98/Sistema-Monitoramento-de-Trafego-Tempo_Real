# teste_ip_correto.py
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from packet_sniffer import PacketSniffer

print("🎯 TESTE COM IP CORRETO: 192.168.0.4")
print("=" * 45)

sniffer = PacketSniffer(server_ip="192.168.0.4", interface="Ethernet 2")

print("📡 EXECUTE EM OUTRO TERMINAL:")
print("   ping -t 192.168.0.4")
print("\nCapturando por 10 segundos...")

packets = sniffer.start_capture(duration=10)

if packets:
    print(f"✅ CAPTURADOS {len(packets)} PACOTES!")
    
    # Mostra estatísticas
    unique_ips = set(p['client_ip'] for p in packets)
    print(f"📊 IPs ÚNICOS: {list(unique_ips)}")
    
    # Por protocolo
    protocols = {}
    for p in packets:
        proto = p.get('protocol', 'UNKNOWN')
        protocols[proto] = protocols.get(proto, 0) + 1
    
    print(f"📡 PROTOCOLOS: {protocols}")
    
    # Mostra alguns pacotes
    print(f"\n📦 PRIMEIROS 3 PACOTES:")
    for i, pkt in enumerate(packets[:3]):
        print(f"   {i+1}. {pkt['client_ip']} -> {pkt['protocol']} ({pkt['size']} bytes)")
    
else:
    print("❌ NENHUM PACOTE CAPTURADO")