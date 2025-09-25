try:
    import scapy.all as scapy
    import pandas as pd
    print("✅ Scapy e Pandas instalados com sucesso!")
    print(f"Versão Scapy: {scapy.__version__}")
    print(f"Versão Pandas: {pd.__version__}")
except ImportError as e:
    print(f"❌ Erro: {e}")