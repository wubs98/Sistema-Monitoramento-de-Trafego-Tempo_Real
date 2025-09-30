import sqlite3
import pandas as pd
from datetime import datetime
import os

DB_PATH = "data/traffic.db"
CSV_DIR = "data"

os.makedirs(CSV_DIR, exist_ok=True)

date_tag = datetime.utcnow().strftime("%Y%m%d")  # YYYYMMDD

# Conecta ao SQLite
conn = sqlite3.connect(DB_PATH)

# 1️⃣ Exporta detalhes por protocolo (protocol_details)
df_protocol = pd.read_sql_query("SELECT * FROM protocol_details", conn)
csv_protocol = os.path.join(CSV_DIR, f"protocol_details_{date_tag}.csv")
df_protocol.to_csv(csv_protocol, index=False, encoding="utf-8-sig")
print(f"✅ protocol_details exportado para {csv_protocol}, {len(df_protocol)} linhas")

# 2️⃣ Exporta agregados por janela de tempo (window_aggregates)
df_window = pd.read_sql_query("SELECT * FROM window_aggregates", conn)
csv_window = os.path.join(CSV_DIR, f"window_aggregates_{date_tag}.csv")
df_window.to_csv(csv_window, index=False, encoding="utf-8-sig")
print(f"✅ window_aggregates exportado para {csv_window}, {len(df_window)} linhas")

conn.close()
