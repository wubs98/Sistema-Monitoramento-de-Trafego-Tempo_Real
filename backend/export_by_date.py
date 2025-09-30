# backend/export_by_date.py
from persistence import Persistence
from datetime import datetime
import sys

# opcional: passe a data como argumento no formato YYYYMMDD, ex: 20250929
date_tag = sys.argv[1] if len(sys.argv) > 1 else None

p = Persistence(db_path="data/traffic.db", csv_dir="data")
p.export_csv_for_date(date_tag)
print("Export attempted for date:", date_tag or datetime.utcnow().strftime("%Y%m%d"))
