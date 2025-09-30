# backend/persistence.py
import os
import sqlite3
import csv
import json
from datetime import date, datetime
from typing import List, Dict, Any

DB_DEFAULT = "data/traffic.db"
CSV_DIR_DEFAULT = "data"
ENCODING = "utf-8-sig"  # BOM for Excel on Windows


class Persistence:
    def __init__(self, db_path: str = DB_DEFAULT, csv_dir: str = CSV_DIR_DEFAULT):
        self.db_path = db_path
        self.csv_dir = csv_dir
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        os.makedirs(self.csv_dir, exist_ok=True)
        self._ensure_db()

    def _connect(self):
        return sqlite3.connect(self.db_path, timeout=30)

    def _ensure_db(self):
        conn = self._connect()
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS protocol_details (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            window_start TEXT,
            client_ip TEXT,
            server_ip TEXT,
            direction TEXT,
            protocol TEXT,
            service TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            size INTEGER,
            flags TEXT
        )""")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_pd_client ON protocol_details(client_ip)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_pd_window ON protocol_details(window_start)")

        cur.execute("""
        CREATE TABLE IF NOT EXISTS window_aggregates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            window_start TEXT,
            window_end TEXT,
            client_ip TEXT,
            traffic_in INTEGER,
            traffic_out INTEGER,
            total_traffic INTEGER,
            protocols_json TEXT,
            services_json TEXT,
            ports_json TEXT
        )""")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_wa_window ON window_aggregates(window_start)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_wa_client ON window_aggregates(client_ip)")

        conn.commit()
        conn.close()

    def insert_protocol_details(self, details: List[Dict[str, Any]]):
        """
        details: list of dicts with keys:
          timestamp, window_start, client_ip, server_ip, direction, protocol,
          service, src_port, dst_port, size, flags
        """
        if not details:
            return
        conn = self._connect()
        cur = conn.cursor()
        try:
            rows = [
                (
                    d.get('timestamp'),
                    d.get('window_start'),
                    d.get('client_ip'),
                    d.get('server_ip'),
                    d.get('direction'),
                    d.get('protocol'),
                    d.get('service'),
                    int(d.get('src_port') or 0),
                    int(d.get('dst_port') or 0),
                    int(d.get('size') or 0),
                    d.get('flags') or ""
                )
                for d in details
            ]
            cur.executemany("""
                INSERT INTO protocol_details
                (timestamp, window_start, client_ip, server_ip, direction, protocol, service, src_port, dst_port, size, flags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, rows)
            conn.commit()
        finally:
            conn.close()

    def insert_window_aggregates(self, rows: List[Dict[str, Any]]):
        """
        rows: list of dicts with keys:
          window_start, window_end, client_ip, traffic_in, traffic_out, total_traffic,
          protocols_json, services_json, ports_json
        """
        if not rows:
            return
        conn = self._connect()
        cur = conn.cursor()
        try:
            tup_rows = [
                (
                    r.get('window_start'),
                    r.get('window_end'),
                    r.get('client_ip'),
                    int(r.get('traffic_in') or 0),
                    int(r.get('traffic_out') or 0),
                    int(r.get('total_traffic') or 0),
                    r.get('protocols_json') or "{}",
                    r.get('services_json') or "{}",
                    r.get('ports_json') or "{}"
                )
                for r in rows
            ]
            cur.executemany("""
                INSERT INTO window_aggregates
                (window_start, window_end, client_ip, traffic_in, traffic_out, total_traffic, protocols_json, services_json, ports_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, tup_rows)
            conn.commit()
        finally:
            conn.close()

    # ---------- CSV helpers ----------
    def _atomic_write_csv(self, path: str, fieldnames: List[str], rows: List[Dict[str, Any]]):
        """Write CSV atomically using a tmp file and os.replace"""
        tmp = path + ".tmp"
        dirn = os.path.dirname(path) or "."
        os.makedirs(dirn, exist_ok=True)
        with open(tmp, "w", newline="", encoding=ENCODING) as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

    def _append_csv(self, path: str, rows: List[Dict[str, Any]]):
        """Append rows to CSV in a safe way (create header if not exists)."""
        if not rows:
            return
        file_exists = os.path.exists(path)
        fieldnames = list(rows[0].keys())
        tmp = None
        if not file_exists:
            # write new file via atomic write
            self._atomic_write_csv(path, fieldnames, rows)
            return
        # append (not atomic for append, but simpler); for single-writer scenarios it's acceptable
        with open(path, "a", newline="", encoding=ENCODING) as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writerows(rows)

    def export_csv_for_date(self, date_tag: str = None):
        """
        Exports CSVs for the provided date_tag (YYYYMMDD). If None uses today's date (UTC).
        It will dump:
          - protocol_details_YYYYMMDD.csv (rows filtered by window_start date)
          - window_aggregates_YYYYMMDD.csv
        """
        if date_tag is None:
            date_tag = datetime.utcnow().strftime("%Y%m%d")
        # compute ISO date for comparison: we assume window_start like 'YYYY-MM-DDTHH:MM:SSZ'
        iso_prefix = f"{date_tag[:4]}-{date_tag[4:6]}-{date_tag[6:8]}"

        conn = self._connect()
        try:
            cur = conn.cursor()
            q_details = """
                SELECT timestamp, window_start, client_ip, server_ip, direction, protocol, service, src_port, dst_port, size, flags
                FROM protocol_details
                WHERE window_start LIKE ?
                ORDER BY window_start, timestamp
            """
            cur.execute(q_details, (f"{iso_prefix}%",))
            cols = [c[0] for c in cur.description]
            rows = [dict(zip(cols, r)) for r in cur.fetchall()]
            details_path = os.path.join(self.csv_dir, f"protocol_details_{date_tag}.csv")
            if rows:
                self._atomic_write_csv(details_path, cols, rows)
            else:
                # ensure file exists (empty with header) so Excel power query finds consistent schema
                self._atomic_write_csv(details_path, cols, [])

            q_agg = """
                SELECT window_start, window_end, client_ip, traffic_in, traffic_out, total_traffic, protocols_json, services_json, ports_json
                FROM window_aggregates
                WHERE window_start LIKE ?
                ORDER BY window_start
            """
            cur.execute(q_agg, (f"{iso_prefix}%",))
            cols_a = [c[0] for c in cur.description]
            rows_a = [dict(zip(cols_a, r)) for r in cur.fetchall()]
            agg_path = os.path.join(self.csv_dir, f"window_aggregates_{date_tag}.csv")
            if rows_a:
                # ensure protocols_json etc are strings in CSV
                for r in rows_a:
                    # keep as JSON strings
                    r['protocols_json'] = r.get('protocols_json') or "{}"
                    r['services_json'] = r.get('services_json') or "{}"
                    r['ports_json'] = r.get('ports_json') or "{}"
                self._atomic_write_csv(agg_path, cols_a, rows_a)
            else:
                self._atomic_write_csv(agg_path, cols_a, [])
        finally:
            conn.close()
