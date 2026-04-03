"""
AegisCore — Log Parser Module
Parses and normalizes Linux (CSV), Windows (CBS/CSI TXT), and Mac (BSD Syslog) logs
into a unified DataFrame for AI classification.
"""

import pandas as pd
import re
import os
from datetime import datetime

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")


def parse_linux_logs() -> pd.DataFrame:
    """Parse Linux_2k.log_structured.csv into normalized DataFrame."""
    filepath = os.path.join(DATA_DIR, "Linux_2k.log_structured.csv")
    if not os.path.exists(filepath):
        return pd.DataFrame()

    df = pd.read_csv(filepath)

    records = []
    for _, row in df.iterrows():
        # Build a pseudo-timestamp (original data has Month/Date/Time but no year)
        try:
            month_str = str(row.get("Month", "Jan"))
            day_str = str(row.get("Date", "1")).zfill(2)
            time_str = str(row.get("Time", "00:00:00"))
            timestamp = f"2026-{month_str}-{day_str} {time_str}"
            # Convert month name to number
            dt = datetime.strptime(f"{month_str} {day_str} 2026 {time_str}", "%b %d %Y %H:%M:%S")
            timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            timestamp = "2026-01-01 00:00:00"

        component = str(row.get("Component", "unknown"))
        content = str(row.get("Content", ""))
        level = str(row.get("Level", "info")).lower()
        event_id = str(row.get("EventId", ""))

        records.append({
            "id": int(row.get("LineId", 0)),
            "timestamp": timestamp,
            "source_os": "Linux",
            "component": component,
            "level": level,
            "content": content,
            "event_id": event_id,
            "raw": content,
        })

    return pd.DataFrame(records)


def parse_windows_logs() -> pd.DataFrame:
    """Parse Windows_2k.log.txt (CBS/CSI servicing logs) into normalized DataFrame."""
    filepath = os.path.join(DATA_DIR, "Windows_2k.log.txt")
    if not os.path.exists(filepath):
        return pd.DataFrame()

    # Pattern: 2016-09-28 04:30:30, Info                  CBS    Message...
    pattern = re.compile(
        r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}),\s+'
        r'(\w+)\s+'
        r'(\w+)\s+'
        r'(.+)$'
    )

    records = []
    line_id = 0

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            line_id += 1
            match = pattern.match(line)
            if match:
                timestamp_raw, level, component, content = match.groups()
                # Remap year to 2026 for demo
                timestamp = "2026" + timestamp_raw[4:]
                records.append({
                    "id": 2000 + line_id,
                    "timestamp": timestamp,
                    "source_os": "Windows",
                    "component": component.strip(),
                    "level": level.strip().lower(),
                    "content": content.strip(),
                    "event_id": "",
                    "raw": line,
                })
            else:
                records.append({
                    "id": 2000 + line_id,
                    "timestamp": "2026-01-01 00:00:00",
                    "source_os": "Windows",
                    "component": "Unknown",
                    "level": "info",
                    "content": line,
                    "event_id": "",
                    "raw": line,
                })

    return pd.DataFrame(records)


def parse_mac_logs() -> pd.DataFrame:
    """Parse Mac_2k.log.txt (BSD syslog format) into normalized DataFrame."""
    filepath = os.path.join(DATA_DIR, "Mac_2k.log.txt")
    if not os.path.exists(filepath):
        return pd.DataFrame()

    # Pattern: Jul  1 09:00:55 hostname process[pid]: message
    pattern = re.compile(
        r'^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+'
        r'([\w\-\.]+)\s+'
        r'([\w\.\-]+)(?:\[(\d+)\])?:\s*'
        r'(.+)$'
    )

    records = []
    line_id = 0

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            line_id += 1
            match = pattern.match(line)
            if match:
                month, day, time_str, hostname, process, pid, message = match.groups()
                try:
                    dt = datetime.strptime(f"{month} {day} 2026 {time_str}", "%b %d %Y %H:%M:%S")
                    timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    timestamp = "2026-01-01 00:00:00"

                records.append({
                    "id": 4000 + line_id,
                    "timestamp": timestamp,
                    "source_os": "macOS",
                    "component": process,
                    "level": "info",
                    "content": message,
                    "event_id": "",
                    "raw": line,
                })
            else:
                records.append({
                    "id": 4000 + line_id,
                    "timestamp": "2026-01-01 00:00:00",
                    "source_os": "macOS",
                    "component": "Unknown",
                    "level": "info",
                    "content": line,
                    "event_id": "",
                    "raw": line,
                })

    return pd.DataFrame(records)


def load_soc_3000() -> pd.DataFrame:
    filepath = os.path.join(DATA_DIR, "soc_3000_dataset.csv")
    if not os.path.exists(filepath):
        print(f"Dataset not found at {filepath}")
        return pd.DataFrame()

    df = pd.read_csv(filepath)
    records = []
    
    import random
    random.seed(42)  # For reproducibility
    
    for idx, row in df.iterrows():
        src_ip = str(row.get('src_ip', ''))
        raw_log = str(row.get('raw_log', ''))
        # Append from <ip> so classifier.py regex can naturally pick it up
        content = f"{raw_log} from {src_ip}"
        
        port = str(row.get('dest_port', ''))
        if port in ['22', '21']:
            source_os = 'Linux'
        elif port in ['3389', '445']:
            source_os = 'Windows'
        elif port in ['80', '443']:
            source_os = random.choice(['Linux', 'Windows', 'macOS'])
        else:
            source_os = random.choice(['Linux', 'Windows', 'macOS'])
            
        records.append({
            "id": idx + 1,
            "timestamp": str(row.get('timestamp', '')),
            "source_os": source_os,
            "component": f"{row.get('protocol', 'TCP')} {port}",
            "level": str(row.get('severity', 'info')).lower(),
            "content": content,
            "event_id": str(row.get('alert_type', '')),
            "raw": raw_log
        })
        
    return pd.DataFrame(records)


def load_all_logs() -> pd.DataFrame:
    """Load and merge all 4 log sources (2k + 2k + 2k + 3k = 9k logs)."""
    linux_df = parse_linux_logs()
    windows_df = parse_windows_logs()
    mac_df = parse_mac_logs()
    soc_df = load_soc_3000()

    frames = [df for df in [linux_df, windows_df, mac_df, soc_df] if not df.empty]
    if not frames:
        return pd.DataFrame(columns=[
            "id", "timestamp", "source_os", "component",
            "level", "content", "event_id", "raw"
        ])

    merged = pd.concat(frames, ignore_index=True)
    # Re-assign sequential IDs
    merged = merged.sort_values("timestamp").reset_index(drop=True)
    merged["id"] = range(1, len(merged) + 1)
    
    print(f"[AegisCore] Loaded {len(merged)} logs total.")
    return merged


if __name__ == "__main__":
    df = load_all_logs()
    print(df.head(20))
    print(f"\nTotal logs: {len(df)}")
    print(f"Sources: {df['source_os'].value_counts().to_dict()}")
