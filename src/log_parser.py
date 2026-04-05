import re
import pandas as pd
from dataclasses import dataclass
from datetime import datetime
from typing import Generator, Optional


@dataclass
class LogEntry:
    ip: str
    timestamp: float
    method: Optional[str]
    url: Optional[str]
    status: Optional[int]
    bytes_transferred: int
    is_attack: bool
    label: str


LOG_PATTERN = re.compile(
    r'(\S+) - - \[(.+?)\] "(\S+) (\S+) \S+" (\d+) (\S+)'
)

TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def _parse_nasa_line(line: str) -> Optional[LogEntry]:
    match = LOG_PATTERN.match(line)
    if not match:
        return None
    ip, ts_str, method, url, status, bytes_str = match.groups()
    try:
        timestamp = datetime.strptime(ts_str, TIMESTAMP_FORMAT).timestamp()
    except ValueError:
        return None
    return LogEntry(
        ip=ip,
        timestamp=timestamp,
        method=method,
        url=url,
        status=int(status),
        bytes_transferred=0 if bytes_str == '-' else int(bytes_str),
        is_attack=False,
        label="BENIGN"
    )


def stream_nasa_logs(*filepaths: str) -> Generator[LogEntry, None, None]:
    for filepath in filepaths:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                entry = _parse_nasa_line(line.strip())
                if entry:
                    yield entry


def stream_cic_logs(*filepaths: str) -> Generator[LogEntry, None, None]:
    for filepath in filepaths:
        for chunk in pd.read_csv(filepath, low_memory=False, chunksize=1000):
            chunk.columns = chunk.columns.str.strip().str.replace(' ', '_')
            for row in chunk.itertuples(index=False):
                try:
                    timestamp = pd.to_datetime(row.Timestamp).timestamp()
                except Exception:
                    continue
                label = str(row.Label).strip()
                yield LogEntry(
                    ip=str(row.Source_IP).strip(),
                    timestamp=timestamp,
                    method=None,
                    url=None,
                    status=None,
                    bytes_transferred=int(getattr(row, 'Total_Length_of_Fwd_Packets', 0)),
                    is_attack=label.upper() != 'BENIGN',
                    label=label
                )