from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

DATABASE_PATH = Path(
    os.environ.get(
        "DDOSGUARD_DB_PATH",
        str(Path(__file__).resolve().parent.parent / "ddosguard.db"),
    )
).expanduser()


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database() -> None:
    conn = get_connection()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                observed_value REAL,
                threshold_value TEXT,
                explanation TEXT NOT NULL,
                traffic_source TEXT NOT NULL DEFAULT 'unknown'
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def insert_alert(alert: Dict[str, Any]) -> int:
    initialize_database()
    conn = get_connection()
    try:
        cursor = conn.execute(
            """
            INSERT INTO alerts (timestamp, severity, rule_name, observed_value, threshold_value, explanation, traffic_source)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert.get("timestamp"),
                alert.get("severity"),
                alert.get("rule_name"),
                alert.get("observed_value"),
                str(alert.get("threshold_value")) if alert.get("threshold_value") is not None else None,
                alert.get("explanation"),
                alert.get("traffic_source", "unknown"),
            ),
        )
        conn.commit()
        return int(cursor.lastrowid)
    finally:
        conn.close()


def fetch_alerts(
    severity: Optional[str] = None,
    traffic_source: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    initialize_database()
    conn = get_connection()
    query = "SELECT * FROM alerts"
    conditions = []
    params: List[Any] = []

    if severity:
        conditions.append("severity = ?")
        params.append(severity)
    if traffic_source:
        conditions.append("traffic_source = ?")
        params.append(traffic_source)
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    try:
        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def clear_alerts() -> None:
    conn = get_connection()
    try:
        conn.execute("DELETE FROM alerts")
        conn.commit()
    finally:
        conn.close()
