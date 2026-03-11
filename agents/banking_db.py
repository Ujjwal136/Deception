from __future__ import annotations

import sqlite3
from typing import Any

from config import settings


SEED_CUSTOMERS = [
    ("CUST001", "Aarav Sharma", "3849 7261 5022", "AHKPS9123Q", "SBIN0A12CD3", "aarav.sharma@oksbi", "+91 9876543210", "aarav.sharma@gmail.com", "1990-03-12", "M1234567", 253400.75),
    ("CUST002", "Priya Nair", "5561 0198 7732", "BRTPN6684L", "HDFC0B45EF6", "priya.nair@okhdfcbank", "+91 9123456780", "priya.nair@yahoo.co.in", "1988-11-07", "K7654321", 118920.10),
    ("CUST003", "Rahul Patel", "9174 2201 6658", "CPATP4411Z", "ICIC0C78AB9", "rahul.patel@okaxis", "+91 9988776655", "rahul.patel@outlook.com", "1992-01-30", "N4567123", 87999.50),
    ("CUST004", "Deepa Iyer", "6602 4819 3374", "DPIYR5590H", "UTIB0D90BC1", "deepa.iyer@ybl", "+91 9765432101", "deepa.iyer@gmail.com", "1985-05-22", "P2223334", 315000.00),
    ("CUST005", "Shruti Joshi", "7301 5544 9811", "EJOSH7702M", "PUNB0E12AA4", "shruti.joshi@paytm", "+91 9654321876", "shruti.joshi@rediffmail.com", "1994-09-18", "T9081726", 64200.00),
    ("CUST006", "Suresh Mehta", "4021 7330 2289", "FSMEH3310R", "BARB0F45DD8", "suresh.mehta@oksbi", "+91 9543218765", "suresh.mehta@gmail.com", "1979-12-03", "R8899001", 904500.30),
]


class BankingDB:
    def __init__(self, db_path: str | None = None) -> None:
        self.db_path = db_path or settings.database_path
        self._bootstrap()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _bootstrap(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS customers (
                    customer_id TEXT PRIMARY KEY,
                    full_name TEXT NOT NULL,
                    aadhaar TEXT NOT NULL,
                    pan TEXT NOT NULL,
                    ifsc TEXT NOT NULL,
                    upi TEXT NOT NULL,
                    phone TEXT NOT NULL,
                    email TEXT NOT NULL,
                    dob TEXT NOT NULL,
                    passport TEXT NOT NULL,
                    balance REAL NOT NULL
                )
                """
            )
            count = conn.execute("SELECT COUNT(*) AS c FROM customers").fetchone()["c"]
            if count == 0:
                conn.executemany(
                    """
                    INSERT INTO customers (
                        customer_id, full_name, aadhaar, pan, ifsc, upi, phone, email, dob, passport, balance
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    SEED_CUSTOMERS,
                )

    def raw_query(self, sql: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(sql).fetchall()
            return [dict(row) for row in rows]
