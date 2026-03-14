import sqlite3
import re

from config import settings


SEED_CUSTOMERS = [
    ("CUST001", "Arjun Mehta",   "2345 6789 0123", "ABCPM1234D", "914010012345678", "HDFC0001234", "arjun.mehta@oksbi",   "+91 9876543210", "arjun42@gmail.com",     "15/04/1988", "Savings", 142500.00,  "Mumbai",    "Verified"),
    ("CUST002", "Priya Nair",    "9876 5432 1098", "DXQPS5678K", "50100023456789",  "SBIN0005943", "priya.nair@ybl",      "+91 9123456780", "priya.nair@yahoo.in",   "22/09/1993", "Savings", 87320.50,   "Chennai",   "Verified"),
    ("CUST003", "Rahul Singh",   "3456 7890 1234", "FGHRS9012L", "60120034567890",  "ICIC0001234", "rahul.singh@okaxis",  "+91 9234567891", "rahul99@outlook.com",   "07/12/1985", "Current", 523100.00,  "Delhi",     "Verified"),
    ("CUST004", "Deepa Iyer",    "4567 8901 2345", "HIJDT3456M", "70130045678901",  "UTIB0000123", "deepa.iyer@paytm",    "+91 9345678902", "deepa.iyer@gmail.com",  "30/06/1990", "Savings", 34750.75,   "Bangalore", "Verified"),
    ("CUST005", "Vikram Patel",  "5678 9012 3456", "KLMUV7890N", "80140056789012",  "PUNB0123456", "vikram.patel@upi",    "+91 9456789013", "vpatel@rediffmail.com", "18/03/1978", "NRI",     980000.00,  "Ahmedabad", "Verified"),
    ("CUST006", "Sneha Sharma",  "6789 0123 4567", "NOPWX2345O", "90150067890123",  "BARB0001234", "sneha.sharma@oksbi",  "+91 9567890124", "sneha22@gmail.com",     "25/11/1995", "Savings", 12400.00,   "Jaipur",    "Pending"),
    ("CUST007", "Kiran Reddy",   "7890 1234 5678", "PQRYZ6789P", "10160078901234",  "CNRB0001234", "kiran.reddy@ybl",     "+91 9678901235", "kiran.reddy@gmail.com", "14/08/1982", "Current", 275000.00,  "Hyderabad", "Verified"),
    ("CUST008", "Meera Pillai",  "8901 2345 6789", "STUAB1234Q", "20170089012345",  "KKBK0001234", "meera.pillai@okaxis", "+91 9789012346", "meerap@yahoo.co.in",    "03/02/1991", "Savings", 67890.25,   "Kochi",     "Verified"),
    ("CUST009", "Rohit Gupta",   "9012 3456 7890", "VWXCD5678R", "30180090123456",  "HDFC0002345", "rohit.gupta@paytm",   "+91 9890123457", "rohit.gupta@gmail.com", "20/07/1987", "Savings", 195000.00,  "Lucknow",   "Verified"),
    ("CUST010", "Ananya Bose",   "0123 4567 8901", "YZAEF9012S", "40190001234567",  "SBIN0012345", "ananya.bose@upi",     "+91 9901234568", "ananya.bose@gmail.com", "11/05/1999", "Savings", 28150.00,   "Kolkata",   "Verified"),
]

_COLUMN_NAMES = (
    "customer_id", "full_name", "aadhaar", "pan", "account_no",
    "ifsc", "upi_id", "phone", "email", "dob",
    "account_type", "balance", "city", "kyc_status",
)

_DANGEROUS = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b", re.IGNORECASE
)


class BankingDB:
    def __init__(self, db_path: str = settings.database_path):
        # FastAPI handlers may run in different threads; this DB object is shared.
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._create_and_seed()

    def _create_and_seed(self):
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS customers (
                customer_id  TEXT PRIMARY KEY,
                full_name    TEXT NOT NULL,
                aadhaar      TEXT NOT NULL,
                pan          TEXT NOT NULL,
                account_no   TEXT NOT NULL,
                ifsc         TEXT NOT NULL,
                upi_id       TEXT NOT NULL,
                phone        TEXT NOT NULL,
                email        TEXT NOT NULL,
                dob          TEXT NOT NULL,
                account_type TEXT NOT NULL,
                balance      REAL NOT NULL,
                city         TEXT NOT NULL,
                kyc_status   TEXT NOT NULL
            )
            """
        )
        count = self._conn.execute("SELECT COUNT(*) FROM customers").fetchone()[0]
        if count == 0:
            placeholders = ", ".join("?" * len(_COLUMN_NAMES))
            self._conn.executemany(
                f"INSERT INTO customers ({', '.join(_COLUMN_NAMES)}) VALUES ({placeholders})",
                SEED_CUSTOMERS,
            )
            self._conn.commit()

    def execute_query(self, sql: str) -> list[dict]:
        """Execute a read-only SQL query with safety rails."""
        stripped = sql.strip()

        if ";" in stripped:
            raise ValueError("Multiple statements are not allowed")
        if not stripped.upper().startswith("SELECT"):
            raise ValueError("Only SELECT queries are allowed")
        if _DANGEROUS.search(stripped):
            raise ValueError("Prohibited SQL keyword detected")

        rows = self._conn.execute(stripped).fetchall()
        return [dict(row) for row in rows]

    def get_schema(self) -> str:
        """Return table schema description (no data rows)."""
        return (
            "Table: customers\n"
            "Columns:\n"
            "  customer_id    TEXT PRIMARY KEY  -- e.g. 'CUST001'\n"
            "  full_name      TEXT NOT NULL\n"
            "  aadhaar        TEXT NOT NULL      -- e.g. '2345 6789 0123'\n"
            "  pan            TEXT NOT NULL      -- e.g. 'ABCPM1234D'\n"
            "  account_no     TEXT NOT NULL      -- e.g. '914010012345678'\n"
            "  ifsc           TEXT NOT NULL      -- e.g. 'HDFC0001234'\n"
            "  upi_id         TEXT NOT NULL      -- e.g. 'arjun.mehta@oksbi'\n"
            "  phone          TEXT NOT NULL      -- e.g. '+91 9876543210'\n"
            "  email          TEXT NOT NULL      -- e.g. 'arjun42@gmail.com'\n"
            "  dob            TEXT NOT NULL      -- e.g. '15/04/1988'\n"
            "  account_type   TEXT NOT NULL      -- 'Savings' | 'Current' | 'NRI'\n"
            "  balance        REAL NOT NULL      -- e.g. 142500.00\n"
            "  city           TEXT NOT NULL      -- e.g. 'Mumbai'\n"
            "  kyc_status     TEXT NOT NULL      -- 'Verified' | 'Pending'\n"
        )

    def close(self):
        self._conn.close()


banking_db = BankingDB()


if __name__ == "__main__":
    test_db = BankingDB(db_path=":memory:")
    passed = 0
    total = 5

    # Test 1: Query CUST001
    try:
        rows = test_db.execute_query("SELECT * FROM customers WHERE customer_id = 'CUST001'")
        assert len(rows) == 1 and rows[0]["full_name"] == "Arjun Mehta"
        print("[PASS] 1. Query CUST001 → Arjun Mehta")
        passed += 1
    except Exception as e:
        print(f"[FAIL] 1. Query CUST001 → {e}")

    # Test 2: Query all Savings accounts
    try:
        rows = test_db.execute_query("SELECT * FROM customers WHERE account_type = 'Savings'")
        assert len(rows) == 7, f"Expected 7, got {len(rows)}"
        print(f"[PASS] 2. Savings accounts → {len(rows)} rows")
        passed += 1
    except Exception as e:
        print(f"[FAIL] 2. Savings accounts → {e}")

    # Test 3: Attempt INSERT
    try:
        test_db.execute_query("INSERT INTO customers VALUES ('X','X','X','X','X','X','X','X','X','X','X',0,'X','X')")
        print("[FAIL] 3. INSERT should have raised ValueError")
    except ValueError:
        print("[PASS] 3. INSERT blocked")
        passed += 1

    # Test 4: Attempt DELETE
    try:
        test_db.execute_query("DELETE FROM customers WHERE customer_id = 'CUST001'")
        print("[FAIL] 4. DELETE should have raised ValueError")
    except ValueError:
        print("[PASS] 4. DELETE blocked")
        passed += 1

    # Test 5: get_schema() returns schema, no data
    try:
        schema = test_db.get_schema()
        assert "customer_id" in schema and "Arjun" not in schema
        print(f"[PASS] 5. get_schema() → {len(schema)} chars, no data rows")
        passed += 1
    except Exception as e:
        print(f"[FAIL] 5. get_schema() → {e}")

    test_db.close()
    print(f"\nResults: {passed}/{total} passed — {'ALL PASS' if passed == total else 'SOME FAILED'}")
