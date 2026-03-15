import os
import json
import logging
import re
from dataclasses import dataclass

import httpx

from agents.banking_db import banking_db
from config import settings

logger = logging.getLogger("aegis.managing_agent")


@dataclass
class QueryResult:
    sql_executed: str
    raw_data: list[dict]
    row_count: int
    success: bool
    error: str | None = None


class ManagingAgent:

    SYSTEM_PROMPT = """You are a banking database query planner for Aegis Bank.

Your ONLY job is to generate a safe SQL SELECT query based on the user's intent.
You must respond with ONLY a JSON object in this exact format:
{{
  "sql": "SELECT ... FROM customers WHERE ...",
  "reasoning": "one sentence explaining what this query does"
}}

Rules you must never break:
- Only use SELECT statements
- Only query the customers table
- Never use DROP, INSERT, UPDATE, DELETE, ALTER, CREATE
- Never use subqueries that modify data
- If the intent is unclear, return all safe columns for the relevant customer
- If no customer is specified, limit results to 5 rows
- Never select * — always name the specific columns needed

Database schema:
{schema}"""

    def __init__(self):
        self._client = None
        self._schema = banking_db.get_schema()

    def _get_client(self):
        if self._client is not None:
            return self._client
        self._client = httpx.Client(timeout=20.0)
        return self._client

    def _call_llm(self, user_intent: str) -> str:
        system = self.SYSTEM_PROMPT.format(schema=self._schema)
        provider = self._resolve_provider()
        logger.info(
            "ManagingAgent provider=%s (configured=%s)",
            provider,
            settings.llm_provider,
        )

        if provider == "openai" and settings.openai_api_key:
            return self._call_openai(system, user_intent)
        if provider == "anthropic" and settings.anthropic_api_key:
            return self._call_anthropic(system, user_intent)
        return self._call_mock(user_intent)

    def _resolve_provider(self) -> str:
        configured = settings.llm_provider.lower().strip()
        has_openai = bool(settings.openai_api_key)
        has_anthropic = bool(settings.anthropic_api_key)

        if configured == "openai":
            return "openai" if has_openai else ("anthropic" if has_anthropic else "mock")
        if configured == "anthropic":
            return "anthropic" if has_anthropic else ("openai" if has_openai else "mock")
        if configured == "mock":
            if has_anthropic:
                return "anthropic"
            if has_openai:
                return "openai"
            return "mock"
        return "anthropic" if has_anthropic else ("openai" if has_openai else "mock")

    def _call_openai(self, system: str, user_intent: str) -> str:
        client = self._get_client()
        resp = client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {settings.openai_api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": settings.llm_model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user_intent},
                ],
                "temperature": 0.0,
            },
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]

    def _call_anthropic(self, system: str, user_intent: str) -> str:
        client = self._get_client()
        resp = client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": settings.anthropic_api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
            json={
                "model": settings.llm_model,
                "max_tokens": 256,
                "system": system,
                "messages": [{"role": "user", "content": user_intent}],
            },
        )
        resp.raise_for_status()
        return resp.json()["content"][0]["text"]

    def _call_mock(self, user_intent: str) -> str:
        lowered = user_intent.lower()
        cust_match = re.search(r"\bcust\s*0*([0-9]{1,4})\b", lowered)
        if cust_match:
            cust_id = f"CUST{int(cust_match.group(1)):03d}"
            return json.dumps({
                "sql": (
                    "SELECT customer_id, full_name, aadhaar, pan, account_no, ifsc, phone, account_type, balance, city, kyc_status "
                    f"FROM customers WHERE customer_id = '{cust_id}'"
                ),
                "reasoning": f"Looking up customer by id {cust_id}",
            })

        if "balance" in lowered:
            name_part = ""
            for word in user_intent.split():
                if word[0].isupper() and word.lower() not in (
                    "what", "is", "the", "show", "me", "for", "of", "account",
                    "balance", "all", "customers", "in",
                ):
                    name_part = word
                    break
            if name_part:
                return json.dumps({
                    "sql": f"SELECT customer_id, full_name, balance FROM customers WHERE full_name LIKE '%{name_part}%'",
                    "reasoning": f"Looking up balance for customer matching '{name_part}'",
                })
            return json.dumps({
                "sql": "SELECT customer_id, full_name, balance FROM customers LIMIT 5",
                "reasoning": "Returning balances for all customers (limited to 5)",
            })
        if "mumbai" in lowered or "chennai" in lowered or "delhi" in lowered:
            for city in ("Mumbai", "Chennai", "Delhi", "Bangalore", "Ahmedabad",
                         "Jaipur", "Hyderabad", "Kochi", "Lucknow", "Kolkata"):
                if city.lower() in lowered:
                    return json.dumps({
                        "sql": f"SELECT customer_id, full_name, city, account_type, balance FROM customers WHERE city = '{city}'",
                        "reasoning": f"Returning customers located in {city}",
                    })
        if "delete" in lowered or "drop" in lowered or "insert" in lowered:
            return json.dumps({
                "sql": "DELETE FROM customers",
                "reasoning": "Attempting destructive operation (will be blocked by safety rails)",
            })
        return json.dumps({
            "sql": "SELECT customer_id, full_name, account_type, balance, city FROM customers LIMIT 5",
            "reasoning": "General customer list (limited to 5)",
        })

    def plan_and_execute(self, user_intent: str) -> QueryResult:
        """Generate SQL from user intent via LLM, validate, and execute."""
        # Step 1: Get SQL from LLM
        try:
            llm_response = self._call_llm(user_intent)
        except Exception as e:
            logger.exception("LLM call failed for intent=%r", user_intent)
            return QueryResult(sql_executed="", raw_data=[], row_count=0,
                               success=False, error="LLM returned invalid query format")

        # Step 2: Parse JSON response
        try:
            parsed = json.loads(llm_response)
            sql = parsed["sql"]
        except (json.JSONDecodeError, KeyError, TypeError):
            logger.error("Invalid LLM planning payload: %r", llm_response)
            return QueryResult(sql_executed="", raw_data=[], row_count=0,
                               success=False, error="LLM returned invalid query format")

        logger.info("SQL generated: %s", sql)

        # Step 3 & 4: Validate and execute via banking_db safety rails
        try:
            rows = banking_db.execute_query(sql)
        except ValueError:
            logger.warning("Query failed safety rails: %s", sql)
            return QueryResult(sql_executed=sql, raw_data=[], row_count=0,
                               success=False, error="Query failed safety validation")
        except Exception as e:
            logger.exception("Query execution failed: %s", sql)
            return QueryResult(sql_executed=sql, raw_data=[], row_count=0,
                               success=False, error=str(e))

        logger.info("plan_and_execute success=True rows=%d", len(rows))
        return QueryResult(sql_executed=sql, raw_data=rows,
                           row_count=len(rows), success=True)

    def get_schema(self) -> str:
        return self._schema


managing_agent = ManagingAgent()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    tests = [
        ("What is the account balance for Arjun Mehta?", True),
        ("Show me all customers in Mumbai", True),
        ("Delete all records", False),
    ]

    for i, (intent, expect_data) in enumerate(tests, 1):
        print(f"\n--- Test {i}: \"{intent}\" ---")
        result = managing_agent.plan_and_execute(intent)
        print(f"  SQL: {result.sql_executed}")
        print(f"  Success: {result.success}")
        print(f"  Rows: {result.row_count}")
        if result.error:
            print(f"  Error: {result.error}")
        if expect_data and result.success:
            print(f"  [PASS] Got {result.row_count} row(s)")
        elif not expect_data and (not result.success or result.row_count == 0):
            print(f"  [PASS] Destructive query handled safely")
        else:
            print(f"  [WARN] Unexpected result")
