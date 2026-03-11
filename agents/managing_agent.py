from __future__ import annotations

import re

from agents.banking_db import BankingDB
from agents.llm_agent import LLMAgent


class ManagingAgent:
    def __init__(self, db: BankingDB, llm: LLMAgent) -> None:
        self.db = db
        self.llm = llm

    def plan_query(self, user_intent: str) -> str:
        llm_sql = self._try_llm_planner(user_intent)
        if llm_sql and self._is_safe_select(llm_sql):
            return llm_sql
        return self._heuristic_plan(user_intent)

    def execute_planned_query(self, user_intent: str) -> list[dict]:
        sql = self.plan_query(user_intent)
        if not self._is_safe_select(sql):
            raise ValueError("Only SELECT queries are permitted.")
        return self.db.raw_query(sql)

    def _try_llm_planner(self, user_intent: str) -> str:
        prompt = (
            "Convert this banking user intent into a SQLite SELECT query over table customers. "
            "Return only SQL text. Never use INSERT/UPDATE/DELETE/DDL. "
            f"Intent: {user_intent}"
        )
        response = self.llm.ask(prompt).strip()
        cleaned = response.strip("`\n ")
        if cleaned.lower().startswith("sql"):
            cleaned = cleaned[3:].strip()
        return cleaned

    def _heuristic_plan(self, user_intent: str) -> str:
        lowered = user_intent.lower()
        cust_match = re.search(r"cust\d{3}", lowered)
        if cust_match:
            customer_id = cust_match.group(0).upper()
            if "detail" in lowered or "profile" in lowered or "record" in lowered:
                return f"SELECT * FROM customers WHERE customer_id = '{customer_id}'"
            return f"SELECT customer_id, full_name, balance FROM customers WHERE customer_id = '{customer_id}'"

        if "balance" in lowered:
            return "SELECT customer_id, full_name, balance FROM customers"
        if "ifsc" in lowered:
            return "SELECT customer_id, full_name, ifsc FROM customers"
        if "upi" in lowered:
            return "SELECT customer_id, full_name, upi FROM customers"
        return "SELECT customer_id, full_name, balance FROM customers LIMIT 5"

    def _is_safe_select(self, sql: str) -> bool:
        normalized = sql.strip().lower().rstrip(";")
        forbidden = [" insert ", " update ", " delete ", " drop ", " alter ", " create ", " pragma "]
        if not normalized.startswith("select "):
            return False
        wrapped = f" {normalized} "
        return not any(token in wrapped for token in forbidden)
