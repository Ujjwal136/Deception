import os
import logging
from dataclasses import dataclass
from collections import OrderedDict

from openai import OpenAI

from config import settings

logger = logging.getLogger("aegis.llm_agent")


@dataclass
class AgentResponse:
    answer: str
    trace_id: str
    was_blocked: bool
    model_used: str
    input_tokens: int
    output_tokens: int


SYSTEM_PROMPT = """You are Aegis Assistant — a secure, helpful banking assistant \
for Aegis Bank customers.

You help customers with account inquiries, balance checks, \
transaction history, and general banking questions.

Important rules:
- The data you receive has already been security-processed. \
Encrypted values like "4697 1962 9001" are reference tokens, \
not real account numbers — never tell the user these are \
their real details.
- Always be polite, concise, and professional.
- If data shows [TYPE_REDACTED], tell the user that information \
is protected and cannot be displayed.
- Never make up information not present in the data provided.
- If no relevant data was found, say so clearly."""

GENERAL_BANKING_PROMPT = """You are Aegis Assistant, a helpful banking assistant
for Aegis Bank India. Answer general banking questions
about processes, policies, fees, and procedures.
Be concise and helpful. If asked about specific
customer data you cannot access, explain that
customers should log in to check their details."""


class LLMAgent:

    def __init__(self):
        self._model_name = settings.llm_model
        self._general_cache: OrderedDict[str, str] = OrderedDict()
        self._general_cache_max = int(os.getenv("GENERAL_CACHE_SIZE", "128"))

    def _resolve_provider(self) -> str:
        if os.getenv("TEST_MODE", "").lower() == "true" or os.getenv("PYTEST_CURRENT_TEST"):
            return "mock"
        if os.getenv("OPENAI_API_KEY"):
            return "openai"
        if os.getenv("ANTHROPIC_API_KEY"):
            return "anthropic"
        return "mock"

    def _call_llm(self, system: str, user_message: str) -> dict:
        """
        Call the configured LLM provider. Returns dict with
        keys: text, model, input_tokens, output_tokens.
        """
        provider = self._resolve_provider()

        if provider == "openai":
            return self._call_openai(system, user_message)
        if provider == "anthropic":
            return self._call_anthropic(system, user_message)
        return self._call_mock(user_message)

    def _call_openai(self, system: str, user_message: str) -> dict:
        api_key = os.getenv("OPENAI_API_KEY", "")
        if not api_key:
            return self._call_mock(user_message)

        try:
            client = OpenAI(api_key=api_key, max_retries=0, timeout=8)
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                temperature=0.1,
                max_tokens=220,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user_message},
                ],
            )
            usage = response.usage
            answer = response.choices[0].message.content or ""

            return {
                "text": answer,
                "model": response.model or self._model_name,
                "input_tokens": usage.prompt_tokens if usage and usage.prompt_tokens is not None else 0,
                "output_tokens": usage.completion_tokens if usage and usage.completion_tokens is not None else 0,
            }
        except Exception:
            logger.exception("OpenAI call failed; using mock fallback response")
            return self._call_mock(user_message)

    def _call_anthropic(self, system: str, user_message: str) -> dict:
        import httpx

        api_key = os.getenv("ANTHROPIC_API_KEY", "")
        if not api_key:
            return self._call_mock(user_message)

        client = httpx.Client(timeout=20.0)
        try:
            resp = client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self._model_name,
                    "max_tokens": 512,
                    "system": system,
                    "messages": [{"role": "user", "content": user_message}],
                },
            )
            resp.raise_for_status()
            data = resp.json()
            usage = data.get("usage", {})
            return {
                "text": data["content"][0]["text"],
                "model": data.get("model", self._model_name),
                "input_tokens": usage.get("input_tokens", 0),
                "output_tokens": usage.get("output_tokens", 0),
            }
        except Exception:
            logger.exception("Anthropic call failed; using mock fallback response")
            return self._call_mock(user_message)

    def _call_mock(self, user_message: str) -> dict:
        if "Relevant account data" in user_message:
            lines = user_message.split("Relevant account data (security-processed):")
            if len(lines) > 1:
                data_part = lines[1].split("Please answer the customer")[0].strip()
                text = f"Based on the account information available, here is what I found: {data_part}"
            else:
                text = "Here is the information from your account records."
        else:
            text = self._fallback_general_answer(user_message)
        return {
            "text": text,
            "model": "mock",
            "input_tokens": 0,
            "output_tokens": 0,
        }

    def _fallback_general_answer(self, user_message: str) -> str:
        lowered = user_message.lower()
        if "upi" in lowered and "pin" in lowered and "reset" in lowered:
            return (
                "To reset your UPI PIN, open your bank or UPI app, select the linked account, choose 'Reset UPI PIN', "
                "verify your debit card details, then set a new UPI PIN with OTP verification."
            )
        if "neft" in lowered and ("charges" in lowered or "charge" in lowered or "fee" in lowered):
            return (
                "NEFT charges vary by bank account type and channel. Many banks offer free NEFT through net/mobile banking, "
                "while branch-initiated transfers may have a small fee plus GST."
            )
        if "hello" in lowered or "help" in lowered:
            return (
                "Hello. I can help with account balances, customer lookup requests, transfer guidance, and banking process questions "
                "for Aegis Bank services."
            )
        return "I can help with Aegis Bank account queries, transfers, and general banking process questions."

    def _quick_local_general_answer(self, user_message: str) -> str | None:
        lowered = user_message.lower().strip()

        if lowered in ("hi", "hello", "hey", "hello aegis", "hi aegis"):
            return "Hello. I can help with balances, customer lookups, transfers, and banking policy questions."

        if "what can you help" in lowered:
            return "I can help with account balances, customer details, transfer guidance, and general banking process and fee questions."

        if "upi" in lowered and "pin" in lowered and "reset" in lowered:
            return (
                "To reset your UPI PIN, open your UPI or bank app, choose your linked account, tap Reset UPI PIN, "
                "verify with card details and OTP, then set a new PIN."
            )

        if "neft" in lowered and ("charge" in lowered or "fee" in lowered):
            return (
                "NEFT is usually free on most net/mobile banking channels, while branch requests may include a small service fee plus GST."
            )

        return None

    def _cache_get(self, key: str) -> str | None:
        if key not in self._general_cache:
            return None
        value = self._general_cache.pop(key)
        self._general_cache[key] = value
        return value

    def _cache_put(self, key: str, value: str) -> None:
        if key in self._general_cache:
            self._general_cache.pop(key)
        self._general_cache[key] = value
        while len(self._general_cache) > self._general_cache_max:
            self._general_cache.popitem(last=False)

    def _fast_synthesize_from_data(self, user_prompt: str, sanitised_data: list[dict]) -> str:
        rows = sanitised_data[:3]
        lowered = user_prompt.lower()
        lines: list[str] = []

        if "balance" in lowered and rows:
            row = rows[0]
            name = row.get("full_name", "Customer")
            balance = row.get("balance", "N/A")
            account_type = row.get("account_type", "")
            city = row.get("city", "")
            return (
                f"{name} has a current {account_type} account balance of {balance}."
                + (f" Registered city: {city}." if city else "")
            )

        for idx, row in enumerate(rows, 1):
            name = row.get("full_name", f"Customer {idx}")
            customer_id = row.get("customer_id", "")
            account_type = row.get("account_type", "")
            balance = row.get("balance", "")
            city = row.get("city", "")
            parts = [p for p in [customer_id, name, account_type, str(balance) if balance != "" else "", city] if p]
            lines.append(f"{idx}. " + " | ".join(parts))

        if not lines:
            return "I could not find relevant account details for this request."

        suffix = "" if len(sanitised_data) <= 3 else f" Showing first {len(rows)} of {len(sanitised_data)} records."
        return "Here are the matched customer records:\n" + "\n".join(lines) + suffix

    def ask(self, user_prompt: str, session_id: str) -> str:
        """Send a general question to the LLM (no DB context)."""
        normalized = " ".join(user_prompt.lower().split())

        quick = self._quick_local_general_answer(user_prompt)
        if quick:
            return quick

        cached = self._cache_get(normalized)
        if cached:
            return cached

        try:
            result = self._call_llm(GENERAL_BANKING_PROMPT, user_prompt)
            text = result["text"]
            if text:
                self._cache_put(normalized, text)
            return text
        except Exception:
            logger.exception("LLM ask() call failed")
            fallback = self._fallback_general_answer(user_prompt)
            self._cache_put(normalized, fallback)
            return fallback

    def synthesize(
        self,
        user_prompt: str,
        sanitised_data: list[dict],
        trace_id: str,
        session_id: str,
    ) -> AgentResponse:
        """Synthesise a natural language answer from sanitised DB data."""
        if not sanitised_data:
            general_answer = self.ask(user_prompt=user_prompt, session_id=session_id)
            return AgentResponse(
                answer=general_answer,
                trace_id=trace_id,
                was_blocked=False,
                model_used=self._resolve_provider(),
                input_tokens=0,
                output_tokens=0,
            )

        if os.getenv("FAST_SYNTHESIS", "true").lower() == "true":
            return AgentResponse(
                answer=self._fast_synthesize_from_data(user_prompt, sanitised_data),
                trace_id=trace_id,
                was_blocked=False,
                model_used="fast-template",
                input_tokens=0,
                output_tokens=0,
            )

        formatted_rows = []
        for i, row in enumerate(sanitised_data, 1):
            fields = "\n".join(f"  {k}: {v}" for k, v in row.items())
            formatted_rows.append(f"Record {i}:\n{fields}")
        formatted_data = "\n\n".join(formatted_rows)

        user_message = (
            f"Customer query: {user_prompt}\n\n"
            f"Relevant account data (security-processed):\n{formatted_data}\n\n"
            f"Please answer the customer's query using only the data provided above."
        )

        try:
            result = self._call_llm(SYSTEM_PROMPT, user_message)
            logger.debug("synthesize tokens: in=%d out=%d", result["input_tokens"], result["output_tokens"])
            return AgentResponse(
                answer=result["text"],
                trace_id=trace_id,
                was_blocked=False,
                model_used=result["model"],
                input_tokens=result["input_tokens"],
                output_tokens=result["output_tokens"],
            )
        except Exception:
            logger.exception("LLM synthesize() call failed")
            return AgentResponse(
                answer="I'm sorry, I encountered an error processing your request. Please try again.",
                trace_id=trace_id,
                was_blocked=False,
                model_used=self._model_name,
                input_tokens=0,
                output_tokens=0,
            )

    def handle_blocked(
        self,
        trace_id: str,
        threat_type: str,
        session_id: str,
    ) -> AgentResponse:
        """Return a safe rejection message for blocked requests."""
        return AgentResponse(
            answer=(
                "Your request could not be processed due to a security "
                "policy violation. If you believe this is an error, "
                f"please contact support with reference ID: {trace_id}"
            ),
            trace_id=trace_id,
            was_blocked=True,
            model_used="none",
            input_tokens=0,
            output_tokens=0,
        )


llm_agent = LLMAgent()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format="%(message)s")
    passed = 0
    total = 4

    # Test 1: synthesize() with valid sanitised data
    try:
        resp = llm_agent.synthesize(
            user_prompt="What is my account balance?",
            sanitised_data=[{
                "full_name": "[PERSON_REDACTED]",
                "account_no": "4697196290011234",
                "balance": 142500.00,
                "account_type": "Savings",
            }],
            trace_id="test-trace-001",
            session_id="test-session",
        )
        assert not resp.was_blocked
        assert resp.answer and len(resp.answer) > 0
        print(f"[PASS] 1. synthesize() with data → answer={resp.answer[:80]}...")
        passed += 1
    except Exception as e:
        print(f"[FAIL] 1. synthesize() with data → {e}")

    # Test 2: synthesize() with empty sanitised_data
    try:
        resp = llm_agent.synthesize(
            user_prompt="What is my balance?",
            sanitised_data=[],
            trace_id="test-trace-002",
            session_id="test-session",
        )
        assert "could not find" in resp.answer.lower()
        print(f"[PASS] 2. synthesize() empty data → \"{resp.answer[:60]}...\"")
        passed += 1
    except Exception as e:
        print(f"[FAIL] 2. synthesize() empty data → {e}")

    # Test 3: handle_blocked()
    try:
        resp = llm_agent.handle_blocked(
            trace_id="test-trace-123",
            threat_type="PROMPT_OVERRIDE",
            session_id="test-session",
        )
        assert resp.was_blocked is True
        assert "test-trace-123" in resp.answer
        assert resp.input_tokens == 0
        print(f"[PASS] 3. handle_blocked() → blocked={resp.was_blocked}, has trace_id=True")
        passed += 1
    except Exception as e:
        print(f"[FAIL] 3. handle_blocked() → {e}")

    # Test 4: ask() general question
    try:
        answer = llm_agent.ask(
            user_prompt="What are your branch timings?",
            session_id="test-session",
        )
        assert answer and len(answer) > 0
        print(f"[PASS] 4. ask() → \"{answer[:60]}...\"")
        passed += 1
    except Exception as e:
        print(f"[FAIL] 4. ask() → {e}")

    print(f"\nResults: {passed}/{total} passed — {'ALL PASS' if passed == total else 'SOME FAILED'}")
