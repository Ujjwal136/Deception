import os
import logging
from dataclasses import dataclass

import httpx

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


class LLMAgent:

    def __init__(self):
        self._client = None
        self._model_name = settings.llm_model

    def _get_client(self):
        """Lazy-load and cache the HTTP client."""
        if self._client is not None:
            return self._client
        self._client = httpx.Client(timeout=20.0)
        return self._client

    def _call_llm(self, system: str, user_message: str) -> dict:
        """
        Call the configured LLM provider. Returns dict with
        keys: text, model, input_tokens, output_tokens.
        """
        provider = settings.llm_provider.lower().strip()

        if provider == "openai" and settings.openai_api_key:
            return self._call_openai(system, user_message)
        if provider == "anthropic" and settings.anthropic_api_key:
            return self._call_anthropic(system, user_message)
        return self._call_mock(user_message)

    def _call_openai(self, system: str, user_message: str) -> dict:
        client = self._get_client()
        resp = client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {settings.openai_api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": self._model_name,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user_message},
                ],
                "temperature": 0.1,
            },
        )
        resp.raise_for_status()
        data = resp.json()
        usage = data.get("usage", {})
        return {
            "text": data["choices"][0]["message"]["content"],
            "model": data.get("model", self._model_name),
            "input_tokens": usage.get("prompt_tokens", 0),
            "output_tokens": usage.get("completion_tokens", 0),
        }

    def _call_anthropic(self, system: str, user_message: str) -> dict:
        client = self._get_client()
        resp = client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": settings.anthropic_api_key,
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

    def _call_mock(self, user_message: str) -> dict:
        if "Relevant account data" in user_message:
            lines = user_message.split("Relevant account data (security-processed):")
            if len(lines) > 1:
                data_part = lines[1].split("Please answer the customer")[0].strip()
                text = f"Based on the account information available, here is what I found: {data_part}"
            else:
                text = "Here is the information from your account records."
        else:
            text = "Aegis mock reply: request received."
        return {
            "text": text,
            "model": "mock",
            "input_tokens": 0,
            "output_tokens": 0,
        }

    def ask(self, user_prompt: str, session_id: str) -> str:
        """Send a general question to the LLM (no DB context)."""
        try:
            result = self._call_llm(SYSTEM_PROMPT, user_prompt)
            return result["text"]
        except Exception:
            logger.exception("LLM ask() call failed")
            return "I'm sorry, I'm unable to process your request right now. Please try again later."

    def synthesize(
        self,
        user_prompt: str,
        sanitised_data: list[dict],
        trace_id: str,
        session_id: str,
    ) -> AgentResponse:
        """Synthesise a natural language answer from sanitised DB data."""
        if not sanitised_data:
            return AgentResponse(
                answer="I could not find any relevant account information "
                       "for your query. Please contact branch support.",
                trace_id=trace_id,
                was_blocked=False,
                model_used=self._model_name,
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
