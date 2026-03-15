from __future__ import annotations

import logging

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from agents import llm_agent, banking_db, managing_agent as ma
from agents.managing_agent import QueryResult
from config import settings
from firewall.interceptor import Interceptor
from firewall.redactor import Redactor
from firewall.sentinel import Sentinel
from firewall.weilchain import Weilchain
from models.schemas import (
    ChatRequest,
    ChatResponse,
    FirewallEgressRequest,
    FirewallEgressResponse,
    FirewallIngressRequest,
    FirewallIngressResponse,
    HealthResponse,
)


app = FastAPI(title=settings.app_name)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("aegis")

sentinel = Sentinel()
redactor = Redactor()
weilchain = Weilchain(db_path=settings.weilchain_db_path)
interceptor = Interceptor(sentinel, redactor, weilchain)

sentinel_loaded = sentinel.load()
redactor_loaded = redactor.load()


@app.on_event("startup")
def log_startup_status() -> None:
    logger.info("Aegis Firewall starting...")

    try:
        layer_a = sentinel.layer_a_loaded
        logger.info("Sentinel Layer A (SGD) - %s", "LOADED" if layer_a else "NOT AVAILABLE (fallback mode)")
    except Exception:
        logger.exception("Sentinel Layer A status check failed")

    try:
        layer_b = sentinel.layer_b_loaded
        logger.info("Sentinel Layer B (DistilBERT) - %s", "LOADED" if layer_b else "NOT AVAILABLE (fallback mode)")
    except Exception:
        logger.exception("Sentinel Layer B status check failed")

    try:
        has_ner = redactor.ner_model is not None
        logger.info("Redactor NER (DistilBERT) - %s", "LOADED" if has_ner else "NOT AVAILABLE (fallback mode)")
    except Exception:
        logger.exception("Redactor NER status check failed")

    logger.info("Redactor Regex - LOADED")

    try:
        from firewall.fpe_engine import _get_numeric_cipher

        _get_numeric_cipher()
        logger.info("FPE Engine - LOADED")
    except Exception:
        logger.exception("FPE Engine failed to initialize")

    try:
        _ = weilchain.stats()
        wc = weilchain.connectivity()
        logger.info("Weilchain - %s (%s)", wc["status"].upper(), wc["backend"])
    except Exception:
        logger.exception("Weilchain status check failed")

    try:
        rows = banking_db.execute_query("SELECT customer_id FROM customers LIMIT 100")
        logger.info("Banking DB - LOADED (%d customers)", len(rows))
    except Exception:
        logger.exception("Banking DB status check failed")

    logger.info("Aegis Firewall ready")


@app.post("/api/v1/chat", response_model=ChatResponse)
def chat(payload: ChatRequest) -> ChatResponse:
    logger.info("[chat] session=%s prompt=%s", payload.session_id, payload.message)
    if not payload.message.strip():
        return ChatResponse(
            trace_id="none",
            verdict="CLEAN",
            response="Please enter a valid banking query.",
            redactions=[],
        )
    ingress = interceptor.ingress(payload.message, payload.session_id)
    logger.info("[ingress] trace=%s verdict=%s", ingress["trace_id"], ingress["verdict"])
    if ingress["verdict"] == "BLOCKED":
        logger.warning("[blocked] trace=%s threat=%s", ingress["trace_id"], ingress["threat_type"])
        blocked_resp = llm_agent.handle_blocked(
            trace_id=ingress["trace_id"],
            threat_type=ingress["threat_type"],
            session_id=payload.session_id,
        )
        return ChatResponse(
            trace_id=ingress["trace_id"],
            verdict="BLOCKED",
            response=blocked_resp.answer,
            redactions=[],
        )

    result = ma.plan_and_execute(ingress["sanitized_prompt"])
    if not result.success:
        logger.warning("[db] trace=%s error=%s", ingress["trace_id"], result.error)
        raw_db = []
    else:
        raw_db = result.raw_data
    logger.info("[db] trace=%s rows=%d", ingress["trace_id"], len(raw_db))
    egress = interceptor.egress(ingress["trace_id"], payload.session_id, str(raw_db))
    logger.info("[egress] trace=%s verdict=%s redactions=%s", ingress["trace_id"], egress["verdict"], egress["redactions"])
    agent_resp = llm_agent.synthesize(
        user_prompt=payload.message,
        sanitised_data=raw_db,
        trace_id=ingress["trace_id"],
        session_id=payload.session_id,
    )

    return ChatResponse(
        trace_id=ingress["trace_id"],
        verdict=egress["verdict"],
        response=agent_resp.answer,
        redactions=egress["redactions"],
    )


@app.post("/api/v1/firewall/ingress", response_model=FirewallIngressResponse)
def ingress(payload: FirewallIngressRequest) -> FirewallIngressResponse:
    result = interceptor.ingress(payload.prompt, payload.session_id)
    return FirewallIngressResponse(**result)


@app.post("/api/v1/firewall/egress", response_model=FirewallEgressResponse)
def egress(payload: FirewallEgressRequest) -> FirewallEgressResponse:
    result = interceptor.egress(payload.trace_id, payload.session_id, str(payload.payload))
    return FirewallEgressResponse(**result)


@app.get("/api/v1/audit/ledger")
def ledger() -> list[dict]:
    return weilchain.get_all()


@app.get("/api/v1/audit/verify/{trace_id}")
def verify(trace_id: str) -> dict:
    result = weilchain.verify(trace_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@app.get("/api/v1/audit/stats")
def audit_stats() -> dict:
    stats = weilchain.stats()
    wc = weilchain.connectivity()
    stats["storage"] = "on-chain" if wc.get("status") == "online" else "offline-fallback"
    return stats


@app.get("/api/v1/audit/verify_all")
def verify_all() -> dict:
    return weilchain.verify_all()


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        sentinel_loaded=sentinel_loaded,
        redactor_loaded=redactor_loaded,
        weilchain=weilchain.connectivity(),
    )


app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
