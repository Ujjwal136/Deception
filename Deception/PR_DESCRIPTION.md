PR Title
Submission #Deception

PR Description
Project summary:
Aegis AI Firewall is a zero-trust middleware for banking workflows. It blocks prompt attacks, prevents PII leakage with redaction/FPE, and records tamper-evident audit events.

Run/Test instructions:
1. pip install -r requirements.txt
2. python -m uvicorn main:app --host 0.0.0.0 --port 8000
3. Open http://localhost:8000
4. Verify clean query, blocked attack query, and audit endpoints:
   - /api/v1/audit/ledger
   - /api/v1/audit/stats
