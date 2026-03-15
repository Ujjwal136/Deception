## AegisAudit — Weilliptic Applet

AegisAudit is a Weilliptic Applet that stores tamper-evident
security event records on WeilChain. Every blocked attack and
PII redaction in Aegis produces an immutable on-chain receipt —
cryptographically verifiable without storing any raw PII.
Directly implements the Weilliptic Receipts concept.

## Build
  cd applet
  npm install
  npm run asbuild

## Deploy to WeilChain
  wcli wallet create
  # Add private key to WEIL_PRIVATE_KEY in .env

  wcli deploy build/aegis_audit.wasm
  # Add applet address to WEIL_APPLET_ADDRESS in .env

## Interact via CLI
  wcli call <address> get_all_entries
  wcli call <address> verify_entry <trace_id>
  wcli call <address> get_stats

## Weilliptic Products Used
  WeilChain  — audit entries stored immutably on-chain
  Receipts   — every security event is a verifiable receipt
  Cerebrum   — Aegis two-agent pipeline on WeilChain
  Provable   — verify_entry() proves events occurred
