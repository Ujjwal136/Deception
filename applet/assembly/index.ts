// AegisAudit Applet (AssemblyScript)
// stores only event metadata / hashes, never raw pii

import { SHA256 } from "assemblyscript-crypto";

let entries = new Array<string>();

function esc(v: string): string {
  return v.replaceAll("\\", "\\\\").replaceAll('"', '\\"');
}

function parseField(entry: string, key: string): string {
  const needle = `\"${key}\":\"`;
  const start = entry.indexOf(needle);
  if (start < 0) return "";
  const from = start + needle.length;
  const end = entry.indexOf('"', from);
  if (end < 0) return "";
  return entry.substring(from, end);
}

function toHex(bytes: Uint8Array): string {
  const hex = "0123456789abcdef";
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    out += hex.charAt((b >> 4) & 0xf);
    out += hex.charAt(b & 0xf);
  }
  return out;
}

export function commit_event(
  trace_id: string,
  session_id: string,
  event_type: string,
  threat_type: string,
  weilchain_hash: string,
  timestamp: string
): string {
  const row =
    "{" +
    `\"trace_id\":\"${esc(trace_id)}\",` +
    `\"session_id\":\"${esc(session_id)}\",` +
    `\"event_type\":\"${esc(event_type)}\",` +
    `\"threat_type\":\"${esc(threat_type)}\",` +
    `\"weilchain_hash\":\"${esc(weilchain_hash)}\",` +
    `\"timestamp\":\"${esc(timestamp)}\"` +
    "}";

  entries.push(row);
  return trace_id;
}

export function get_all_entries(): string {
  if (entries.length == 0) return "[]";
  let out = "[";
  for (let i = entries.length - 1; i >= 0; i--) {
    out += entries[i];
    if (i != 0) out += ",";
  }
  out += "]";
  return out;
}

export function verify_entry(trace_id: string): string {
  for (let i = entries.length - 1; i >= 0; i--) {
    const row = entries[i];
    const t = parseField(row, "trace_id");
    if (t != trace_id) continue;

    const session_id = parseField(row, "session_id");
    const event_type = parseField(row, "event_type");
    const threat_type = parseField(row, "threat_type");
    const timestamp = parseField(row, "timestamp");
    const stored = parseField(row, "weilchain_hash");

    const payload = `${trace_id}|${session_id}|${event_type}|${threat_type}|${timestamp}`;
    const derived = toHex(SHA256.hash(Uint8Array.wrap(String.UTF8.encode(payload))));

    if (derived == stored) {
      return `{\"valid\":true,\"trace_id\":\"${esc(trace_id)}\"}`;
    }
    return `{\"valid\":false,\"tampered\":true,\"trace_id\":\"${esc(trace_id)}\"}`;
  }
  return `{\"error\":\"not found\",\"trace_id\":\"${esc(trace_id)}\"}`;
}

export function get_stats(): string {
  let ingress = 0;
  let egress = 0;

  for (let i = 0; i < entries.length; i++) {
    const evt = parseField(entries[i], "event_type");
    if (evt == "INGRESS_BLOCK") ingress++;
    if (evt == "EGRESS_REDACT") egress++;
  }

  return `{"total":${entries.length},"ingress_blocks":${ingress},"egress_redacts":${egress}}`;
}
