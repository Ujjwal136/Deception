const { stdin, stdout } = process;

function write(obj) {
  stdout.write(JSON.stringify(obj));
}

async function withTimeout(promise, ms) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error("timeout")), ms);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function readStdin() {
  return new Promise((resolve) => {
    let data = "";
    stdin.setEncoding("utf8");
    stdin.on("data", (chunk) => (data += chunk));
    stdin.on("end", () => resolve(data));
  });
}

async function main() {
  try {
    const raw = await readStdin();
    const cmd = JSON.parse(raw || "{}");

    const priv = process.env.WEIL_PRIVATE_KEY;
    const applet = process.env.WEIL_APPLET_ADDRESS;
    if (!priv || !applet) {
      return write({ error: "weilchain unavailable", fallback: true });
    }

    let sdk;
    try {
      sdk = require("@weilliptic/weil-sdk");
    } catch (e) {
      return write({ error: `bridge sdk load failed: ${e.message}`, fallback: true });
    }

    const WeilWallet = sdk.WeilWallet || sdk.default?.WeilWallet;
    if (!WeilWallet) {
      return write({ error: "bridge sdk incompatible", fallback: true });
    }

    const wallet = new WeilWallet({ privateKey: priv });

    if (cmd.action === "commit") {
      const d = cmd.data || {};
      const res = await withTimeout(
        wallet.callAppletMutate(applet, "commit_event", [
          d.trace_id,
          d.session_id,
          d.event_type,
          d.threat_type,
          d.weilchain_hash,
          d.timestamp,
        ]),
        5000
      );
      return write({ ok: true, result: res });
    }

    if (cmd.action === "get_all") {
      const res = await withTimeout(wallet.callAppletQuery(applet, "get_all_entries", []), 5000);
      return write({ ok: true, result: res });
    }

    if (cmd.action === "verify") {
      const res = await withTimeout(wallet.callAppletQuery(applet, "verify_entry", [cmd.trace_id]), 5000);
      return write({ ok: true, result: res });
    }

    if (cmd.action === "stats") {
      const res = await withTimeout(wallet.callAppletQuery(applet, "get_stats", []), 5000);
      return write({ ok: true, result: res });
    }

    return write({ error: "unknown action", fallback: true });
  } catch (e) {
    return write({ error: String(e.message || e), fallback: true });
  }
}

main();
