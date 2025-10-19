export default async function handler(req, res) {
  try {
    const ingestUrl = process.env.INGEST_URL;
    if (!ingestUrl) throw new Error("INGEST_URL env var is not set on ith-ui");

    const type = (req.query.type || "canary_user_probe").toString(); // canary_user_probe | canary_token_use
    const ruleName = type === "canary_token_use"
      ? "ITH – Honey Token Used"
      : "ITH – Honey Canary User Probe";

    const body = {
      "@timestamp": new Date().toISOString(),
      event: { category: "honeypot", action: type, kind: "event", module: "honey_identity" },
      user: { name: "decoy_user" },
      source: { ip: "203.0.113.50" },
      "risk.score": 99,
      "risk.reason": `Honey event: ${type}`,
      "raw.rule.name": ruleName
    };

    const r = await fetch(ingestUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body)
    });

    const text = await r.text();
    res.status(200).json({ ok: r.ok, status: r.status, type, ingestUrl, response: text });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message, stack: e.stack });
  }
}
