export default async function handler(req, res) {
  try {
    const ingestUrl = process.env.INGEST_URL;
    if (!ingestUrl) throw new Error("INGEST_URL env var is not set on ith-ui");

    const scenario = (req.query.scenario || "").toString();
    if (!scenario) throw new Error("Missing 'scenario' query param");

    const body = {
      "@timestamp": new Date().toISOString(),
      event: { category: "authentication", action: scenario, kind: "event" },
      "raw.rule.name": `ITH – ${scenario.replace(/_/g, " ")}`,
      user: { name: "judge_demo" },
      source: { ip: "198.51.100.60" },
      "risk.score": 90
    };

    const r = await fetch(ingestUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body)
    });

    const text = await r.text();
    res.status(200).json({ ok: r.ok, status: r.status, scenario, ingestUrl, response: text });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message, stack: e.stack });
  }
}
