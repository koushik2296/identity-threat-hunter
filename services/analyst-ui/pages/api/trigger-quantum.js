export default async function handler(req, res) {
  try {
    const ingestUrl = process.env.INGEST_URL;
    if (!ingestUrl) throw new Error("INGEST_URL env var is not set on ith-ui");

    const qesScore = Number(req.query.qes || 85); // let you override for testing

    const body = {
      "@timestamp": new Date().toISOString(),
      event: {
        category: "token",
        action: "quantum_exposure_assessed",
        kind: "event",
        module: "quantum_guardian"
      },
      identity: { token_alg: "RS256", key_bits: 2048, rotation_days: 120, device_bound: false },
      qes: { score: qesScore },
      "risk.score": 90,
      "risk.reason": `Quantum risk test, QES=${qesScore}`,
      "raw.rule.name": "ITH – Quantum Guardian (QES ≥ 80)"
    };

    const r = await fetch(ingestUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body)
    });

    const text = await r.text();
    res.status(200).json({ ok: r.ok, status: r.status, qes: qesScore, ingestUrl, response: text });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message, stack: e.stack });
  }
}
