import { useState } from "react";

const S = {
  page: { padding: 28, fontFamily: "system-ui,-apple-system,Segoe UI,Roboto,Arial" },
  h1: { fontSize: 38, margin: "0 0 6px" },
  lead: { fontSize: 15, color: "#374151", marginBottom: 16 },
  card: { border: "1px solid #e5e7eb", borderRadius: 14, padding: 16, marginTop: 16, background: "#fff" },
  sectionTitle: { fontWeight: 700, marginBottom: 8 },
  grid: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 12, marginTop: 12 },
  btn: {
    padding: "12px 16px",
    borderRadius: 12,
    border: "1px solid #e5e7eb",
    background: "linear-gradient(180deg,#fff,#f7f7f7)",
    cursor: "pointer",
    boxShadow: "0 1px 0 rgba(0,0,0,0.04)",
    transition: "all .15s ease",
    textAlign: "left",
    fontSize: 14,
  },
  btnPrimary: {
    padding: "12px 16px",
    borderRadius: 12,
    border: "1px solid #2563eb",
    background: "#2563eb",
    color: "#fff",
    cursor: "pointer",
    boxShadow: "0 2px 6px rgba(37,99,235,.2)",
    transition: "all .15s ease",
    fontSize: 14,
  },
  small: { fontSize: 12, color: "#6b7280", marginTop: 8 },
  pre: {
    background: "#0b1020",
    color: "#d7e0ff",
    padding: 12,
    borderRadius: 10,
    fontSize: 12,
    overflowX: "auto",
    minHeight: 120,
    whiteSpace: "pre-wrap",
    wordBreak: "break-word",
  },
  pill: {
    display: "inline-block",
    padding: "2px 8px",
    fontSize: 12,
    borderRadius: 999,
    background: "#eef2ff",
    color: "#1f2937",
    border: "1px solid #e5e7eb",
    marginLeft: 8,
  },
};

const SCENARIOS = [
  "impossible_travel",
  "mfa_bypass",
  "brute_force_then_success",
  "rare_country",
  "credential_stuffing",
  "asn_change",
  "privilege_escalation",
];

export default function Home() {
  const [log, setLog] = useState("");

  const add = (m) =>
    setLog((p) => `${p}${p ? "\n" : ""}${typeof m === "string" ? m : JSON.stringify(m, null, 2)}`);

  const hover = (e, up = true) => {
    e.currentTarget.style.transform = up ? "translateY(-1px)" : "translateY(0)";
    e.currentTarget.style.boxShadow = up
      ? "0 2px 10px rgba(0,0,0,.06)"
      : "0 1px 0 rgba(0,0,0,.04)";
  };

  async function triggerScenario(s) {
    try {
      const r = await fetch(`/api/trigger?scenario=${encodeURIComponent(s)}`, { method: "POST" });
      const j = await r.json().catch(() => ({}));
      add(`Scenario: ${s} → ${r.status} ${r.statusText}`);
      if (Object.keys(j).length) add(j);
    } catch (e) {
      add(`Error: ${e?.message || String(e)}`);
    }
  }

  async function triggerAll() {
    for (const s of SCENARIOS) {
      // eslint-disable-next-line no-await-in-loop
      await triggerScenario(s); // sequential for readable output
    }
  }

  async function triggerHoney(type) {
    try {
      const r = await fetch(`/api/trigger-honey?type=${encodeURIComponent(type)}`, { method: "POST" });
      const j = await r.json().catch(() => ({}));
      add(`Honey: ${type} → ${r.status} ${r.statusText}`);
      if (Object.keys(j).length) add(j);
    } catch (e) {
      add(`Error: ${e?.message || String(e)}`);
    }
  }

  async function triggerQuantum() {
    try {
      const r = await fetch(`/api/trigger-quantum`, { method: "POST" });
      const j = await r.json().catch(() => ({}));
      add(`Quantum risk check → ${r.status} ${r.statusText}`);
      if (Object.keys(j).length) add(j);
    } catch (e) {
      add(`Error: ${e?.message || String(e)}`);
    }
  }

  return (
    <main style={S.page}>
      <h1 style={S.h1}>Identity Threat Hunter</h1>
      <p style={S.lead}>
        Analyst UI to generate synthetic identity events and validate Elastic detections.
        <span style={S.pill}>Data view: ith-events*</span>
      </p>

      {/* Baseline */}
      <section style={S.card}>
        <div style={S.sectionTitle}>Baseline Scenarios</div>
        <div style={S.grid}>
          {SCENARIOS.map((s) => (
            <button
              key={s}
              style={S.btn}
              onMouseEnter={(e) => hover(e, true)}
              onMouseLeave={(e) => hover(e, false)}
              onClick={() => triggerScenario(s)}
              title={s}
            >
              {s.replace(/_/g, " ")}
            </button>
          ))}
          <button
            style={S.btnPrimary}
            onMouseEnter={(e) => hover(e, true)}
            onMouseLeave={(e) => hover(e, false)}
            onClick={triggerAll}
            title="Run all baseline scenarios"
          >
            ▶ Trigger All
          </button>
        </div>
        <div style={S.small}>Rules run every minute with a 5-minute lookback.</div>
      </section>

      {/* Honey */}
      <section style={S.card}>
        <div style={S.sectionTitle}>Honey Identity</div>
        <div style={S.grid}>
          <button
            style={S.btn}
            onMouseEnter={(e) => hover(e, true)}
            onMouseLeave={(e) => hover(e, false)}
            onClick={() => triggerHoney("canary_user_probe")}
          >
            Canary User Probe
          </button>
          <button
            style={S.btn}
            onMouseEnter={(e) => hover(e, true)}
            onMouseLeave={(e) => hover(e, false)}
            onClick={() => triggerHoney("canary_token_use")}
          >
            Canary Token Use
          </button>
        </div>
        <div style={S.small}>Emits <code>event.category: honeypot</code> with high risk.</div>
      </section>

      {/* Quantum */}
      <section style={S.card}>
        <div style={S.sectionTitle}>Quantum Guardian</div>
        <div style={S.grid}>
          <button
            style={S.btn}
            onMouseEnter={(e) => hover(e, true)}
            onMouseLeave={(e) => hover(e, false)}
            onClick={triggerQuantum}
          >
            Quantum Risk Check
          </button>
        </div>
        <div style={S.small}>
          Emits <code>qes.score</code> and <code>event.module: quantum_guardian</code>.
        </div>
      </section>

      {/* Output */}
      <section style={S.card}>
        <div style={S.sectionTitle}>Output</div>
        <pre style={S.pre}>{log || "Responses will appear here..."}</pre>
      </section>
    </main>
  );
}
