// ith-ui/src/features/actions/ActionButtons.tsx
import React from "react";
import { sendEvent } from "../../api/ingest";

export default function ActionButtons() {
  const [msg, setMsg] = React.useState<string>("");

  async function click(label: string, ruleName: string, e: Record<string, any>) {
    setMsg(`Sending ${label}...`);
    try {
      const r = await sendEvent(ruleName, e);
      setMsg(`OK ${label}: ${JSON.stringify(r)}`);
    } catch (err: any) {
      setMsg(`Error ${label}: ${err.message}`);
    }
  }

  return (
    <div className="flex flex-col gap-3">
      <button
        className="px-3 py-2 rounded bg-black text-white"
        onClick={() =>
          click("Canary Probe", "ITH - Honey Identity Probe", {
            "event.category": "authentication",
            "event.action": "honeypot_access",
            "event.type": "access",
            "event.outcome": "failure",
            "user.name": "canary-attacker",
            "source.ip": "203.0.113.10",
            "geo.src": "RU-MOW"
          })
        }
      >
        Canary Probe
      </button>

      <button
        className="px-3 py-2 rounded bg-black text-white"
        onClick={() =>
          click("Credential Stuffing", "ITH - Credential Stuffing", {
            "event.category": "authentication",
            "event.action": "password_guess",
            "event.type": "denied",
            "event.outcome": "failure",
            "user.name": "alice",
            "source.ip": "8.8.8.8",
            "geo.src": "BR-SP",
            "geo.prev": "US-NY"
          })
        }
      >
        Credential Stuffing
      </button>

      <button
        className="px-3 py-2 rounded bg-black text-white"
        onClick={() =>
          click("MFA Bypass", "ITH - MFA Bypass Attempt", {
            "event.category": "authentication",
            "event.action": "mfa_bypass",
            "event.type": "failure",
            "event.outcome": "failure",
            "user.name": "bob",
            "source.ip": "4.4.4.4",
            "geo.src": "RU-MOW",
            "geo.prev": "DE-BE"
          })
        }
      >
        MFA Bypass
      </button>

      <button
        className="px-3 py-2 rounded bg-black text-white"
        onClick={() =>
          click("Login", "ITH - AI Enriched Login", {
            "event.category": "authentication",
            "event.action": "login",
            "event.type": "start",
            "event.outcome": "success",
            "user.name": "sanity_user",
            "source.ip": "1.1.1.1",
            "destination.ip": "10.0.0.5",
            "geo.src": "US-CA",
            "geo.prev": "IN-KA"
          })
        }
      >
        Enriched Login
      </button>

      {msg && <div className="text-sm">{msg}</div>}
    </div>
  );
}
