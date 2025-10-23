// ith-ui/src/api/ingest.ts
export const INGEST_URL =
  (import.meta as any)?.env?.VITE_INGEST_URL ||
  (window as any)?.INGEST_URL ||
  "https://ith-ingestor-wcax3xalza-uc.a.run.app";

export async function sendEvent(ruleName: string, event: Record<string, any>) {
  const body = { rule_name: ruleName, event };
  const res = await fetch(`${INGEST_URL}/ingest`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`Ingest failed: ${res.status} ${text}`);
  }
  return res.json();
}
