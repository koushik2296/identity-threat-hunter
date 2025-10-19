import { useEffect, useState } from "react";
import HoneyToggle from "../components/HoneyToggle";

type Query = { kql: string };

export default function HoneyPage() {
  const [query, setQuery] = useState<Query | null>(null);

  useEffect(() => {
    fetch(`/api/events${window.location.search}`)
      .then(r => r.json())
      .then(setQuery)
      .catch(() => setQuery({ kql: "error" } as Query));
  }, [typeof window === "undefined" ? "" : window.location.search]);

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Honey Identity Events</h1>
        <HoneyToggle />
      </div>
      <div className="p-4 rounded-xl border">
        <div className="text-sm opacity-70">Effective KQL</div>
        <pre className="text-sm">{query?.kql ?? "..."}</pre>
      </div>
      <p className="text-sm opacity-70">
        Replace this page&#39;s fetch with your Elastic search and render results in your existing table.
      </p>
    </div>
  );
}
