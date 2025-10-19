import { useRouter } from "next/router";

export default function HoneyToggle() {
  const router = useRouter();
  const isHoney = router.query?.honey === "1";

  const toggle = () => {
    const q = new URLSearchParams(window.location.search);
    if (isHoney) { q.delete("honey"); } else { q.set("honey", "1"); }
    const next = `${window.location.pathname}?${q.toString()}`;
    router.push(next);
  };

  return (
    <button
      onClick={toggle}
      className="px-3 py-2 rounded-2xl shadow text-sm border"
      title="Filter honeypot events"
    >
      {isHoney ? "HONEY: ON" : "HONEY: OFF"}
    </button>
  );
}
