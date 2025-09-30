export default function Home() {
  return (
    <main style={{ padding: 24, fontFamily: 'ui-sans-serif' }}>
      <h1>Identity Threat Hunter</h1>
      <p>Analyst UI scaffold. Build is JS-only to keep CI simple.</p>
      <ul>
        <li>Uses Elastic index <code>ith-events</code>.</li>
        <li>Extend with pages/api for queries.</li>
      </ul>
    </main>
  );
}
