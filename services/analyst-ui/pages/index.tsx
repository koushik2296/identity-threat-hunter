export default function Home() {
  return (
    <main style={{padding:24, fontFamily:'ui-sans-serif'}}>
      <h1>Identity Threat Hunter</h1>
      <p>Simple analyst UI. Configure Elastic endpoint in environment and extend pages/api as needed.</p>
      <ul>
        <li>View recent events and incident summaries (extend implementation).</li>
        <li>Works with Elastic index <code>ith-events</code>.</li>
      </ul>
    </main>
  );
}
