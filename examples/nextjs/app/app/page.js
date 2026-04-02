export default function HomePage() {
  return (
    <main>
      <h1>tukuyomi + Next.js</h1>
      <p>Try XSS/SQLi payloads via query string to verify WAF blocking.</p>
      <p>Example: <code>?q=&lt;script&gt;alert(1)&lt;/script&gt;</code></p>
    </main>
  );
}
