export const metadata = {
  title: 'tukuyomi Next.js example',
  description: 'Next.js app behind tukuyomi',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body style={{ fontFamily: 'ui-sans-serif, system-ui', margin: 0, padding: 24 }}>
        {children}
      </body>
    </html>
  );
}
