import Script from "next/script";
import "./globals.css";

export const metadata = {
  title: "SafeGate",
  description: "Safe download and file inspection platform",
};

export default function RootLayout({ children }) {
  const cfToken = process.env.NEXT_PUBLIC_CLOUDFLARE_TOKEN;

  return (
    <html lang="en">
      <body>
        {cfToken && (
          <Script
            src="https://static.cloudflareinsights.com/beacon.min.js"
            data-cf-beacon={JSON.stringify({ token: cfToken })}
            strategy="afterInteractive"
          />
        )}
        {children}
      </body>
    </html>
  );
}


