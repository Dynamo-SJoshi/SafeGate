import "./globals.css";

export const metadata = {
  title: "SafeGate",
  description: "Safe download and file inspection platform",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}

