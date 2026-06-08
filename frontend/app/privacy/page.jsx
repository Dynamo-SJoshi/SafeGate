import Link from "next/link";

export default function PrivacyPage() {
  return (
    <main className="shell">
      <section className="hero">
        <div className="badge">SafeGate Privacy</div>
        <h1>Privacy Policy</h1>
        <p className="lede">
          This Privacy Policy explains how SafeGate collects, uses, and safeguards user data.
        </p>

        <div className="statusCard" style={{ background: "rgba(110, 231, 255, 0.04)" }}>
          <h2 style={{ fontSize: "1.2rem", margin: "0 0 10px", color: "var(--accent)" }}>1. Data We Collect</h2>
          <p style={{ color: "var(--muted)", lineHeight: "1.6" }}>
            To inspect suspicious download links and files before you download them locally, SafeGate collects:
          </p>
          <ul style={{ color: "var(--muted)", lineHeight: "1.6", paddingLeft: "20px" }}>
            <li><strong>IP Address:</strong> The IP address of the client making the request is captured to prevent platform abuse, ensure rate-limiting, and satisfy legal compliance.</li>
            <li><strong>Scan Metadata:</strong> The file name, file size, SHA256 hash, and the inspected URL are stored to generate static report history.</li>
            <li><strong>Scanned File Binaries:</strong> Scanned files (either uploaded or followed via a download link) are temporarily stored on our backend server disk solely to run YARA rules, ClamAV, and ExifTool.</li>
          </ul>
        </div>

        <div className="statusCard" style={{ background: "rgba(110, 231, 255, 0.04)", marginTop: "20px" }}>
          <h2 style={{ fontSize: "1.2rem", margin: "0 0 10px", color: "var(--accent)" }}>2. Strict Data Retention</h2>
          <p style={{ color: "var(--muted)", lineHeight: "1.6" }}>
            We implement automatic, self-deleting thresholds to safeguard user data:
          </p>
          <ul style={{ color: "var(--muted)", lineHeight: "1.6", paddingLeft: "20px" }}>
            <li><strong>Scanned Files (Local Disk):</strong> The actual files analyzed are automatically and permanently deleted from our server disk <strong>15 minutes</strong> after the scan finishes.</li>
            <li><strong>Scan Reports & IP Records (Supabase Database):</strong> The record of your scan (including filenames, URLs, and your IP address) is stored securely in the cloud and is automatically, permanently deleted after <strong>30 days</strong>.</li>
          </ul>
        </div>

        <div className="statusCard" style={{ background: "rgba(110, 231, 255, 0.04)", marginTop: "20px" }}>
          <h2 style={{ fontSize: "1.2rem", margin: "0 0 10px", color: "var(--accent)" }}>3. Legal Compliance & Safety</h2>
          <p style={{ color: "var(--muted)", lineHeight: "1.6" }}>
            We log IP addresses to protect the service from being used for illegal activities. We will cooperate with legitimate law enforcement requests and subpoenas by providing access to the logged IPs and scan metadata within our 30-day retention window. We do not sell or share your data with any third-party advertisers.
          </p>
        </div>

        <div style={{ marginTop: "32px", display: "flex", gap: "12px" }}>
          <Link href="/" className="ui-btn-legal">
            <strong>Back to Home</strong>
          </Link>
          <Link href="/terms" className="ui-btn-legal" style={{ opacity: 0.8 }}>
            <strong>Terms of Service</strong>
          </Link>
        </div>
      </section>
    </main>
  );
}
