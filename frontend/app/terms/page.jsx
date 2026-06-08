import Link from "next/link";

export default function TermsPage() {
  return (
    <main className="shell">
      <section className="hero">
        <div className="badge">SafeGate Terms</div>
        <h1>Terms of Service</h1>
        <p className="lede">
          By using SafeGate, you agree to these Terms of Service. Please read them carefully.
        </p>

        <div className="statusCard" style={{ background: "rgba(110, 231, 255, 0.04)" }}>
          <h2 style={{ fontSize: "1.2rem", margin: "0 0 10px", color: "var(--accent)" }}>1. Permitted Use</h2>
          <p style={{ color: "var(--muted)", lineHeight: "1.6" }}>
            SafeGate is a security inspection tool designed to run static analyses on suspicious files and URLs. You agree to:
          </p>
          <ul style={{ color: "var(--muted)", lineHeight: "1.6", paddingLeft: "20px" }}>
            <li>Only scan links and files that you own, have created, or have explicit permission to inspect.</li>
            <li>Not use the service to host, distribute, or coordinate malware campaigns or any form of cyberattacks.</li>
            <li>Not attempt to bypass rate limits, perform DDoS attacks, or disrupt the backend servers.</li>
          </ul>
        </div>

        <div className="statusCard" style={{ background: "rgba(110, 231, 255, 0.04)", marginTop: "20px" }}>
          <h2 style={{ fontSize: "1.2rem", margin: "0 0 10px", color: "var(--accent)" }}>2. Disclaimer of Liability (No Warranty)</h2>
          <p style={{ color: "var(--muted)", lineHeight: "1.6" }}>
            <strong>SafeGate is provided "as is" without any warranties of any kind.</strong>
          </p>
          <ul style={{ color: "var(--muted)", lineHeight: "1.6", paddingLeft: "20px" }}>
            <li><strong>Not 100% Foolproof:</strong> Static analysis tools (YARA, ClamAV, ExifTool) check for known signatures and structural anomalies. They cannot guarantee that a clean result is 100% safe, nor that a flagged result is definitely malicious (false positives can occur).</li>
            <li><strong>User Responsibility:</strong> You are solely responsible for what you download and run on your devices. SafeGate, its developers, and hosts are not liable for any malware infections, data loss, hardware damage, or financial loss resulting from your use of this service.</li>
          </ul>
        </div>

        <div className="statusCard" style={{ background: "rgba(110, 231, 255, 0.04)", marginTop: "20px" }}>
          <h2 style={{ fontSize: "1.2rem", margin: "0 0 10px", color: "var(--accent)" }}>3. IP Logging and Law Enforcement</h2>
          <p style={{ color: "var(--muted)", lineHeight: "1.6" }}>
            To protect our systems and satisfy legal requirements, we log the IP addresses of all incoming requests and scans. If our service is used to inspect or download illegal or malicious material, we reserve the right to cooperate with legal authorities and share connection logs (which are deleted automatically after 30 days) to assist in investigations.
          </p>
        </div>

        <div style={{ marginTop: "32px", display: "flex", gap: "12px" }}>
          <Link href="/" className="ui-btn-legal">
            <strong>Back to Home</strong>
          </Link>
          <Link href="/privacy" className="ui-btn-legal" style={{ opacity: 0.8 }}>
            <strong>Privacy Policy</strong>
          </Link>
        </div>
      </section>
    </main>
  );
}
