const { chromium } = require('playwright');
const path = require('path');
const fs = require('fs');

async function main() {
  const filePath = process.argv[2];
  if (!filePath) {
    console.log(JSON.stringify({ error: "No HTML file specified" }));
    process.exit(1);
  }

  const absolutePath = path.resolve(filePath);
  if (!fs.existsSync(absolutePath)) {
    console.log(JSON.stringify({ error: `File not found: ${absolutePath}` }));
    process.exit(1);
  }

  let browser;
  try {
    browser = await chromium.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
    const page = await browser.newPage();
    
    // Navigate to local file URL
    await page.goto(`file://${absolutePath}`, { timeout: 5000, waitUntil: 'domcontentloaded' });
    
    // Run DOM checks
    const analysis = await page.evaluate(() => {
      const alerts = [];
      const findings = {};
      
      // Check for password inputs
      const pwdFields = document.querySelectorAll('input[type="password"]');
      if (pwdFields.length > 0) {
        alerts.push(`Credential Harvesting Form: Found ${pwdFields.length} password field(s) on the page.`);
        findings.has_password = true;
      }
      
      // Check for form action targets
      const forms = document.querySelectorAll('form');
      const externalForms = [];
      forms.forEach(form => {
        const action = form.getAttribute('action') || '';
        if (action.startsWith('http://') || action.startsWith('https://')) {
          externalForms.push(action);
          alerts.push(`Suspicious Form Action: Form submits credentials directly to an external server (${action}).`);
        }
      });
      if (externalForms.length > 0) {
        findings.external_forms = externalForms;
      }
      
      // Check for suspicious redirection scripts
      const scripts = document.querySelectorAll('script');
      let hasRedirect = false;
      let hasObfuscation = false;
      
      scripts.forEach(script => {
        const content = script.textContent || '';
        if (content.includes('window.location') || content.includes('location.replace') || content.includes('location.href')) {
          hasRedirect = true;
        }
        if (content.includes('eval(') || content.includes('unescape(') || content.includes('atob(')) {
          hasObfuscation = true;
        }
      });
      
      if (hasRedirect) {
        alerts.push("Automated Redirection: Script contains auto-redirect window.location behaviors.");
        findings.has_redirect = true;
      }
      if (hasObfuscation) {
        alerts.push("Obfuscated JavaScript Code: Page contains scripting evasion/obfuscation tags (eval, unescape, atob).");
        findings.has_obfuscation = true;
      }
      
      return { alerts, findings };
    });
    
    console.log(JSON.stringify({
      success: true,
      behavior_alerts: analysis.alerts,
      findings: analysis.findings
    }));
    
  } catch (err) {
    console.log(JSON.stringify({ success: false, error: err.message }));
  } finally {
    if (browser) {
      await browser.close();
    }
  }
}

main();
