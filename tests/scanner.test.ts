import { scanContent, analyzeUrl, computeMlPrediction, detectLanguage } from "../src/scanner";

function assert(condition: boolean, msg: string) {
  if (!condition) {
    console.error(`❌ FAILED: ${msg}`);
    process.exit(1);
  }
  console.log(`✅ PASSED: ${msg}`);
}

console.log("--- Running PhishGuard AI Scanner Test Suite ---");

// Test 1: Benign message stays low
const r1 = scanContent("Project meeting is tomorrow at 10 AM in the seminar hall. Bring your notes.");
assert(r1.risk_score < 25, "Benign message score is low (< 25)");
assert(r1.risk_level === "low", "Benign message risk level is low");

// Test 2: Tanglish EB Scam is detected as critical
const r2 = scanContent("TNEB EB Alert: Ungal veetu electricity line inre 10 PM cut aagidum. Udane EB Officer call panni bill pay pannunga.");
assert(r2.risk_score >= 70, "Tanglish EB bill cut scam is flagged as Critical / High");
assert(r2.findings.some(f => f.type === "india_electricity_bill_scam" || f.type.includes("tanglish")), "Flagged India EB or Tanglish scam rule");

// Test 3: Tamil Bank KYC
const r3 = scanContent("வங்கி கணக்கு முடக்கப்படும்! உங்கள் எஸ்பிஐ வங்கி கேஒய்சி முடிவடைந்தது. உடனே பான் கார்டு இணைக்கவும்.");
assert(r3.breakdown.detected_language === "Tamil", "Detected Tamil script language");
assert(r3.findings.some(f => f.type.includes("tanglish") || f.type.includes("pan")), "Flagged Tamil KYC / account threat rule");

// Test 4: Fake Journal Website
const r4 = scanContent("https://nature-openaccess-journal.org/submit-manuscript", "journal");
assert(r4.findings.some(f => f.type === "fake_journal_website" || f.type.includes("brand")), "Cloned journal website flagged");

// Test 5: UPI Cashback Fraud
const r5 = scanContent("Enter your UPI PIN to claim ₹2500 cashback reward directly into your bank account.");
assert(r5.findings.some(f => f.type === "india_upi_payment_fraud"), "UPI PIN collect fraud flagged");

// Test 6: Adversarial Zero-Width character evasion
const r6 = scanContent("URGENT\u200B! Your acc\u200Bount has been susp\u200Bended.");
assert(r6.findings.some(f => f.type === "adversarial_zero_width"), "Zero-width evasion attack detected and stripped");

// Test 7: Private IP SSRF
const u7 = analyzeUrl("http://192.168.1.1/admin-login");
assert(u7.some(f => f.type === "private_ip_ssrf"), "Private IP SSRF target flagged");

// Test 8: ML Classifier Prediction
const ml8 = computeMlPrediction("Urgent! Your account has been suspended. Verify your password and otp immediately.");
assert(ml8.probability > 0.8, "ML model predicts high probability (> 80%) for phishing phrasing");
assert(ml8.topTerms.length > 0, "Top TF-IDF predictive terms returned as explainable evidence");

console.log("--- All 8 Scanner Tests Passed Successfully! ---");
