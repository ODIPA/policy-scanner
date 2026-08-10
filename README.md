# ODIPA Privacy Policy Scanner

**ODIPA Open-Source Privacy Tool** · [odipa.org](https://odipa.org) · MIT License

Fetches a privacy policy from a URL or local file, analyzes it using keyword and pattern matching across six weighted categories, detects red flags, and produces a graded A–F report with GDPR and CCPA compliance notes.

---

## Development Transparency

This tool was developed by ODIPA with AI-assisted development and is maintained by ODIPA, which accepts community contributions and is responsible for the accuracy of its scoring methodology.

---

## Quick Start

```bash
pip install requests beautifulsoup4 lxml

# Scan from URL
python policy_scanner.py https://example.com/privacy

# Scan from local file
python policy_scanner.py --file policy.txt

# Save report
python policy_scanner.py https://example.com/privacy --output report.json
```

---

## Scoring Methodology

Policies are scored across six categories with weighted contributions to a 0–100 overall score:

| Category | Weight | What it measures |
|---|---|---|
| Data Collection | 20% | Whether the policy clearly states what data is collected and in what categories |
| Data Sharing | 20% | Transparency about third-party sharing, whether data is sold, law enforcement disclosures |
| User Rights | 20% | Whether access, deletion, correction, portability, and opt-out rights are disclosed |
| Retention | 15% | Whether specific retention periods are stated and deletion processes described |
| Legal Basis | 15% | Whether GDPR legal bases are disclosed and specific privacy laws referenced |
| Contact | 10% | Whether a privacy contact, DPO, and physical address are provided |

Grades: A (90–100), B (75–89), C (60–74), D (45–59), F (below 45)

---

## Red Flag Detection

The scanner detects eight categories of red flags with severity ratings:

| Flag | Severity | GDPR | CCPA |
|---|---|---|---|
| Data selling language | Critical | ✓ | ✓ |
| Indefinite retention | High | ✓ | |
| Opt-out rights denied | High | ✓ | ✓ |
| Biometric data collection | High | ✓ | ✓ |
| Data broker / ad network sharing | High | ✓ | ✓ |
| Precise location tracking | Medium | ✓ | ✓ |
| Children's data | Medium | ✓ | |
| Unilateral policy changes without notice | Medium | | |

---

## Legal Implications

**Before using this tool, read this section carefully.**

### Accuracy limitations
This scanner uses keyword and pattern matching. It is **not a legal compliance tool** and its output is not legally authoritative. Specifically:

- A high score does not mean a policy is legally compliant. A policy can use all the right keywords and still be non-compliant in practice.
- A low score does not mean a policy is non-compliant. Unusual phrasing or structure may cause legitimate disclosures to be missed.
- Red flag detection is probabilistic. The word "sell" in a policy does not always mean data is being sold, context matters and the scanner cannot evaluate context the way a lawyer can.
- The scanner evaluates written disclosures only. It cannot assess whether actual data practices match the policy.

### Using results in legal or regulatory contexts
Do not submit scanner output as evidence of compliance or non-compliance in regulatory filings, litigation, or audit reports without independent legal review. ODIPA is a nonprofit education organization, not a law firm, and this tool does not constitute legal advice.

### Scanning third-party policies
Privacy policies are publicly published documents. Accessing and analyzing them programmatically is generally lawful. However:

- Some sites' Terms of Service prohibit automated access. Review the target site's ToS before conducting bulk scanning.
- In the EU, automated processing of publicly available documents may still require a documented lawful basis under GDPR Article 6 if that processing could be linked to identifiable individuals.

### Jurisdictional coverage
The scanner's scoring and red flag logic is calibrated primarily for GDPR (EU/UK) and CCPA (California). Coverage of PIPEDA (Canada), LGPD (Brazil), PDPA (Thailand/Singapore), and other frameworks is partial. Do not use this tool as the sole basis for multi-jurisdictional compliance assessment.

### Not legal advice
ODIPA is a nonprofit education and advocacy organization. This tool is provided for educational and research purposes. Nothing in this tool or its output constitutes legal advice.

---

## Options

```
positional:
  url               Privacy policy URL (mutually exclusive with --file)

optional:
  --file / -f       Local policy text file
  --output / -o     Output file path
  --format          text (default) or json
  --quiet / -q      Suppress console report
```

---

## Contributing

The scoring weights, pattern lists, and red flag rules are the core of this tool and benefit most from community review. Privacy law expertise is especially welcome, if you identify patterns that produce false positives or miss real issues, please open an issue or PR.

---

---

## Disclaimer & Limitation of Liability

**By downloading, installing, or using this tool, you acknowledge that you have read this disclaimer and accept full responsibility for your use of the tool.**

### User responsibility
You are solely responsible for how you use this tool, including any consequences arising from scanning websites you do not own or are not authorized to audit. ODIPA provides this tool as-is for educational, research, and authorized audit purposes. ODIPA does not control how you deploy it.

### ODIPA is not liable for misuse
ODIPA, its board members, officers, volunteers, and contributors are not liable for:
- Any legal action taken against you by a website operator, data broker, or third party as a result of your use of this tool
- Violations of any website's Terms of Service that result from your use of this tool
- Any civil or criminal liability arising from your use of this tool in jurisdictions where such use may be restricted
- Any damages, direct, indirect, incidental, consequential, or punitive, resulting from your use of or inability to use this tool

### Third-party Terms of Service
Many websites prohibit automated access in their Terms of Service. **It is your responsibility to review and comply with the Terms of Service of any website you scan using this tool before doing so.** ODIPA does not warrant that use of this tool is permissible under any particular website's terms, and ODIPA will not defend or indemnify you in any dispute arising from a ToS violation.

### Jurisdictional variation
Laws governing automated access to websites, data collection, and privacy vary by country, state, and context. What is lawful in one jurisdiction may not be lawful in another. **You are responsible for ensuring your use of this tool complies with all applicable laws in your jurisdiction.**

### No endorsement of misuse
ODIPA's mission is to protect digital privacy. This tool is intended to help users understand and audit data practices on websites they own or are authorized to review. Any use of this tool to harass, surveil, or harm individuals or organizations is explicitly prohibited and contrary to ODIPA's mission.

## License

MIT License. Free for personal, research, and commercial use with attribution.
