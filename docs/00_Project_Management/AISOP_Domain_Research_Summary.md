# AISOP Domain and Hosting Research Summary

**Document ID:** AISOP-DOC-DOMAIN-SUMMARY-2026-001  
**Classification:** Infrastructure Architecture Planning  
**Governing Policy:** Local-first, zero recurring cost, privacy-preserving  
**Date:** 2026-10-31  

---

## 1. Key Findings

1. **Subdomains vs. Sovereign Domains:**
   - Free subdomains (`is-a.dev`, `eu.org`, `duckdns.org`) do NOT convey ownership. The root domain holder maintains absolute administrative authority.
   - Dynamic DNS and free subdomains are heavily flagged or blocked by enterprise SOCs and threat intelligence feeds due to high malicious abuse rates.
2. **Evaluation of Options:**
   - **For Development & Previews:** `aisop.is-a.dev` via GitHub pull request is the cleanest free option with SSL via Cloudflare Pages or GitHub Pages.
   - **For Free Secure DNS:** `deSEC.io` provides free, open-source, automated DNSSEC-enabled DNS hosting.
   - **For Production / Serious Public Launch:** Purchasing a standard custom domain (`aisop.dev` or `aisop-security.org`) at wholesale cost (~$10/year via Cloudflare Registrar) is strongly recommended for institutional credibility, brand protection, and zero revocation risk.
3. **Execution Guardrail:**
   - No domains were registered, and no DNS records were created or modified during this investigation.

