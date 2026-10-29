# Risk Engine Specification

The Risk Engine is the deterministic core of Thelix AI. It fuses signals from multiple AI services into a single, predictable Trust Score (0-100) and Risk Score (0-100). 
`Trust Score + Risk Score = 100`.

## 1. Core Principles
1. **Deterministic:** Given the same inputs (e.g., same URL threat level, same OCR keywords), the engine must produce the *exact same* score every time.
2. **Idempotent:** Running the engine twice on the same evidence yields the same result.
3. **LLMs only explain, they do not score:** The Trust Score is calculated via mathematical weights. Gemini/Gemma are only fed the final score and reasons, and asked to write a human-readable `explanation` paragraph.

## 2. Signal Weighting & Scoring

We start with a baseline `Risk Score = 0`. We add penalty points based on evidence. Cap at 100.

### URL Intelligence (Weight: Highest)
- **Safe Browsing match (Malware/Phishing):** +80 points
- **VirusTotal detection (>3 vendors):** +90 points
- **Newly registered domain (< 30 days):** +40 points
- **Suspicious TLD (e.g., .top, .xyz):** +20 points

### Scam NLP / Keyword Heuristics (Weight: Medium)
- **Urgency keywords** ("immediate action", "account suspended"): +30 points
- **Financial keywords** ("crypto", "wire transfer", "IRS"): +20 points
- **Greeting mismatch** (e.g., "Dear Customer" from a supposed bank): +15 points

### Image / OCR context (Weight: Medium-High)
- **Fake Login UI matched:** +75 points
- **Hidden/Obfuscated Text in image:** +40 points

## 3. Conflict Resolution
What happens when signals conflict? (e.g., URL is totally safe/known, but the text is extremely urgent and scam-like).
- **Rule of Maximum Danger:** The Risk Score is strongly influenced by the highest single threat. If a known phishing URL is present (+80), the Risk Score cannot be lower than 80, even if the text sounds friendly.
- **Whitelist Override:** If a URL is a verified known-good entity (e.g., `google.com`), its URL risk is forced to 0, but the OCR context can still generate a medium risk (e.g., a scammer using a Google Form).

## 4. Threat Level Mapping
- **0 - 20:** Low Risk (Trust Score: 80-100)
- **21 - 50:** Medium Risk (Trust Score: 50-79)
- **51 - 85:** High Risk (Trust Score: 15-49)
- **86 - 100:** Critical Risk (Trust Score: 0-14)

## 5. Test Dataset Requirements
Before deploying the Risk Engine to production, we must evaluate it against:
- 100 known phishing screenshots
- 100 benign/safe screenshots
- 50 conflicting cases (safe link, scam text)
*Target Metric:* 0% False Negatives on Critical Risk items.
