# API Contracts (Backend ↔ AI Gateway)

This document defines the strict Pydantic schemas that the Backend Engineer (Tharika) will use to interface with the AI Gateway.

## Base Uniform Response
Regardless of the AI service called, the Risk Engine guarantees this unified output format.

```json
{
  "trust_score": 8,
  "risk_score": 92,
  "threat_level": "High",
  "reasons": [
    "Suspicious URL: 'paypal-login-secure.com'",
    "Urgent scam language detected in text"
  ],
  "recommendations": [
    "Do not open any links",
    "Delete this image/message immediately"
  ],
  "explanation": "We detected a phishing attempt designed to steal your PayPal credentials.",
  "evidence": {
    "ocr_text": "Please verify your account immediately at...",
    "url_threats": ["Social Engineering"]
  },
  "model_versions": {
    "ocr": "google-mlkit-v1",
    "scam_detector": "gemma-2b-v3",
    "risk_engine": "v1.0"
  },
  "processed_offline": false
}
```

## 1. Screenshot Analysis
`POST /v1/ai/analyze-screenshot`

**Request Schema:**
```json
{
  "user_id": "uuid-string",
  "image_base64": "base64-encoded-string",
  "source": "WhatsApp",
  "locale": "en-US",
  "timestamp": "2026-07-11T09:41:21Z"
}
```
**Response:** Base Uniform Response

## 2. URL Analysis
`POST /v1/ai/analyze-url`

**Request Schema:**
```json
{
  "user_id": "uuid-string",
  "url": "https://suspicious-link.com",
  "source": "SMS",
  "locale": "en-US"
}
```
**Response:** Base Uniform Response

## 3. QR Code Analysis
`POST /v1/ai/analyze-qr`

**Request Schema:**
```json
{
  "user_id": "uuid-string",
  "image_base64": "base64-encoded-string"
}
```
**Response:** Base Uniform Response (includes decoded URL in evidence)

## SLA & Error Handling
- **Target Latency:** < 2000ms for text/URL, < 5000ms for images (online).
- **Timeouts:** If an AI service exceeds 10s, the Gateway will fallback to a `Timeout` threat level and prompt the user to try again offline.
- **Errors:** 
  - `400 Bad Request` (Invalid base64, missing fields)
  - `401 Unauthorized` (Invalid internal JWT)
  - `503 Service Unavailable` (Hardware limits reached on device)
