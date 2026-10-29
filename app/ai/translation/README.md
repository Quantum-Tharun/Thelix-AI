# AI Translation Subsystem (Placeholder)

## Status: INCOMPLETE / PLANNED CAPABILITY (Phase 2+)

This directory is an architectural placeholder for future multi-lingual translation capabilities (e.g. translating foreign-language phishing emails or fraudulent SMS lures into the user's localized language before analysis).

### Current Architecture
- Text normalization currently performs ASCII and Unicode transliteration within the input normalizers (`risk_engine/url_normalizer.py` and multimodal processors).
- Direct machine translation models (such as local MarianMT or NLLB models) are not yet integrated into the runtime pipeline.
- Production multi-language analysis currently passes normalized strings with language hints to the contextual NLP engines and explanation generators.
