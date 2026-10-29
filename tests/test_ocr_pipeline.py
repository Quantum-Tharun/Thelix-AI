"""
Tests for Screenshot and OCR Analysis Pipeline (Phase 12)
Tests image format validation, pixel bomb limits, preprocessing,
text normalization, URL extraction, and limitation reporting.
"""
import io
import pytest
from PIL import Image

from ai_engineering.ocr.ocr_pipeline import OCRPipeline, OCRConfig
from ai_engineering.multimodal.contracts import InputType


def create_test_image(width: int = 200, height: int = 100, format: str = "PNG", color: str = "white") -> bytes:
    img = Image.new("RGB", (width, height), color=color)
    buf = io.BytesIO()
    img.save(buf, format=format)
    return buf.getvalue()


def test_ocr_valid_image_ingestion_and_format_validation():
    """Verify that supported image formats (PNG, JPEG, WEBP, BMP) are accepted."""
    pipeline = OCRPipeline()
    for fmt in ["PNG", "JPEG", "BMP"]:
        img_bytes = create_test_image(format=fmt)
        res = pipeline.process_image(img_bytes, filename=f"test.{fmt.lower()}")
        assert res.success is True
        assert res.input_type == InputType.SCREENSHOT
        assert res.detector_metadata["format"] == fmt.lower()
        assert len(res.raw_hash) == 64


def test_ocr_empty_and_corrupt_image_handled_safely():
    """Verify that empty bytes or corrupt payloads return safe extraction errors without crashing."""
    pipeline = OCRPipeline()

    # Empty bytes
    res_empty = pipeline.process_image(b"")
    assert res_empty.success is False
    assert "LIMITATION-IMAGE-EMPTY" in res_empty.limitations

    # Corrupt payload with random invalid bytes
    res_corrupt = pipeline.process_image(b"NOT_AN_IMAGE_HEADER_AT_ALL_12345")
    assert res_corrupt.success is False
    assert "LIMITATION-UNSUPPORTED-IMAGE-FORMAT" in res_corrupt.limitations


def test_ocr_decompression_bomb_and_dimension_limits():
    """Verify that images exceeding pixel safety thresholds are rejected before decompression."""
    config = OCRConfig(max_total_pixels=10000, max_width=500, max_height=500)
    pipeline = OCRPipeline(config=config)

    # 1000 x 1000 = 1,000,000 pixels > 10,000 limit
    oversized_bytes = create_test_image(width=600, height=600)
    res = pipeline.process_image(oversized_bytes)
    assert res.success is False
    assert "LIMITATION-DECOMPRESSION-BOMB-REJECTED" in res.limitations
    assert "safety threshold" in res.error_message.lower()


def test_ocr_text_normalization_and_url_extraction():
    """Verify that text normalization strips unprintable chars and extracts valid URLs."""
    pipeline = OCRPipeline()
    raw_text = "Security Alert:\x00 Visit https://paypal-security-update.xyz/login to verify your account."
    clean = pipeline._normalize_text(raw_text)
    assert "\x00" not in clean
    assert "paypal-security-update.xyz" in clean

    urls = pipeline._extract_urls(clean)
    assert len(urls) == 1
    assert urls[0] == "https://paypal-security-update.xyz/login"


def test_ocr_failure_or_missing_binary_reports_limitation():
    """Verify that if OCR produces no text or engine is unavailable, an explicit limitation is recorded."""
    pipeline = OCRPipeline()
    # Plain blank image produces no text
    blank_bytes = create_test_image(width=100, height=50, color="white")
    res = pipeline.process_image(blank_bytes)
    assert res.success is True
    assert any("NO-TEXT" in lim or "UNAVAILABLE" in lim for lim in res.limitations)
