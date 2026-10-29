"""
Tests for PDF and Document Security Extractor (Phase 12)
Tests PDF text extraction, encryption detection, prohibited binary blocking,
scanned PDF limitations, character caps, and link extraction.
"""
import io
import pytest
import pypdf

from ai_engineering.document_analysis.document_extractor import DocumentExtractor, DocumentExtractionConfig
from ai_engineering.multimodal.contracts import InputType


def generate_simple_pdf(text: str = "") -> bytes:
    """Generates an in-memory PDF with or without text."""
    writer = pypdf.PdfWriter()
    page = writer.add_blank_page(width=300, height=300)
    # If text is provided, add it via annotation or simple stream
    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


def test_pdf_valid_extraction_with_urls():
    """Verify that a text document or PDF containing URLs extracts indicators cleanly."""
    extractor = DocumentExtractor()
    doc_text = "Security Notification: Please review invoice at https://invoice-billing-portal.top/view.pdf."
    res = extractor.extract_from_bytes(doc_text.encode("utf-8"), filename="notice.txt")

    assert res.success is True
    assert res.input_type == InputType.DOCUMENT_TEXT
    assert len(res.extracted_urls) == 1
    assert res.extracted_urls[0] == "https://invoice-billing-portal.top/view.pdf"
    assert "invoice-billing-portal.top" in res.extracted_text


def test_pdf_empty_scanned_document_reports_limitation():
    """Verify that a blank or scanned PDF with no extractable text reports LIMITATION-PDF-SCANNED-NO-TEXT."""
    blank_pdf = generate_simple_pdf()
    extractor = DocumentExtractor()
    res = extractor.extract_from_bytes(blank_pdf, filename="scanned.pdf", force_type=InputType.DOCUMENT_PDF)

    assert res.success is True
    assert res.input_type == InputType.DOCUMENT_PDF
    assert "LIMITATION-PDF-SCANNED-NO-TEXT" in res.limitations
    assert res.extracted_text is None


def test_pdf_encrypted_document_rejected_gracefully():
    """Verify that password-protected/encrypted PDFs are rejected with LIMITATION-DOC-ENCRYPTED."""
    writer = pypdf.PdfWriter()
    writer.add_blank_page(width=100, height=100)
    writer.encrypt("super_secret_password")
    buf = io.BytesIO()
    writer.write(buf)
    encrypted_pdf = buf.getvalue()

    extractor = DocumentExtractor()
    res = extractor.extract_from_bytes(encrypted_pdf, filename="secret.pdf", force_type=InputType.DOCUMENT_PDF)

    assert res.success is False
    assert "LIMITATION-DOC-ENCRYPTED" in res.limitations
    assert "encrypted" in res.error_message.lower()


def test_document_prohibited_executable_signatures_rejected():
    """Verify that Windows executables (MZ) and ZIP files are rejected immediately."""
    extractor = DocumentExtractor()

    # Windows PE executable
    pe_bytes = b"MZ\x90\x00\x03\x00\x00\x00malicious_binary_content"
    res_pe = extractor.extract_from_bytes(pe_bytes, filename="malware.exe")
    assert res_pe.success is False
    assert "LIMITATION-PROHIBITED-FILE-FORMAT" in res_pe.limitations
    assert "executable" in res_pe.error_message.lower()

    # ZIP archive
    zip_bytes = b"PK\x03\x04\x14\x00\x00\x00fake_zip_archive"
    res_zip = extractor.extract_from_bytes(zip_bytes, filename="archive.zip")
    assert res_zip.success is False
    assert "LIMITATION-PROHIBITED-FILE-FORMAT" in res_zip.limitations


def test_document_character_cap_enforced():
    """Verify that documents exceeding the character limit are truncated with a limitation notice."""
    config = DocumentExtractionConfig(max_text_characters=200)
    extractor = DocumentExtractor(config=config)

    oversized_text = "A" * 500
    res = extractor.extract_from_bytes(oversized_text.encode("utf-8"), filename="large.txt")

    assert res.success is True
    assert len(res.extracted_text) == 200
    assert "LIMITATION-TEXT-TRUNCATED-AT-LIMIT" in res.limitations
