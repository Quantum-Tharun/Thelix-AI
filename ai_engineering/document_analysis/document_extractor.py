"""
Document Text and Security Indicator Extractor
Safely extracts text, hyperlinks, and threat indicators from PDF documents and plain-text files.
Enforces strict file signatures, page limits, character caps, and encryption checks.
"""
import io
import re
import time
import hashlib
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple, Set

try:
    import pypdf
    PYPDF_AVAILABLE = True
except ImportError:
    PYPDF_AVAILABLE = False

from ai_engineering.multimodal.contracts import InputType, MultimodalExtractionResult, ExtractedIndicator

logger = logging.getLogger("thelix.document_extractor")

# Blocked dangerous binary file signatures
DANGEROUS_BINARY_SIGNATURES = {
    b"MZ": "Windows PE Executable / DLL",
    b"\x7fELF": "Linux ELF Executable",
    b"PK\x03\x04": "ZIP / Office Archive",
    b"Rar!\x1a\x07": "RAR Archive",
    b"7z\xbc\xaf\x27\x1c": "7-Zip Archive",
}

URL_REGEX = re.compile(
    r"(?:https?://(?:[a-zA-Z0-9\-\._~%!$&'()*+,;=:]+@)?(?:[a-zA-Z0-9\-\.]+|\[[a-fA-F0-9:]+\])(?::\d+)?(?:/[^\s<>{}\\|^`\"\']*)?)|"
    r"(?:www\.[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?::\d+)?(?:/[^\s<>{}\\|^`\"\']*)?)",
    re.IGNORECASE
)


@dataclass
class DocumentExtractionConfig:
    max_file_size_bytes: int = 10 * 1024 * 1024      # 10 MB limit
    max_pages: int = 50                              # Max PDF pages inspected
    max_text_characters: int = 500_000               # 500k char cap
    timeout_seconds: float = 10.0


class DocumentExtractor:
    """
    Safely extracts text and links from PDFs and plain-text documents without script execution.
    """
    ENGINE_NAME = "thelix_document_extractor"
    ENGINE_VERSION = "1.0.0"

    def __init__(self, config: Optional[DocumentExtractionConfig] = None):
        self.config = config or DocumentExtractionConfig()

    def extract_from_bytes(
        self,
        content_bytes: bytes,
        filename: Optional[str] = None,
        force_type: Optional[InputType] = None
    ) -> MultimodalExtractionResult:
        """
        Parses PDF or text document bytes, extracts text & URLs, and enforces security boundaries.
        Returns MultimodalExtractionResult.
        """
        start_time = time.time()
        file_hash = hashlib.sha256(content_bytes).hexdigest()

        # 1. Byte Size Check
        if not content_bytes:
            return MultimodalExtractionResult(
                input_type=InputType.DOCUMENT_TEXT,
                raw_hash=file_hash,
                extracted_text="",
                extracted_urls=[],
                success=False,
                error_message="Empty document data: 0 bytes received",
                limitations=["LIMITATION-DOC-EMPTY"],
            )

        if len(content_bytes) > self.config.max_file_size_bytes:
            return MultimodalExtractionResult(
                input_type=InputType.DOCUMENT_TEXT,
                raw_hash=file_hash,
                extracted_text="",
                extracted_urls=[],
                success=False,
                error_message=f"Document size {len(content_bytes)} bytes exceeds limit ({self.config.max_file_size_bytes} bytes)",
                limitations=["LIMITATION-DOC-SIZE-EXCEEDED"],
            )

        # 2. Check for Prohibited Executable / Archive Signatures
        for sig, desc in DANGEROUS_BINARY_SIGNATURES.items():
            if content_bytes.startswith(sig):
                return MultimodalExtractionResult(
                    input_type=InputType.DOCUMENT_TEXT,
                    raw_hash=file_hash,
                    extracted_text="",
                    extracted_urls=[],
                    success=False,
                    error_message=f"Prohibited executable/archive file format: {desc}",
                    limitations=["LIMITATION-PROHIBITED-FILE-FORMAT"],
                )

        # 3. Determine Format (PDF vs Plain Text)
        is_pdf = content_bytes.startswith(b"%PDF-")
        if force_type == InputType.DOCUMENT_PDF or (force_type is None and is_pdf):
            return self._extract_pdf(content_bytes, file_hash, start_time)
        else:
            return self._extract_text(content_bytes, file_hash, start_time)

    def _extract_pdf(self, pdf_bytes: bytes, file_hash: str, start_time: float) -> MultimodalExtractionResult:
        """Extracts text, annotations, and embedded links from PDF files."""
        if not PYPDF_AVAILABLE:
            return MultimodalExtractionResult(
                input_type=InputType.DOCUMENT_PDF,
                raw_hash=file_hash,
                extracted_text="",
                extracted_urls=[],
                success=False,
                error_message="PDF parsing library (pypdf) is unavailable",
                limitations=["LIMITATION-PDF-ENGINE-UNAVAILABLE"],
            )

        limitations: List[str] = []
        page_texts: List[str] = []
        extracted_urls: List[str] = []
        indicators: List[ExtractedIndicator] = []

        try:
            reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))

            # Encryption check
            if reader.is_encrypted:
                return MultimodalExtractionResult(
                    input_type=InputType.DOCUMENT_PDF,
                    raw_hash=file_hash,
                    extracted_text="",
                    extracted_urls=[],
                    success=False,
                    error_message="Document is encrypted / password protected",
                    limitations=["LIMITATION-DOC-ENCRYPTED"],
                )

            total_pages = len(reader.pages)
            if total_pages == 0:
                limitations.append("LIMITATION-PDF-NO-PAGES")

            pages_to_read = min(total_pages, self.config.max_pages)
            if total_pages > self.config.max_pages:
                limitations.append(f"LIMITATION-PDF-PAGES-CAPPED: Inspected first {self.config.max_pages} of {total_pages} pages")

            total_chars = 0
            for idx in range(pages_to_read):
                page = reader.pages[idx]
                page_num = idx + 1
                try:
                    text = page.extract_text() or ""
                except Exception as e:
                    logger.warning(f"Error extracting text from page {page_num}: {e}")
                    text = ""

                # Extract annotations / hyperlinks (URIs)
                try:
                    if "/Annots" in page:
                        annots = page["/Annots"]
                        for annot in annots:
                            annot_obj = annot.get_object() if hasattr(annot, "get_object") else annot
                            if isinstance(annot_obj, dict) and "/A" in annot_obj:
                                action = annot_obj["/A"]
                                if isinstance(action, dict) and action.get("/S") == "/URI" and "/URI" in action:
                                    uri = str(action["/URI"]).strip()
                                    if uri and uri not in extracted_urls:
                                        extracted_urls.append(uri)
                                        indicators.append(ExtractedIndicator(
                                            indicator_type="url",
                                            value=uri,
                                            confidence=1.0,
                                            location={"page": page_num, "source": "annotation"},
                                            source_detector="pypdf_annotations",
                                        ))
                except Exception as e:
                    logger.debug(f"Annotation parsing skipped for page {page_num}: {e}")

                if text:
                    # Enforce character limits
                    remaining_space = self.config.max_text_characters - total_chars
                    if remaining_space <= 0:
                        limitations.append("LIMITATION-TEXT-TRUNCATED-AT-LIMIT")
                        break
                    truncated_page = text[:remaining_space]
                    page_texts.append(f"--- Page {page_num} ---\n{truncated_page}")
                    total_chars += len(truncated_page)

                    # Extract URLs from page body text
                    for u in self._extract_urls(truncated_page):
                        if u not in extracted_urls:
                            extracted_urls.append(u)
                            indicators.append(ExtractedIndicator(
                                indicator_type="url",
                                value=u,
                                confidence=0.95,
                                location={"page": page_num, "source": "body_text"},
                                source_detector="pypdf_text",
                            ))

        except Exception as e:
            return MultimodalExtractionResult(
                input_type=InputType.DOCUMENT_PDF,
                raw_hash=file_hash,
                extracted_text="",
                extracted_urls=[],
                success=False,
                error_message=f"PDF parsing error: {str(e)}",
                limitations=["LIMITATION-MALFORMED-PDF"],
            )

        combined_text = "\n\n".join(page_texts) if page_texts else None
        if not combined_text:
            limitations.append("LIMITATION-PDF-SCANNED-NO-TEXT")

        duration_ms = int((time.time() - start_time) * 1000)

        return MultimodalExtractionResult(
            input_type=InputType.DOCUMENT_PDF,
            raw_hash=file_hash,
            extracted_text=combined_text,
            extracted_urls=extracted_urls,
            indicators=indicators,
            limitations=limitations,
            detector_metadata={
                "total_pages": total_pages,
                "inspected_pages": pages_to_read,
                "total_extracted_characters": total_chars,
            },
            processing_time_ms=duration_ms,
            success=True,
        )

    def _extract_text(self, text_bytes: bytes, file_hash: str, start_time: float) -> MultimodalExtractionResult:
        """Extracts text and URLs from plain-text files."""
        limitations: List[str] = []
        try:
            # Decode with UTF-8, replace illegal characters
            decoded = text_bytes.decode("utf-8", errors="replace")
        except Exception as e:
            return MultimodalExtractionResult(
                input_type=InputType.DOCUMENT_TEXT,
                raw_hash=file_hash,
                extracted_text="",
                extracted_urls=[],
                success=False,
                error_message=f"Text decoding failed: {str(e)}",
                limitations=["LIMITATION-TEXT-DECODE-FAILED"],
            )

        # Check for excessive null bytes (often binary files masquerading as text)
        if decoded.count("\x00") > 5:
            return MultimodalExtractionResult(
                input_type=InputType.DOCUMENT_TEXT,
                raw_hash=file_hash,
                extracted_text="",
                extracted_urls=[],
                success=False,
                error_message="Binary data detected in text file (null byte threshold exceeded)",
                limitations=["LIMITATION-BINARY-DATA-IN-TEXT"],
            )

        clean_text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", decoded)
        if len(clean_text) > self.config.max_text_characters:
            clean_text = clean_text[: self.config.max_text_characters]
            limitations.append("LIMITATION-TEXT-TRUNCATED-AT-LIMIT")

        extracted_urls = self._extract_urls(clean_text)
        indicators: List[ExtractedIndicator] = []
        for u in extracted_urls:
            indicators.append(ExtractedIndicator(
                indicator_type="url",
                value=u,
                confidence=1.0,
                source_detector="plain_text_extractor",
            ))

        duration_ms = int((time.time() - start_time) * 1000)

        return MultimodalExtractionResult(
            input_type=InputType.DOCUMENT_TEXT,
            raw_hash=file_hash,
            extracted_text=clean_text if clean_text.strip() else None,
            extracted_urls=extracted_urls,
            indicators=indicators,
            limitations=limitations,
            detector_metadata={
                "character_count": len(clean_text),
            },
            processing_time_ms=duration_ms,
            success=True,
        )

    def _extract_urls(self, text: str) -> List[str]:
        """Extracts unique URLs from text, normalizing wrapped or hyphenated line breaks."""
        if not text:
            return []

        # Stitch URLs split across line breaks or hyphens
        # e.g., 'https://domain.com/path-\npage' -> 'https://domain.com/pathpage'
        stitched = re.sub(
            r"(https?://[^\s]+)-\r?\n\s*([a-zA-Z0-9\-._~%!$&'()*+,;=:@/?#]+)",
            r"\1\2",
            text
        )
        # e.g., 'https://domain.com/\npath' -> 'https://domain.com/path'
        stitched = re.sub(
            r"(https?://[a-zA-Z0-9\-._~%!$&'()*+,;=:@]+(?:/[^\s<>{}\\|^`\"\']*)?)/\r?\n\s*([a-zA-Z0-9\-._~%!$&'()*+,;=:@/?#]+)",
            r"\1/\2",
            stitched
        )

        matches = URL_REGEX.findall(stitched)
        urls: List[str] = []
        for m in matches:
            u = m.strip(".,;:()[]{}'\"")
            if not u.startswith("http://") and not u.startswith("https://"):
                u = "https://" + u
            if u not in urls:
                urls.append(u)
        return urls
