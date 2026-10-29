"""
Input Type Detector & Sanitizer
Determines the verified input modality (URL, screenshot, QR, PDF, document text, message text)
using magic byte signatures, structural headers, and content sniffing rather than user claims alone.
Enforces strict allowlists and rejects prohibited executable and archive formats.
"""
import re
from enum import Enum
from typing import Optional, Tuple, Dict, Any, List
from urllib.parse import urlsplit, urlunsplit

from ai_engineering.multimodal.contracts import InputType
from risk_engine.exceptions import ValidationError


class ProhibitedFileFormatException(ValidationError):
    """Raised when an uploaded file matches a prohibited executable, binary, or archive signature."""
    def __init__(self, message: str, signature_type: str, details: Optional[Dict[str, Any]] = None):
        d = details or {}
        d["prohibited_signature"] = signature_type
        super().__init__(message, code="PROHIBITED_FILE_FORMAT", details=d)


# Magic byte signatures for prohibited binary/executable/archive formats
PROHIBITED_BINARY_SIGNATURES: Dict[bytes, str] = {
    b"MZ": "Windows PE Executable / DLL (.exe, .dll, .sys)",
    b"\x7fELF": "Linux ELF Executable (.bin, .so)",
    b"PK\x03\x04": "ZIP / Office Archive (.zip, .jar, .docx, .xlsx)",
    b"Rar!\x1a\x07": "RAR Archive (.rar)",
    b"7z\xbc\xaf\x27\x1c": "7-Zip Archive (.7z)",
    b"\xca\xfe\xba\xbe": "Mach-O Fat Binary / Java Class",
    b"\xcf\xfa\xed\xfe": "Mach-O 64-bit Binary",
    b"\xce\xfa\xed\xfe": "Mach-O 32-bit Binary",
    b"\xfe\xed\xfa\xce": "Mach-O Binary (byte-swapped 32-bit)",
    b"\xfe\xed\xfa\xcf": "Mach-O Binary (byte-swapped 64-bit)",
}

# Magic byte signatures for permitted image formats
PERMITTED_IMAGE_SIGNATURES: Dict[str, bytes] = {
    "png": b"\x89PNG\r\n\x1a\n",
    "jpeg": b"\xff\xd8\xff",
    "webp": b"RIFF",  # with WEBP at offset 8
    "bmp": b"BM",
}


def sanitize_target_for_display(target: str) -> str:
    """
    Safely redacts passwords, userinfo, and sensitive query tokens from target strings
    for display in public logs, error messages, and reports.
    """
    if not target:
        return ""

    # 1. Redact credentials embedded in URL userinfo: https://user:pass@domain.com
    try:
        parsed = urlsplit(target)
        if parsed.scheme and parsed.netloc:
            netloc = parsed.netloc
            if "@" in netloc:
                creds, host = netloc.split("@", 1)
                user = creds.split(":", 1)[0] if ":" in creds else creds
                redacted_netloc = f"{user}:[REDACTED]@{host}"
                parsed = parsed._replace(netloc=redacted_netloc)

            # Redact sensitive query parameters
            if parsed.query:
                query_pairs = []
                for pair in parsed.query.split("&"):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        if any(s in k.lower() for s in ("token", "key", "secret", "password", "auth", "credential", "api_key")):
                            query_pairs.append(f"{k}=[REDACTED]")
                        else:
                            query_pairs.append(pair)
                    else:
                        query_pairs.append(pair)
                parsed = parsed._replace(query="&".join(query_pairs))

            target = urlunsplit(parsed)
    except Exception:
        pass

    # 2. General regex scrubbing for API keys / tokens in arbitrary strings
    target = re.sub(r"(key|token|secret|password|api_key)[=:\s]+([0-9A-Za-z-_]{8,})", r"\1=[REDACTED]", target, flags=re.IGNORECASE)
    return target


def detect_and_validate_input_type(
    content_bytes: Optional[bytes] = None,
    text_content: Optional[str] = None,
    declared_type: Optional[str] = None,
    filename: Optional[str] = None,
) -> Tuple[InputType, Dict[str, Any]]:
    """
    Inspects raw content bytes and text to determine the verified InputType.
    Enforces allowlists, detects magic byte signatures, prevents executable execution,
    and resolves client-declared vs actually detected input type discrepancies.

    Returns:
        (verified_input_type, detection_metadata)

    Raises:
        ProhibitedFileFormatException: If input contains executable/archive signatures.
        ValidationError: If input is empty or corrupt.
    """
    detection_meta: Dict[str, Any] = {
        "declared_type": declared_type,
        "filename": filename,
        "signature_matched": None,
        "discrepancy_resolved": False,
    }

    # 1. Byte-level Signature Inspection
    if content_bytes and len(content_bytes) > 0:
        # Check against prohibited executable/archive formats
        for sig, desc in PROHIBITED_BINARY_SIGNATURES.items():
            if content_bytes.startswith(sig):
                detection_meta["prohibited_signature"] = desc
                raise ProhibitedFileFormatException(
                    message=f"Unsupported input: {desc} is prohibited. Executables and archives cannot be executed or analyzed.",
                    signature_type=desc,
                    details=detection_meta,
                )

        # Check for shell scripts
        if content_bytes.startswith(b"#!"):
            raise ProhibitedFileFormatException(
                message="Unsupported input: Shell scripts and command files cannot be executed or analyzed.",
                signature_type="Shell Script (#!)",
                details=detection_meta,
            )

        # Check for PDF signature: %PDF- in first 1024 bytes
        if b"%PDF-" in content_bytes[:1024]:
            detection_meta["signature_matched"] = "application/pdf"
            if declared_type and declared_type.lower() not in ("pdf", "document_pdf"):
                detection_meta["discrepancy_resolved"] = True
                detection_meta["resolution_note"] = f"Declared '{declared_type}', but verified PDF magic bytes (%PDF-). Normalized to DOCUMENT_PDF."
            return InputType.DOCUMENT_PDF, detection_meta

        # Check for Permitted Image Signatures
        is_image = False
        img_format = None
        if content_bytes.startswith(PERMITTED_IMAGE_SIGNATURES["png"]):
            is_image = True
            img_format = "png"
        elif content_bytes.startswith(PERMITTED_IMAGE_SIGNATURES["jpeg"]):
            is_image = True
            img_format = "jpeg"
        elif content_bytes.startswith(PERMITTED_IMAGE_SIGNATURES["bmp"]):
            is_image = True
            img_format = "bmp"
        elif content_bytes.startswith(b"RIFF") and len(content_bytes) >= 12 and content_bytes[8:12] == b"WEBP":
            is_image = True
            img_format = "webp"

        if is_image:
            detection_meta["signature_matched"] = f"image/{img_format}"
            # If user explicitly requested QR code analysis, honor QR_CODE modality
            if declared_type and declared_type.lower() in ("qr", "qr_code"):
                return InputType.QR_CODE, detection_meta
            if declared_type and declared_type.lower() in ("pdf", "text", "document"):
                detection_meta["discrepancy_resolved"] = True
                detection_meta["resolution_note"] = f"Declared '{declared_type}', but verified image ({img_format}) signature. Normalized to SCREENSHOT."
            return InputType.SCREENSHOT, detection_meta

        # If not an image or PDF, test if it's valid UTF-8 text
        try:
            decoded = content_bytes.decode("utf-8")
            detection_meta["signature_matched"] = "text/plain; charset=utf-8"
            clean_str = decoded.strip()
            if clean_str.startswith("http://") or clean_str.startswith("https://"):
                return InputType.URL, detection_meta
            if declared_type and declared_type.lower() in ("message", "message_text"):
                return InputType.MESSAGE_TEXT, detection_meta
            return InputType.DOCUMENT_TEXT, detection_meta
        except UnicodeDecodeError:
            # Binary data that didn't match known safe formats
            raise ValidationError(
                message="Unsupported input: Unrecognized binary file format. Only images (PNG, JPEG, WEBP, BMP), PDFs, and plain text are supported.",
                code="UNSUPPORTED_BINARY_FORMAT",
                details=detection_meta,
            )

    # 2. Text Content Inspection
    if text_content and text_content.strip():
        clean_text = text_content.strip()
        detection_meta["text_length"] = len(clean_text)

        # Check if text is a single direct URL
        if (clean_text.startswith("http://") or clean_text.startswith("https://") or clean_text.startswith("www.")) and "\n" not in clean_text:
            detection_meta["signature_matched"] = "text/url"
            return InputType.URL, detection_meta

        if declared_type and declared_type.lower() in ("document", "text", "document_text"):
            detection_meta["signature_matched"] = "text/document"
            return InputType.DOCUMENT_TEXT, detection_meta

        detection_meta["signature_matched"] = "text/message"
        return InputType.MESSAGE_TEXT, detection_meta

    # 3. Fallback to declared type if no payload was passed
    if declared_type:
        try:
            return InputType(declared_type.lower()), detection_meta
        except ValueError:
            pass

    raise ValidationError(
        message="Empty or invalid input: Must provide either file bytes or text content for analysis.",
        code="EMPTY_INPUT",
        details=detection_meta,
    )


def sniff_content_type(content_bytes: bytes) -> InputType:
    """Convenience wrapper to sniff InputType from raw bytes."""
    detected_type, _ = detect_and_validate_input_type(content_bytes=content_bytes)
    return detected_type

