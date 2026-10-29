"""
QR Code Analysis & Safe Extraction Engine
Detects, decodes, and categorizes single and multi-QR codes from images.
Enforces SSRF boundaries and prevents automatic navigation.
"""
import io
import re
import time
import hashlib
import logging
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple, Set
from PIL import Image
import cv2
import numpy as np

from ai_engineering.multimodal.contracts import InputType, MultimodalExtractionResult, ExtractedIndicator
from risk_engine.evidence import Evidence, Finding, Severity

logger = logging.getLogger("thelix.qr_analyzer")

# Prohibited or dangerous schemes often embedded in malicious QR codes
DANGEROUS_SCHEMES = {"javascript", "file", "data", "intent", "smb", "ftp", "tel", "sms"}

IMAGE_SIGNATURES = {
    "png": b"\x89PNG\r\n\x1a\n",
    "jpeg": b"\xff\xd8\xff",
    "webp": b"RIFF",
    "bmp": b"BM",
}


class QRPayloadType(str, Enum):
    URL = "url"
    TEXT = "text"
    WIFI = "wifi"
    CONTACT = "contact"
    DANGEROUS_SCHEME = "dangerous_scheme"
    UNKNOWN = "unknown"


@dataclass
class DecodedQRPayload:
    raw_payload: str
    payload_type: QRPayloadType
    normalized_target: Optional[str] = None
    bounding_box: Optional[List[List[float]]] = None


@dataclass
class QRExtractionResult:
    payloads: List[DecodedQRPayload]
    extracted_urls: List[str]
    limitations: List[str]
    detector_engine: str = "opencv_qrcode_detector"


class QRAnalyzer:
    """
    Decodes QR codes from image bytes and evaluates payload risks without network access.
    """
    ENGINE_NAME = "thelix_qr_analyzer"
    ENGINE_VERSION = "1.0.0"

    def __init__(self, max_file_size_bytes: int = 10 * 1024 * 1024):
        self.max_file_size_bytes = max_file_size_bytes
        self.detector = cv2.QRCodeDetector()

    def analyze_image(
        self,
        image_bytes: bytes,
        filename: Optional[str] = None
    ) -> Tuple[MultimodalExtractionResult, List[Evidence], List[Finding]]:
        """
        Extracts QR codes from image bytes and produces extraction artifacts + security findings.
        Returns (extraction_result, evidence_list, findings_list).
        """
        start_time = time.time()
        file_hash = hashlib.sha256(image_bytes).hexdigest()
        evidence_list: List[Evidence] = []
        findings_list: List[Finding] = []

        # 1. Byte Size & Signature Validation
        if not image_bytes:
            res = MultimodalExtractionResult(
                input_type=InputType.QR_CODE,
                raw_hash=file_hash,
                extracted_text="",
                extracted_urls=[],
                success=False,
                error_message="Empty image data: 0 bytes received",
                limitations=["LIMITATION-IMAGE-EMPTY"],
            )
            return res, evidence_list, findings_list

        if len(image_bytes) > self.max_file_size_bytes:
            res = MultimodalExtractionResult(
                input_type=InputType.QR_CODE,
                raw_hash=file_hash,
                extracted_text="",
                extracted_urls=[],
                success=False,
                error_message=f"Image size exceeds limit of {self.max_file_size_bytes} bytes",
                limitations=["LIMITATION-IMAGE-SIZE-EXCEEDED"],
            )
            return res, evidence_list, findings_list

        # Validate magic bytes
        if not self._validate_signature(image_bytes):
            res = MultimodalExtractionResult(
                input_type=InputType.QR_CODE,
                raw_hash=file_hash,
                extracted_text="",
                extracted_urls=[],
                success=False,
                error_message="Unsupported image signature for QR decoding",
                limitations=["LIMITATION-UNSUPPORTED-IMAGE-FORMAT"],
            )
            return res, evidence_list, findings_list

        # 2. Header & Pixel Dimension Check (Decompression bomb guard)
        try:
            pil_img = Image.open(io.BytesIO(image_bytes))
            w, h = pil_img.size
            if w <= 0 or h <= 0 or (w * h) > 16_777_216:
                res = MultimodalExtractionResult(
                    input_type=InputType.QR_CODE,
                    raw_hash=file_hash,
                    extracted_text="",
                    extracted_urls=[],
                    success=False,
                    error_message="Image dimensions exceed safety limits (16MP max)",
                    limitations=["LIMITATION-DECOMPRESSION-BOMB-REJECTED"],
                )
                return res, evidence_list, findings_list
        except Exception as e:
            res = MultimodalExtractionResult(
                input_type=InputType.QR_CODE,
                raw_hash=file_hash,
                extracted_text="",
                extracted_urls=[],
                success=False,
                error_message=f"Failed to read image headers: {str(e)}",
                limitations=["LIMITATION-CORRUPT-IMAGE"],
            )
            return res, evidence_list, findings_list

        # 3. OpenCV Decoding
        try:
            np_arr = np.frombuffer(image_bytes, np.uint8)
            cv_img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
            if cv_img is None:
                res = MultimodalExtractionResult(
                    input_type=InputType.QR_CODE,
                    raw_hash=file_hash,
                    extracted_text="",
                    extracted_urls=[],
                    success=False,
                    error_message="OpenCV failed to decode image array",
                    limitations=["LIMITATION-CORRUPT-PIXELS"],
                )
                return res, evidence_list, findings_list
        except Exception as e:
            res = MultimodalExtractionResult(
                input_type=InputType.QR_CODE,
                raw_hash=file_hash,
                extracted_text="",
                extracted_urls=[],
                success=False,
                error_message=f"OpenCV decode error: {str(e)}",
                limitations=["LIMITATION-IMAGE-DECODE-ERROR"],
            )
            return res, evidence_list, findings_list

        # 4. Multi-QR Detection and Fallback Single-QR Detection
        raw_payloads: List[str] = []
        try:
            retval, decoded_info, points, _ = self.detector.detectAndDecodeMulti(cv_img)
            if retval and decoded_info:
                for text in decoded_info:
                    if text and text.strip():
                        raw_payloads.append(text.strip())
        except Exception as e:
            logger.debug(f"Multi-QR detection encountered exception ({e}); attempting single detector fallback.")

        if not raw_payloads:
            try:
                single_text, single_points, _ = self.detector.detectAndDecode(cv_img)
                if single_text and single_text.strip():
                    raw_payloads.append(single_text.strip())
            except Exception as e:
                logger.warning(f"Single QR detection failed: {e}")

        # Fallback with quiet zone border padding for tightly cropped QR images
        if not raw_payloads:
            try:
                padded_img = cv2.copyMakeBorder(cv_img, 80, 80, 80, 80, cv2.BORDER_CONSTANT, value=[255, 255, 255])
                retval, decoded_info, _, _ = self.detector.detectAndDecodeMulti(padded_img)
                if retval and decoded_info:
                    for text in decoded_info:
                        if text and text.strip():
                            raw_payloads.append(text.strip())
                if not raw_payloads:
                    single_text, _, _ = self.detector.detectAndDecode(padded_img)
                    if single_text and single_text.strip():
                        raw_payloads.append(single_text.strip())
            except Exception as e:
                logger.debug(f"Padded QR fallback failed: {e}")

        # 5. Process & Deduplicate Decoded Payloads
        limitations: List[str] = []
        seen_payloads: Set[str] = set()
        decoded_items: List[DecodedQRPayload] = []
        extracted_urls: List[str] = []
        extracted_texts: List[str] = []
        indicators: List[ExtractedIndicator] = []

        if not raw_payloads:
            limitations.append("LIMITATION-NO-QR-CODE-DETECTED")
        else:
            for raw_text in raw_payloads:
                if raw_text in seen_payloads:
                    continue
                seen_payloads.add(raw_text)

                p_type, norm_url = self._classify_payload(raw_text)
                decoded_items.append(DecodedQRPayload(
                    raw_payload=raw_text,
                    payload_type=p_type,
                    normalized_target=norm_url,
                ))

                if p_type == QRPayloadType.URL and norm_url:
                    extracted_urls.append(norm_url)
                    indicators.append(ExtractedIndicator(
                        indicator_type="url",
                        value=norm_url,
                        confidence=1.0,
                        source_detector="opencv_qr",
                    ))
                elif p_type == QRPayloadType.DANGEROUS_SCHEME:
                    # Emits critical/high finding for dangerous executable schemes
                    ev_danger = Evidence(
                        indicator_type="qr_dangerous_scheme",
                        indicator_value_or_reference=raw_text[:200],
                        source_engine=self.ENGINE_NAME,
                        source_version=self.ENGINE_VERSION,
                        observation={"scheme_payload": raw_text[:200]},
                        reliability=1.0,
                        confidence=1.0,
                        correlation_group="qr_attack",
                    )
                    evidence_list.append(ev_danger)
                    findings_list.append(Finding(
                        finding_code="FIND-QR-DANGEROUS-SCHEME",
                        title="Dangerous Scheme Decoded in QR Code",
                        description=f"QR code contains prohibited executable scheme: '{raw_text[:50]}...'",
                        severity=Severity.CRITICAL,
                        confidence=1.0,
                        source_engine=self.ENGINE_NAME,
                        source_version=self.ENGINE_VERSION,
                        evidence_references=[ev_danger.evidence_id],
                        correlation_group="qr_attack",
                    ))
                else:
                    extracted_texts.append(raw_text)
                    indicators.append(ExtractedIndicator(
                        indicator_type="text_phrase",
                        value=raw_text[:500],
                        confidence=1.0,
                        source_detector="opencv_qr",
                    ))

        duration_ms = int((time.time() - start_time) * 1000)
        combined_text = "\n".join(extracted_texts) if extracted_texts else None

        result = MultimodalExtractionResult(
            input_type=InputType.QR_CODE,
            raw_hash=file_hash,
            extracted_text=combined_text,
            extracted_urls=extracted_urls,
            indicators=indicators,
            limitations=limitations,
            detector_metadata={
                "qr_codes_found": len(decoded_items),
                "unique_payloads": len(seen_payloads),
                "payload_types": [item.payload_type.value for item in decoded_items],
            },
            processing_time_ms=duration_ms,
            success=True,
        )

        return result, evidence_list, findings_list

    def _validate_signature(self, image_bytes: bytes) -> bool:
        if image_bytes.startswith(IMAGE_SIGNATURES["png"]):
            return True
        elif image_bytes.startswith(IMAGE_SIGNATURES["jpeg"]):
            return True
        elif image_bytes.startswith(IMAGE_SIGNATURES["bmp"]):
            return True
        elif image_bytes.startswith(IMAGE_SIGNATURES["webp"]) and len(image_bytes) >= 12 and image_bytes[8:12] == b"WEBP":
            return True
        return False

    def _classify_payload(self, text: str) -> Tuple[QRPayloadType, Optional[str]]:
        """Classifies QR string into URL, dangerous scheme, WiFi, or text."""
        clean = text.strip()

        # Check dangerous schemes
        for scheme in DANGEROUS_SCHEMES:
            if clean.lower().startswith(f"{scheme}:"):
                return QRPayloadType.DANGEROUS_SCHEME, None

        if clean.lower().startswith("http://") or clean.lower().startswith("https://"):
            return QRPayloadType.URL, clean
        elif clean.lower().startswith("www."):
            return QRPayloadType.URL, "https://" + clean
        elif clean.upper().startswith("WIFI:"):
            return QRPayloadType.WIFI, None
        elif clean.upper().startswith("BEGIN:VCARD") or clean.upper().startswith("MECARD:"):
            return QRPayloadType.CONTACT, None

        # Check if text contains embedded URL
        url_match = re.search(r"https?://[^\s<>\"']+", clean, re.I)
        if url_match:
            return QRPayloadType.URL, url_match.group(0)

        return QRPayloadType.TEXT, None
