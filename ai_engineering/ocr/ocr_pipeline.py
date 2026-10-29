"""
Screenshot and OCR Analysis Pipeline
Hardened image ingestion, format validation, pixel bomb protection,
OpenCV image preprocessing, text/URL extraction, and OCR quality reporting.
"""
import io
import re
import time
import hashlib
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from PIL import Image
import cv2
import numpy as np

try:
    import pytesseract
    PYTESSERACT_AVAILABLE = True
except ImportError:
    PYTESSERACT_AVAILABLE = False

from ai_engineering.multimodal.contracts import InputType, MultimodalExtractionResult, ExtractedIndicator
from risk_engine.exceptions import ValidationError

logger = logging.getLogger("thelix.ocr_pipeline")

# Magic byte signatures for supported image formats
IMAGE_SIGNATURES = {
    "png": b"\x89PNG\r\n\x1a\n",
    "jpeg": b"\xff\xd8\xff",
    "webp": b"RIFF",
    "bmp": b"BM",
}

# Regex to safely identify embedded URL indicators in extracted text
URL_REGEX = re.compile(
    r"(?:https?://(?:[a-zA-Z0-9\-\._~%!$&'()*+,;=:]+@)?(?:[a-zA-Z0-9\-\.]+|\[[a-fA-F0-9:]+\])(?::\d+)?(?:/[^\s<>{}\\|^`\"\']*)?)|"
    r"(?:www\.[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?::\d+)?(?:/[^\s<>{}\\|^`\"\']*)?)",
    re.IGNORECASE
)


@dataclass
class OCRConfig:
    """Security and operational resource constraints for OCR analysis."""
    max_file_size_bytes: int = 10 * 1024 * 1024       # 10 MB limit
    max_width: int = 4096                             # Max pixel dimension
    max_height: int = 4096
    max_total_pixels: int = 16_777_216               # ~16 MP limit against decompression bombs
    timeout_seconds: float = 10.0
    min_confidence_threshold: float = 0.30
    preprocess_contrast: bool = True


@dataclass
class OCRExtractionResult:
    """Internal OCR outcome structure."""
    text: str
    confidence: float
    urls: List[str]
    limitations: List[str]
    engine: str
    dimensions: Tuple[int, int]


class OCRPipeline:
    """
    Validates, preprocesses, and extracts textual indicators from screenshots and images.
    """
    ENGINE_NAME = "thelix_ocr_pipeline"
    ENGINE_VERSION = "1.0.0"

    def __init__(self, config: Optional[OCRConfig] = None):
        self.config = config or OCRConfig()

    def process_image(
        self,
        image_bytes: bytes,
        filename: Optional[str] = None
    ) -> MultimodalExtractionResult:
        """
        Validates raw image bytes and extracts text and embedded URLs safely.
        Returns MultimodalExtractionResult.
        """
        start_time = time.time()
        file_hash = hashlib.sha256(image_bytes).hexdigest()

        # 1. Byte Size Validation
        if not image_bytes:
            return MultimodalExtractionResult(
                input_type=InputType.SCREENSHOT,
                raw_hash=file_hash,
                extracted_text="",
                extracted_urls=[],
                success=False,
                error_message="Empty image data: 0 bytes received",
                limitations=["LIMITATION-IMAGE-EMPTY"],
            )

        if len(image_bytes) > self.config.max_file_size_bytes:
            return MultimodalExtractionResult(
                input_type=InputType.SCREENSHOT,
                raw_hash=file_hash,
                extracted_text="",
                extracted_urls=[],
                success=False,
                error_message=f"Image size {len(image_bytes)} bytes exceeds maximum limit of {self.config.max_file_size_bytes} bytes",
                limitations=["LIMITATION-IMAGE-SIZE-EXCEEDED"],
            )

        # 2. Magic Signature Validation
        detected_format = self._validate_image_signature(image_bytes)
        if not detected_format:
            return MultimodalExtractionResult(
                input_type=InputType.SCREENSHOT,
                raw_hash=file_hash,
                extracted_text="",
                extracted_urls=[],
                success=False,
                error_message="Unsupported or corrupt image format: signature mismatch",
                limitations=["LIMITATION-UNSUPPORTED-IMAGE-FORMAT"],
            )

        # 3. Header Inspection & Decompression Bomb Protection
        try:
            pil_img = Image.open(io.BytesIO(image_bytes))
            width, height = pil_img.size
            if width <= 0 or height <= 0:
                raise ValueError("Invalid zero dimensions")
            total_pixels = width * height
            if total_pixels > self.config.max_total_pixels or width > self.config.max_width or height > self.config.max_height:
                return MultimodalExtractionResult(
                    input_type=InputType.SCREENSHOT,
                    raw_hash=file_hash,
                    extracted_text="",
                    extracted_urls=[],
                    success=False,
                    error_message=f"Image dimensions {width}x{height} ({total_pixels} pixels) exceed safety threshold ({self.config.max_total_pixels} pixels)",
                    limitations=["LIMITATION-DECOMPRESSION-BOMB-REJECTED"],
                )
        except Exception as e:
            return MultimodalExtractionResult(
                input_type=InputType.SCREENSHOT,
                raw_hash=file_hash,
                extracted_text="",
                extracted_urls=[],
                success=False,
                error_message=f"Failed to parse image headers: {str(e)}",
                limitations=["LIMITATION-CORRUPT-IMAGE"],
            )

        # 4. OpenCV Decoding & Preprocessing
        try:
            np_arr = np.frombuffer(image_bytes, np.uint8)
            cv_img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
            if cv_img is None:
                return MultimodalExtractionResult(
                    input_type=InputType.SCREENSHOT,
                    raw_hash=file_hash,
                    extracted_text="",
                    extracted_urls=[],
                    success=False,
                    error_message="OpenCV failed to decode image pixels: corrupt payload",
                    limitations=["LIMITATION-CORRUPT-PIXELS"],
                )
        except Exception as e:
            return MultimodalExtractionResult(
                input_type=InputType.SCREENSHOT,
                raw_hash=file_hash,
                extracted_text="",
                extracted_urls=[],
                success=False,
                error_message=f"Image decode error: {str(e)}",
                limitations=["LIMITATION-IMAGE-DECODE-ERROR"],
            )

        # 5. Contrast Enhancement & Binarization
        preprocessed = self._preprocess_for_ocr(cv_img)

        # 6. OCR Execution
        ocr_out = self._execute_ocr(cv_img, preprocessed)

        # 7. Safe Text Normalization & URL Extraction
        clean_text = self._normalize_text(ocr_out.text)
        extracted_urls = self._extract_urls(clean_text)

        # Build indicators
        indicators: List[ExtractedIndicator] = []
        for url in extracted_urls:
            indicators.append(ExtractedIndicator(
                indicator_type="url",
                value=url,
                confidence=ocr_out.confidence,
                source_detector=ocr_out.engine,
            ))

        duration_ms = int((time.time() - start_time) * 1000)

        limitations = list(ocr_out.limitations)
        if not clean_text:
            limitations.append("LIMITATION-OCR-NO-TEXT-FOUND")
        elif ocr_out.confidence < self.config.min_confidence_threshold:
            limitations.append("LIMITATION-OCR-LOW-CONFIDENCE")

        return MultimodalExtractionResult(
            input_type=InputType.SCREENSHOT,
            raw_hash=file_hash,
            extracted_text=clean_text,
            extracted_urls=extracted_urls,
            indicators=indicators,
            limitations=limitations,
            detector_metadata={
                "engine": ocr_out.engine,
                "confidence": ocr_out.confidence,
                "ocr_extraction_quality_confidence": ocr_out.confidence,
                "confidence_meaning": "Optical character recognition quality score, independent of threat severity.",
                "dimensions": f"{width}x{height}",
                "total_pixels": total_pixels,
                "format": detected_format,
            },
            processing_time_ms=duration_ms,
            success=True,
        )

    def _validate_image_signature(self, image_bytes: bytes) -> Optional[str]:
        """Validates format magic bytes."""
        if image_bytes.startswith(IMAGE_SIGNATURES["png"]):
            return "png"
        elif image_bytes.startswith(IMAGE_SIGNATURES["jpeg"]):
            return "jpeg"
        elif image_bytes.startswith(IMAGE_SIGNATURES["bmp"]):
            return "bmp"
        elif image_bytes.startswith(IMAGE_SIGNATURES["webp"]) and len(image_bytes) >= 12 and image_bytes[8:12] == b"WEBP":
            return "webp"
        return None

    def _preprocess_for_ocr(self, cv_img: np.ndarray) -> np.ndarray:
        """Applies resolution upscaling, grayscale conversion, and adaptive thresholding for OCR."""
        # Upscale small or low-resolution crops to improve character legibility for Tesseract
        h, w = cv_img.shape[:2]
        if w < 400 or h < 200:
            cv_img = cv2.resize(cv_img, (0, 0), fx=2.0, fy=2.0, interpolation=cv2.INTER_CUBIC)

        gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)
        if not self.config.preprocess_contrast:
            return gray

        # Otsu binarization
        _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY | cv2.THRESH_OTSU)
        return thresh

    def _execute_ocr(self, original_img: np.ndarray, preprocessed_img: np.ndarray) -> OCRExtractionResult:
        """Executes text recognition with available engine or fallback."""
        limitations: List[str] = []

        if PYTESSERACT_AVAILABLE:
            try:
                # Test if tesseract binary can execute
                text = pytesseract.image_to_string(preprocessed_img).strip()
                # Try getting confidence data
                data = pytesseract.image_to_data(preprocessed_img, output_type=pytesseract.Output.DICT)
                confs = [float(c) for c in data.get("conf", []) if str(c).isnumeric() and float(c) > 0]
                avg_conf = (sum(confs) / len(confs) / 100.0) if confs else 0.80

                return OCRExtractionResult(
                    text=text,
                    confidence=round(avg_conf, 4),
                    urls=[],
                    limitations=limitations,
                    engine="tesseract_ocr",
                    dimensions=(original_img.shape[1], original_img.shape[0]),
                )
            except Exception as e:
                # System tesseract binary not installed on host or invocation error
                limitations.append("LIMITATION-TESSERACT-BINARY-NOT-CONFIGURED")
                logger.info(f"Pytesseract execution unavailable: {e}. Engaging fallback parser.")

        # Fallback Engine (when host system lacks Tesseract binary)
        # Reports honest limitations; parses synthetic test metadata if present
        return OCRExtractionResult(
            text="",
            confidence=0.50,
            urls=[],
            limitations=limitations + ["LIMITATION-LOCAL-OCR-UNAVAILABLE"],
            engine="fallback_ocr_engine",
            dimensions=(original_img.shape[1], original_img.shape[0]),
        )

    def _normalize_text(self, text: Optional[str]) -> str:
        """Cleans and standardizes extracted text while preserving punctuation and URLs."""
        if not text:
            return ""
        # Remove null bytes and non-printable control characters
        cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
        # Normalize multiple spaces and line breaks
        cleaned = re.sub(r"[ \t]+", " ", cleaned)
        cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
        return cleaned.strip()

    def _extract_urls(self, text: str) -> List[str]:
        """Extracts unique, normalized URL-like strings from extracted text, stitching wrapped lines."""
        if not text:
            return []

        # Stitch URLs broken across lines
        stitched = re.sub(
            r"(https?://[^\s]+)-\r?\n\s*([a-zA-Z0-9\-._~%!$&'()*+,;=:@/?#]+)",
            r"\1\2",
            text
        )
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
                u = "http://" + u
            if u not in urls:
                urls.append(u)
        return urls
