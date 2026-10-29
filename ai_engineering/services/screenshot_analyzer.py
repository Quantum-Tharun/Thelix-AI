"""
Screenshot Analyzer Adapter (Legacy Compatibility)
Delegates image preprocessing to the authoritative OCRPipeline.
Visual UI pattern matching remains an experimental prototype.
"""
import base64
import cv2
import numpy as np
from ai_engineering.ocr.ocr_pipeline import OCRPipeline


class ScreenshotAnalyzer:
    """
    OpenCV preprocessing pipeline adapter for screenshots.
    Delegates preprocessing to the authoritative OCRPipeline.
    """

    @staticmethod
    def decode_base64_image(image_base64: str) -> np.ndarray:
        """Decodes base64 string to OpenCV image format."""
        image_bytes = base64.b64decode(image_base64)
        np_arr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
        return img

    @staticmethod
    def preprocess_for_ocr(image: np.ndarray) -> np.ndarray:
        """
        Enhances contrast, binarizes, and removes noise to improve OCR accuracy.
        Delegates to OCRPipeline's tested OpenCV preprocessing routine.
        """
        pipeline = OCRPipeline()
        return pipeline.preprocess_image(image)

    @staticmethod
    def detect_suspicious_ui_patterns(image: np.ndarray) -> str:
        """
        Experimental prototype for template matching or heuristic UI detection.
        Currently disconnected from production inference.
        """
        return "unknown"

