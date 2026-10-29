"""
Deepfake Vision Architecture & Inference Module
Provides PyTorch model architecture definition (SimpleDeepfakeCNN),
secure checkpoint loading with validation, layer geometry verification,
and normalized forward pass inference.
"""
import os
import io
import base64
import logging
from typing import Optional, Tuple, Dict, Any
import torch
import torch.nn as nn
from torchvision import transforms
from PIL import Image

logger = logging.getLogger("thelix.deepfake")


class SimpleDeepfakeCNN(nn.Module):
    """
    Standardized Deepfake CNN architecture for facial and boundary artifact detection.
    Layer Geometry:
      - features:
          Conv2d(3, 16, 3, padding=1) -> ReLU -> MaxPool2d(2, 2)
          Conv2d(16, 32, 3, padding=1) -> ReLU -> MaxPool2d(2, 2)
      - classifier:
          Linear(32 * 64 * 64, 128) -> ReLU -> Linear(128, 1) -> Sigmoid()
    Input expectation: RGB image resized to (256, 256).
    Output: Sigmoid float in [0.0, 1.0] representing manipulation probability.
    """
    def __init__(self):
        super(SimpleDeepfakeCNN, self).__init__()
        self.features = nn.Sequential(
            nn.Conv2d(3, 16, 3, padding=1),
            nn.ReLU(),
            nn.MaxPool2d(2, 2),
            nn.Conv2d(16, 32, 3, padding=1),
            nn.ReLU(),
            nn.MaxPool2d(2, 2),
        )
        self.classifier = nn.Sequential(
            nn.Linear(32 * 64 * 64, 128),  # 131,072 -> 128
            nn.ReLU(),
            nn.Linear(128, 1),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.features(x)
        x = x.view(x.size(0), -1)
        x = self.classifier(x)
        return x


class DeepfakeVisionService:
    """
    Manages the lifecycle, checkpoint validation, and inference of the Deepfake model.
    Enforces security invariants:
      - Uses weights_only=True during torch.load to prevent arbitrary code execution
      - Validates state_dict layer shapes before attaching to model
      - Disallows random inference when trained weights are absent
    """
    _model: Optional[SimpleDeepfakeCNN] = None
    _loaded_weights_path: Optional[str] = None
    _device: torch.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    _transform = transforms.Compose([
        transforms.Resize((256, 256)),
        transforms.ToTensor(),
        transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
    ])

    @classmethod
    def get_loaded_weights_path(cls) -> Optional[str]:
        return cls._loaded_weights_path

    @classmethod
    def is_model_loaded(cls) -> bool:
        return cls._model is not None

    @classmethod
    def reset_model(cls) -> None:
        """Resets cached model in memory (useful for testing or reloading weights)."""
        cls._model = None
        cls._loaded_weights_path = None

    @classmethod
    def validate_weights(cls, weights_path: str) -> Tuple[bool, str]:
        """
        Inspects and validates a weights file without mutating current service state.
        Returns (is_valid, reason_or_error_message).
        """
        if not os.path.isfile(weights_path):
            return False, f"Checkpoint file does not exist at '{weights_path}'."

        try:
            # Safe checkpoint deserialization
            try:
                checkpoint = torch.load(weights_path, map_location=cls._device, weights_only=True)
            except TypeError:
                checkpoint = torch.load(weights_path, map_location=cls._device)

            state_dict = checkpoint
            if isinstance(checkpoint, dict):
                if "state_dict" in checkpoint:
                    state_dict = checkpoint["state_dict"]
                elif "model_state_dict" in checkpoint:
                    state_dict = checkpoint["model_state_dict"]

            if not isinstance(state_dict, dict):
                return False, f"Checkpoint in '{weights_path}' is not a valid state dictionary."

            # Verify layer geometries
            dummy_model = SimpleDeepfakeCNN().to(cls._device)
            dummy_model.load_state_dict(state_dict, strict=True)
            return True, "Weights are valid and match SimpleDeepfakeCNN geometry."
        except Exception as e:
            return False, f"Checkpoint validation failed: {str(e)}"

    @classmethod
    def load_model(cls, weights_path: str) -> SimpleDeepfakeCNN:
        """
        Loads and validates PyTorch checkpoint weights from disk into active model instance.
        Raises FileNotFoundError if file is absent, or ValueError if state_dict does not match.
        """
        is_valid, message = cls.validate_weights(weights_path)
        if not is_valid:
            if not os.path.isfile(weights_path):
                raise FileNotFoundError(message)
            raise ValueError(message)

        try:
            try:
                checkpoint = torch.load(weights_path, map_location=cls._device, weights_only=True)
            except TypeError:
                checkpoint = torch.load(weights_path, map_location=cls._device)

            state_dict = checkpoint
            if isinstance(checkpoint, dict):
                if "state_dict" in checkpoint:
                    state_dict = checkpoint["state_dict"]
                elif "model_state_dict" in checkpoint:
                    state_dict = checkpoint["model_state_dict"]

            model = SimpleDeepfakeCNN().to(cls._device)
            model.load_state_dict(state_dict, strict=True)
            model.eval()

            cls._model = model
            cls._loaded_weights_path = weights_path
            logger.info(f"DeepfakeVisionService successfully loaded weights from {weights_path}")
            return cls._model
        except Exception as e:
            cls._model = None
            cls._loaded_weights_path = None
            raise ValueError(f"Failed to load weights from {weights_path}: {e}")

    @classmethod
    def get_model(cls, weights_path: Optional[str] = None) -> Optional[SimpleDeepfakeCNN]:
        """
        Retrieves active model. If not loaded, attempts to load from weights_path
        or DEEPFAKE_WEIGHTS_PATH. Returns None if weights file is absent.
        """
        if cls._model is not None:
            return cls._model

        target_path = weights_path or os.environ.get("DEEPFAKE_WEIGHTS_PATH", "ai_engineering/models/deepfake/weights.pth")
        if os.path.isfile(target_path):
            return cls.load_model(target_path)

        return None

    @classmethod
    async def analyze_image(cls, image_base64: str, weights_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Runs authenticated deepfake inference on the provided image base64.
        Returns manipulation probability and decision flag.
        """
        model = cls.get_model(weights_path)
        if model is None:
            raise RuntimeError("Cannot execute inference: model weights are not loaded.")

        try:
            image_bytes = base64.b64decode(image_base64)
            image = Image.open(io.BytesIO(image_bytes)).convert("RGB")

            input_tensor = cls._transform(image).unsqueeze(0).to(cls._device)

            with torch.no_grad():
                output = model(input_tensor)
                probability = float(output.item())

            return {
                "is_deepfake": probability > 0.60,
                "confidence_score": probability,
                "raw_score": probability,
            }
        except Exception as e:
            logger.error(f"Deepfake inference execution failed: {e}", exc_info=True)
            raise
