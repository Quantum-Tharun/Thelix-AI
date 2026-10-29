"""
Ollama Gemma LLM Provider
Integrates local Ollama Gemma instances behind the pluggable LLMProvider interface.
Applies bounded timeouts, availability checks, health probes, and structured error handling.
"""
import asyncio
import time
import json
import logging
from typing import Optional, Dict, Any
import urllib.request
import urllib.error

from llm.provider import LLMProvider
from llm.schemas import LLMResult

logger = logging.getLogger("thelix.ollama_provider")


class OllamaGemmaProvider(LLMProvider):
    """
    Local Ollama Gemma LLM implementation.
    Communicates with local Ollama daemon via native HTTP REST API.
    Does not require external python packages and guarantees strict local boundary.
    """
    provider_name = "ollama_gemma"

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model_name: str = "gemma-2b-v3",
        timeout_seconds: float = 15.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.model_name = model_name
        self.timeout_seconds = timeout_seconds

    def check_availability(self) -> Dict[str, Any]:
        """
        Synchronous non-blocking health check against local Ollama daemon.
        Returns dict with status, reachable boolean, and available models.
        """
        url = f"{self.base_url}/api/tags"
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    models = [m.get("name", "") for m in data.get("models", [])]
                    model_found = any(self.model_name in m for m in models)
                    return {
                        "reachable": True,
                        "model_available": model_found,
                        "available_models": models,
                        "status": "ready" if model_found else "model_missing",
                    }
        except urllib.error.URLError:
            pass
        except Exception as e:
            logger.debug(f"Ollama availability check exception: {e}")

        return {
            "reachable": False,
            "model_available": False,
            "available_models": [],
            "status": "unreachable",
        }

    async def generate_text(
        self,
        system_instruction: str,
        user_prompt: str,
        timeout_seconds: float = 15.0,
    ) -> LLMResult:
        """
        Generates text via Ollama /api/generate endpoint with bounded timeout.
        """
        start_time = time.time()
        timeout = timeout_seconds or self.timeout_seconds

        payload = {
            "model": self.model_name,
            "prompt": f"{system_instruction}\n\n{user_prompt}",
            "stream": False,
            "options": {
                "temperature": 0.2,
                "num_predict": 1024,
            },
        }

        url = f"{self.base_url}/api/generate"
        post_data = json.dumps(payload).encode("utf-8")

        def _do_http_call() -> Dict[str, Any]:
            req = urllib.request.Request(
                url,
                data=post_data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    return json.loads(resp.read().decode("utf-8"))
                raise RuntimeError(f"Ollama returned HTTP status {resp.status}")

        try:
            res_data = await asyncio.wait_for(
                asyncio.to_thread(_do_http_call),
                timeout=timeout,
            )
            latency = int((time.time() - start_time) * 1000)
            text = res_data.get("response", "").strip()

            return LLMResult(
                provider=self.provider_name,
                model=self.model_name,
                success=True,
                content=text,
                latency_ms=latency,
            )
        except asyncio.TimeoutError:
            latency = int((time.time() - start_time) * 1000)
            return LLMResult(
                provider=self.provider_name,
                model=self.model_name,
                success=False,
                error=f"Ollama Gemma request timed out after {timeout}s",
                latency_ms=latency,
            )
        except urllib.error.URLError as e:
            latency = int((time.time() - start_time) * 1000)
            return LLMResult(
                provider=self.provider_name,
                model=self.model_name,
                success=False,
                error=f"Ollama service unreachable at {self.base_url} ({e.reason})",
                latency_ms=latency,
            )
        except Exception as e:
            latency = int((time.time() - start_time) * 1000)
            return LLMResult(
                provider=self.provider_name,
                model=self.model_name,
                success=False,
                error=f"Ollama Gemma inference error: {str(e)}",
                latency_ms=latency,
            )
