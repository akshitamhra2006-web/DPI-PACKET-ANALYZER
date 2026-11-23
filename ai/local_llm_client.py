"""
DPI & Packet Analyzer — Local LLM Client & Health Monitor
=========================================================
Connects optionally to local open-source LLM instances (Ollama, vLLM, LM Studio)
without requiring internet access, paid API keys, or cloud services.
Gracefully detects service availability and enforces strict timeouts.
"""

import urllib.request
import urllib.error
import json
import time
from typing import Dict, Any, Optional

DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434"
DEFAULT_MODEL = "llama3.2:latest"

class LocalLLMClient:
    """
    Client for local model inference with proactive availability checks,
    timeout enforcement, and graceful offline degradation.
    """
    def __init__(
        self,
        base_url: str = DEFAULT_OLLAMA_URL,
        model_name: str = DEFAULT_MODEL,
        enabled: bool = True,
        timeout_seconds: float = 3.0
    ):
        self.base_url = base_url.rstrip("/")
        self.model_name = model_name
        self.enabled = enabled
        self.timeout_seconds = timeout_seconds

    def check_health(self) -> Dict[str, Any]:
        """
        Check if local LLM service is active and responsive.
        """
        if not self.enabled:
            return {
                "available": False,
                "reason": "Local LLM integration is disabled by configuration.",
                "provider": "NONE"
            }

        url = f"{self.base_url}/api/tags"
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    models = [m.get("name") for m in data.get("models", [])]
                    has_model = self.model_name in models or len(models) > 0
                    return {
                        "available": True,
                        "provider": "Ollama (Local)",
                        "endpoint": self.base_url,
                        "active_model": self.model_name if self.model_name in models else (models[0] if models else self.model_name),
                        "available_models": models
                    }
        except Exception as e:
            pass

        return {
            "available": False,
            "reason": f"No active local LLM service reachable at {self.base_url}.",
            "provider": "NONE",
            "fallback_mode": "DETERMINISTIC_EVIDENCE_ENGINE"
        }

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> Optional[str]:
        """
        Generate response from local LLM, returning None if service is offline.
        """
        if not self.enabled:
            return None

        url = f"{self.base_url}/api/generate"
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "system": system_prompt or "You are a network security analyst assistant.",
            "stream": False,
            "options": {
                "temperature": 0.2,
                "top_p": 0.9,
                "num_predict": 512
            }
        }

        try:
            body = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                if resp.status == 200:
                    res_data = json.loads(resp.read().decode("utf-8"))
                    return res_data.get("response")
        except Exception:
            return None
        return None
