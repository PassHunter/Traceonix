import os
from openai import AsyncOpenAI
import asyncio
import json
from datetime import datetime

# Initialize OpenRouter Client (OpenAI-Compatible)
API_KEY = os.environ.get("OPENROUTER_API_KEY", "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")
client = AsyncOpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=API_KEY,
    default_headers={
        "HTTP-Referer": "https://aegiscore.soc", # Optional for OpenRouter
        "X-Title": "AegisCore SOC Dashboard",    # Optional for OpenRouter
    }
)

class AegisIntelligence:
    def __init__(self):
        # Defaulting to Gemini 2.0 Flash via OpenRouter for high-speed forensics
        self.model_id = "google/gemini-2.0-flash-001"
        self.system_instruction = (
            "You are the AegisCore Forensic AI, a Tier-3 SOC Analyst. "
            "Your objective is to provide high-fidelity, natural-language forensic explanations "
            "for network alerts and raw log data. "
            "Be technically precise, authoritative, and provide actionable remediation steps. "
            "When explaining raw logs, break down headers, payloads, and anomalous patterns. "
            "Maintain a professional, Cyber-Noir cybersecurity persona."
        )

    async def get_initial_forensic_explanation(self, alert_data: dict):
        """Generates the first 'Deep Forensic Scan' breakdown via OpenRouter."""
        prompt = f"Analyze this alert: {alert_data.get('summary')} | {alert_data.get('content')} | {alert_data.get('source_ip')}"
        
        try:
            response = await client.chat.completions.create(
                model=self.model_id,
                messages=[
                    {"role": "system", "content": self.system_instruction},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error connecting to Aegis Intelligence: {str(e)}. Please check your OpenRouter API Key."

    async def continue_investigation(self, alert_id: int, user_message: str, history: list = None):
        """Handles intermediate chat sessions with history context via OpenRouter."""
        try:
            messages = [{"role": "system", "content": self.system_instruction}]
            
            # Map history to OpenAI format
            if history:
                for item in history:
                    # History items from app.py are role: parts dicts
                    role = "user" if item["role"] == "user" else "assistant"
                    # Handle both 'parts' (Gemini style) and 'content' (OpenAI style)
                    content = item.get("content") or item["parts"][0]
                    messages.append({"role": role, "content": content})
            
            # Add new message
            messages.append({"role": "user", "content": user_message})

            response = await client.chat.completions.create(
                model=self.model_id,
                messages=messages,
                temperature=0.7
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"The forensic uplink was interrupted: {str(e)}"

# Instantiate the engine
aegis_ai = AegisIntelligence()
