"""Optional server-side AI reasoning. API keys remain on the backend only."""
import json
from config import OPENAI_API_KEY, OPENAI_VISION_MODEL


def analyze_text_with_cloud(text: str, modality: str = "text"):
    if not OPENAI_API_KEY:
        return None, "cloud_ai_not_configured"
    try:
        from openai import OpenAI
        client = OpenAI(api_key=OPENAI_API_KEY)
        model = OPENAI_VISION_MODEL
        prompt = (
            "Assess this user-submitted content for scam indicators. It may be English, Simplified Chinese, "
            "or Bahasa Melayu. Be cautious: do not claim certainty and do not treat urgency alone as proof. "
            "Return ONLY JSON with risk_score (integer 0-100), category, language, explanation, "
            "signals (array of short evidence strings), recommendations (array of short actions). "
            "Clearly distinguish observed evidence from inference."
        )
        r = client.chat.completions.create(
            model=model, temperature=0,
            response_format={"type": "json_object"},
            messages=[{"role": "system", "content": prompt},
                      {"role": "user", "content": f"Modality: {modality}\nContent:\n{text[:12000]}"}]
        )
        data = json.loads(r.choices[0].message.content)
        data["risk_score"] = max(0, min(100, int(data.get("risk_score", 0))))
        data["signals"] = [str(x)[:500] for x in data.get("signals", [])[:12]]
        data["recommendations"] = [str(x)[:500] for x in data.get("recommendations", [])[:8]]
        return data, "cloud_ai"
    except Exception:
        return None, "cloud_ai_error"
