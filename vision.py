import base64
from config import OPENAI_API_KEY, OPENAI_VISION_MODEL

def inspect_image_with_vision(image_bytes: bytes, mime: str):
    if not OPENAI_API_KEY:
        return None, "vision_not_configured"
    try:
        from openai import OpenAI
        client = OpenAI(api_key=OPENAI_API_KEY)
        encoded = base64.b64encode(image_bytes).decode("utf-8")
        response = client.chat.completions.create(
            model=OPENAI_VISION_MODEL,
            temperature=0,
            response_format={"type":"json_object"},
            messages=[
                {"role":"system","content":(
                    "You are a cautious multilingual scam-screening assistant. Analyze the provided screenshot for "
                    "potential fraud indicators. Return JSON with keys risk_score (0-100), category, language, "
                    "signals (array of objects with code,label,detail,severity), explanation, recommendations (array). "
                    "Do not claim certainty. Distinguish visible evidence from inference. If unclear, say so."
                )},
                {"role":"user","content":[
                    {"type":"text","text":"Analyze this screenshot for scam indicators. Languages may be English, Chinese or Malay."},
                    {"type":"image_url","image_url":{"url":f"data:{mime};base64,{encoded}"}}
                ]}
            ]
        )
        import json
        data = json.loads(response.choices[0].message.content)
        return data, "vision_api"
    except Exception:
        return None, "vision_error"
