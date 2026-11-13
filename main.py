from fastapi import FastAPI, Depends, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from uuid import uuid4
from time import time
from collections import defaultdict, deque
from pathlib import Path
import re
from config import APP_NAME, ALLOW_ORIGINS, MAX_UPLOAD_MB
from schemas import TextRequest, URLRequest
from security import verify_api_key
from language import detect_language
from rules import text_rule_signals, url_rule_signals, DISCLAIMER
from model_service import model_service
from storage import save_analysis, upload_evidence
from vision import inspect_image_with_vision
from cloud_ai import analyze_text_with_cloud

app = FastAPI(title=APP_NAME, version="2.0.0")
# Lightweight per-process protection for public demo deployments. Use a managed
# gateway/WAF for production multi-instance deployments.
_request_times = defaultdict(deque)
@app.middleware("http")
async def basic_rate_limit(request, call_next):
    if request.url.path.startswith("/api/analyze/"):
        ip = request.client.host if request.client else "unknown"
        now = time(); q = _request_times[ip]
        while q and now - q[0] > 60: q.popleft()
        if len(q) >= 30:
            from fastapi.responses import JSONResponse
            return JSONResponse({"detail":"Rate limit reached. Please try again in one minute."}, status_code=429)
        q.append(now)
    return await call_next(request)
app.add_middleware(CORSMiddleware, allow_origins=ALLOW_ORIGINS, allow_credentials=False,
                   allow_methods=["GET","POST"], allow_headers=["*"])

def risk_level(score):
    return "high" if score >= 65 else "medium" if score >= 30 else "low"

def persist(modality, score, category, language, model_status, explanation, signals, recommendations, evidence_path=None):
    analysis_id = str(uuid4())
    record = {
      "id":analysis_id, "modality":modality, "risk_score":int(score), "risk_level":risk_level(int(score)),
      "category":category, "language":language, "model_status":model_status,
      "explanation":explanation, "signals":signals, "recommendations":recommendations,
      "evidence_path":evidence_path
    }
    saved = save_analysis(record)
    return analysis_id

def response(modality, score, category, language, status, explanation, signals, recommendations, analysis_id=None):
    return {
      "analysis_id":analysis_id, "modality":modality, "risk_score":int(max(0,min(100,score))),
      "risk_level":risk_level(int(score)), "category":category, "language":language,
      "model_status":status, "explanation":explanation, "signals":signals,
      "recommendations":recommendations, "disclaimer":DISCLAIMER
    }

@app.get("/api/health")
def health():
    return {"status":"ok","service":APP_NAME,"text_model_loaded":model_service.text_model is not None,
            "url_model_loaded":model_service.url_model is not None,
            "cloud_ai_configured": bool(__import__("config", fromlist=["OPENAI_API_KEY"]).OPENAI_API_KEY)}

@app.post("/api/analyze/text", dependencies=[Depends(verify_api_key)])
def analyze_text(req: TextRequest):
    lang = detect_language(req.text) if req.language == "auto" else req.language
    rule_score, signals = text_rule_signals(req.text, lang)
    probability, label, status = model_service.text_predict(req.text)
    if probability is not None:
        # Text model class convention: 1=scam, 0=legitimate
        model_score = int(probability*100) if str(label) in ("1","scam","fraud") else int((1-probability)*100)
        score = round(0.55*rule_score + 0.45*model_score)
        status = "trained_text_model+rules"
    else:
        score = rule_score
        status = "rules_fallback_text_model_not_trained"
    cloud, cloud_status = analyze_text_with_cloud(req.text, "text")
    if cloud:
        score = round(0.65*score + 0.35*int(cloud.get("risk_score", score)))
        signals.extend({"code":"cloud_ai","label":str(x),"severity":"review"} for x in cloud.get("signals", [])[:8])
        status += "+cloud_ai"
    else:
        status += "+" + cloud_status
    recommendations = ["Do not share OTPs, PINs, passwords or recovery codes.",
                       "Verify the sender through the organization's official app or published contact details.",
                       "If money was transferred, contact your bank immediately."]
    category = "possible_scam" if score >= 30 else "no_common_pattern_detected"
    analysis_id = persist("text",score,category,lang,status,"Text screened using multilingual patterns and, when available, a trained classifier.",signals,recommendations) if req.save_case else None
    return response("text",score,category,lang,status,"Text screened using multilingual patterns and, when available, a trained classifier.",signals,recommendations,analysis_id)

@app.post("/api/analyze/url", dependencies=[Depends(verify_api_key)])
def analyze_url(req: URLRequest):
    # Intentionally never fetch the user-supplied URL; avoids SSRF and malware execution.
    rule_score, signals = url_rule_signals(req.url)
    probability, status = model_service.url_predict(req.url)
    score = round(0.55*rule_score + 0.45*(probability*100)) if probability is not None else rule_score
    status = "trained_url_model+rules" if probability is not None else "rules_fallback_url_model_not_trained"
    cloud, cloud_status = analyze_text_with_cloud(req.url, "url")
    if cloud:
        score = round(0.65*score + 0.35*int(cloud.get("risk_score", score)))
        signals.extend({"code":"cloud_ai","label":str(x),"severity":"review"} for x in cloud.get("signals", [])[:8])
        status += "+cloud_ai"
    else:
        status += "+" + cloud_status
    recs = ["Do not open the link if you are unsure.","Check the exact registered domain, not only the displayed link text.",
            "Navigate to the service by typing its known official address."]
    analysis_id = persist("url",score,"possible_phishing" if score>=30 else "no_obvious_url_flags","unknown",status,
                          "URL structure analyzed without visiting the destination.",signals,recs) if req.save_case else None
    return response("url",score,"possible_phishing" if score>=30 else "no_obvious_url_flags","unknown",status,
                    "URL structure analyzed without visiting the destination.",signals,recs,analysis_id)

@app.post("/api/analyze/image", dependencies=[Depends(verify_api_key)])
async def analyze_image(file: UploadFile = File(...), save_case: bool = False):
    allowed = {"image/png","image/jpeg","image/webp"}
    if file.content_type not in allowed:
        raise HTTPException(415,"Only PNG, JPEG and WEBP images are accepted")
    content = await file.read()
    if len(content) > MAX_UPLOAD_MB*1024*1024:
        raise HTTPException(413,f"Image exceeds {MAX_UPLOAD_MB} MB limit")
    try:
        from PIL import Image
        import io
        im = Image.open(io.BytesIO(content))
        im.verify()
    except Exception:
        raise HTTPException(400,"Invalid or corrupted image")
    vision, status = inspect_image_with_vision(content,file.content_type)
    signals=[]; score=20; language="unknown"; category="image_review_required"
    explanation="Image received and validated. OCR/vision AI is not configured; no image-based verdict was produced."
    recs=["Manually inspect sender identity, payment details and URLs visible in the image.",
          "Never share OTPs, PINs or passwords.","Verify through the official organization channel."]
    if vision:
        score = int(vision.get("risk_score",20))
        signals = vision.get("signals",[])[:15]
        language = vision.get("language","unknown")
        category = vision.get("category","screenshot_scam_review")
        explanation = vision.get("explanation","Vision model analysis completed with uncertainty.")
        recs = vision.get("recommendations",recs)[:10]
    else:
        # OCR is optional and does not create a verdict by itself.
        try:
            import pytesseract, io
            from PIL import Image
            text = pytesseract.image_to_string(Image.open(io.BytesIO(content)))
            if text.strip():
                lang = detect_language(text)
                score, signals = text_rule_signals(text,lang)
                language = lang
                status = "ocr_rules_only_vision_not_configured"
                explanation = "OCR extracted text and rule checks found possible signals; image context was not analyzed by a vision model."
        except Exception:
            pass
    evidence_path = upload_evidence(file.filename or "evidence",content,file.content_type) if save_case else None
    analysis_id = persist("image",score,category,language,status,explanation,signals,recs,evidence_path) if save_case else None
    return response("image",score,category,language,status,explanation,signals,recs,analysis_id)

@app.get("/api/history", dependencies=[Depends(verify_api_key)])
def history():
    from storage import client
    c=client()
    if not c: return {"items":[],"note":"Supabase is not configured"}
    try:
        result=c.table("analyses").select("id,created_at,modality,risk_score,risk_level,category,language,model_status").order("created_at",desc=True).limit(50).execute()
        return {"items":result.data}
    except Exception:
        raise HTTPException(503,"Could not read analysis history; check Supabase schema and permissions")
