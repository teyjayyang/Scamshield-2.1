import re
from language import TEXT_LABELS, detect_language
from features import url_features

DISCLAIMER = ("Screening assistance only. Scores are model/rule estimates, not proof or a probability of fraud. "
              "Verify independently with the relevant organization. Do not share OTPs, PINs or passwords.")

TEXT_RULES = [
 ("urgent", r"\burgent\b|immediately|act now|final warning|segera|dengan segera|立即|马上|紧急", "high", 16),
 ("credential", r"\botp\b|one.time password|verification code|password|pin\b|验证码|密码|kata laluan|kod pengesahan", "high", 28),
 ("impersonation", r"bank|account suspended|account blocked|pihak berkuasa|polis|kastam|银行|警方|海关|akaun disekat", "medium", 18),
 ("payment", r"transfer|wire|pay now|payment|deposit|crypto|wallet|转账|付款|汇款|pindahan|bayaran", "high", 18),
 ("link", r"click here|login now|verify your account|update your details|点击链接|验证账户|kemas kini akaun|klik pautan", "medium", 16),
 ("reward", r"winner|prize|claim your reward|free gift|中奖|奖品|hadiah percuma|tuntut hadiah", "medium", 12),
 ("threat", r"arrest|warrant|fine|legal action|逮捕|罚款|tangkapan|waran|denda", "high", 18),
]

def text_rule_signals(text, lang):
    labels = TEXT_LABELS.get(lang, TEXT_LABELS["en"])
    signals, score = [], 5
    for code, pattern, severity, weight in TEXT_RULES:
        if re.search(pattern, text, re.I):
            signals.append({"code":code,"label":labels.get(code,code),"detail":"Matched a known risk pattern; verify the context.","severity":severity})
            score += weight
    if not signals:
        signals.append({"code":"no_match","label":"No common scam pattern matched","detail":"A clean rule check does not prove that the message is safe.","severity":"low"})
    return min(score, 96), signals

def url_rule_signals(url):
    f = url_features(url)
    signals=[]; score=5
    def add(code,label,detail,weight):
        nonlocal score
        score += weight
        signals.append({"code":code,"label":label,"detail":detail,"severity":"high" if weight>=18 else "medium"})
    if not f["https"]: add("no_https","No HTTPS","The URL does not use HTTPS. HTTPS alone is not proof of safety.",15)
    if f["has_ip"]: add("ip_host","Raw IP address","The host is an IP address rather than a conventional domain.",22)
    if f["has_punycode"]: add("punycode","Punycode domain","Check for visually similar internationalized characters.",22)
    if f["has_at"]: add("at_symbol","At-sign in URL","The URL contains an @ character; inspect the actual hostname carefully.",15)
    if f["subdomain_count"]>=3: add("deep_subdomain","Many subdomains","Unusually deep subdomain structure.",12)
    if f["has_login_word"]: add("login_keyword","Sensitive login wording","Login/account-related words appear in the URL.",8)
    if f["host_length"]>35: add("long_host","Long hostname","The hostname is unusually long.",8)
    if not signals:
        signals.append({"code":"no_obvious_flag","label":"No obvious structural red flag","detail":"This does not establish that the destination is legitimate.", "severity":"low"})
    return min(score,96), signals
