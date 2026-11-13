import re

def detect_language(text: str) -> str:
    if re.search(r"[\u4e00-\u9fff]", text):
        return "zh"
    low = text.lower()
    ms_words = ["anda", "akaun", "segera", "bayaran", "pengesahan", "bank", "pautan", "sila", "wang"]
    en_words = ["your", "account", "verify", "payment", "urgent", "bank", "click", "password", "claim"]
    ms = sum(w in low for w in ms_words)
    en = sum(w in low for w in en_words)
    if ms > en and ms:
        return "ms"
    if en:
        return "en"
    return "unknown"

TEXT_LABELS = {
 "en": {
  "urgent":"Urgent or pressure-based wording",
  "credential":"Request for password, PIN or one-time code",
  "impersonation":"Possible bank or authority impersonation",
  "payment":"Money transfer or payment request",
  "link":"Prompt to click a link or verify an account",
  "reward":"Unexpected prize or reward claim",
  "threat":"Threat of arrest, penalty or legal action"
 },
 "zh": {
  "urgent":"使用紧急或施压措辞",
  "credential":"要求提供密码、PIN 或一次性验证码",
  "impersonation":"疑似冒充银行或官方机构",
  "payment":"要求转账或付款",
  "link":"要求点击链接或验证账户",
  "reward":"异常奖品或奖励通知",
  "threat":"以逮捕、罚款或法律行动进行威胁"
 },
 "ms": {
  "urgent":"Bahasa mendesak atau memberi tekanan",
  "credential":"Meminta kata laluan, PIN atau kod OTP",
  "impersonation":"Kemungkinan penyamaran bank atau pihak berkuasa",
  "payment":"Permintaan pindahan wang atau bayaran",
  "link":"Arahan klik pautan atau sahkan akaun",
  "reward":"Tuntutan hadiah atau ganjaran yang tidak dijangka",
  "threat":"Ancaman tangkapan, penalti atau tindakan undang-undang"
 }
}
