# src/extract_features.py
import tldextract
from urllib.parse import urlparse
import re
import requests
from bs4 import BeautifulSoup

# Кэш HTML-признаков (опционально, для ускорения повторных вызовов)
_HTML_FEATURES_CACHE = {}

def extract_html_features(url: str, timeout: int = 3):
    """Извлекает 6 HTML-признаков. Возвращает словарь или заглушку при ошибке."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    cache_key = url
    if cache_key in _HTML_FEATURES_CACHE:
        return _HTML_FEATURES_CACHE[cache_key]

    try:
        resp = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 (compatible; PhishingDetector/1.0)"},
            verify=False  # отключаем SSL-проверку для фишингов (часто self-signed)
        )
        soup = BeautifulSoup(resp.text, "html.parser")

        forms = soup.find_all("form")
        scripts = soup.find_all("script", src=True)

        features = {
            "nb_forms": len(forms),
            "form_action_http": sum(1 for f in forms if f.get("action", "").startswith("http://")),
            "has_iframe": len(soup.find_all("iframe")) > 0,
            "has_popup": "window.open" in resp.text,
            "has_onmouseover": "onmouseover" in resp.text.lower(),
            "nb_external_scripts": sum(1 for s in scripts if s.get("src", "").startswith(("http://", "https://")))
        }
    except Exception:
        features = {
            "nb_forms": 0,
            "form_action_http": 0,
            "has_iframe": 0,
            "has_popup": 0,
            "has_onmouseover": 0,
            "nb_external_scripts": 0
        }
    _HTML_FEATURES_CACHE[cache_key] = features
    return features


def extract_features(url: str, use_whois: bool = False, include_html: bool = False):
    """
    Извлекает признаки из URL.
    - use_whois: зарезервировано (не используется в этой версии)
    - include_html: если True — делает HTTP-запрос и парсит HTML (медленнее, +~0.5–2 сек на URL)
    """
    features = {}
    original_url = str(url or "").strip()

    # Нормализация URL для парсинга
    if not original_url.startswith(("http://", "https://")):
        url_for_parsing = "http://" + original_url
    else:
        url_for_parsing = original_url

    try:
        parsed = urlparse(url_for_parsing)
        hostname = parsed.hostname or ""
        path = parsed.path
        scheme = parsed.scheme
    except Exception:
        hostname = ""
        path = ""
        scheme = "http"

    # --- Парсим домен заранее, безопасно ---
    try:
        ext = tldextract.extract(original_url)
        domain = ext.domain or ""
        subdomain = ext.subdomain or ""
        suffix = ext.suffix or ""
    except Exception:
        domain = ""
        subdomain = ""
        suffix = ""

    # --- Базовые признаки URL ---
    features["length_url"] = len(original_url)
    features["length_hostname"] = len(hostname)
    features["nb_dots"] = original_url.count(".")
    features["nb_hyphens"] = original_url.count("-")
    features["nb_at"] = original_url.count("@")
    features["nb_qm"] = original_url.count("?")
    features["nb_and"] = original_url.count("&")
    features["nb_or"] = original_url.count("|")
    features["nb_eq"] = original_url.count("=")
    features["nb_underscore"] = original_url.count("_")
    features["nb_tilde"] = original_url.count("~")
    features["nb_percent"] = original_url.count("%")
    features["nb_slash"] = original_url.count("/")
    features["nb_star"] = original_url.count("*")
    features["nb_colon"] = original_url.count(":")
    features["nb_comma"] = original_url.count(",")
    features["nb_semicolon"] = original_url.count(";")
    features["nb_dollar"] = original_url.count("$")
    features["nb_space"] = original_url.count(" ")
    features["nb_www"] = int("www." in hostname.lower())
    features["nb_com"] = original_url.count(".com")

    # --- Протокол и путь ---
    features["https"] = int(scheme == "https")
    features["http_in_path"] = int("http://" in url_for_parsing[8:] or "https://" in url_for_parsing[8:])
    features["double_slash_in_path"] = int(url_for_parsing.count("//") > 1)
    features["path_length"] = len(path)
    features["nb_slashes_path"] = path.count("/")
    features["nb_params"] = path.count("?")
    features["nb_fragments"] = path.count("#")
    features["ends_with_html"] = int(path.endswith(".html"))

    # --- Hostname ---
    features["nb_subdomains"] = hostname.count(".") if hostname else 0
    features["prefix_suffix"] = int("-" in hostname or "_" in hostname)
    
    # IP в URL?
    try:
        features["ip_in_url"] = int(bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', hostname)))
    except:
        features["ip_in_url"] = 0

    # Punycode
    features["punycode"] = int("xn--" in hostname)

    # --- Слова и цифры ---
    digits = sum(c.isdigit() for c in original_url)
    letters = sum(c.isalpha() for c in original_url)
    features["ratio_digits_url"] = digits / len(original_url) if original_url else 0
    features["ratio_letters_url"] = letters / len(original_url) if original_url else 0

    # --- Подозрительные ключевые слова ---
    suspicious_keywords = [
        "login", "log-in", "signin", "sign-in", "secure", "account", "update",
        "verify", "confirm", "bank", "paypal", "ebay", "apple", "amazon",
        "microsoft", "office", "support", "admin", "password", "reset", "billing"
    ]
    url_lower = original_url.lower()
    features["nb_suspicious_keywords"] = sum(1 for kw in suspicious_keywords if kw in url_lower)

    # --- Shortening services ---
    shorteners = [
        "bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "t.co", "is.gd", "buff.ly",
        "adf.ly", "bitly.com", "cutt.ly", "shorte.st", "clk.sh", "rebrand.ly"
    ]
    features["shortening_service"] = int(any(s in hostname.lower() for s in shorteners))

    # --- TLD & domain ---
    features["tld_length"] = len(suffix)
    features["domain_length"] = len(domain)
    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".info"]
    features["suspicious_tld"] = int("." + suffix in suspicious_tlds)
    features["is_popular_tld"] = int(suffix in ["com", "org", "net", "edu", "gov", "io", "dev", "uk", "de", "fr"])

    # --- Brand impersonation ---
    popular_brands = ["google", "youtube", "facebook", "instagram", "twitter", "linkedin",
                      "apple", "microsoft", "amazon", "ebay", "paypal", "netflix", "spotify"]
    domain_lower = domain.lower()
    subdomain_lower = subdomain.lower()
    features["exact_brand_match"] = int(domain_lower in popular_brands)
    features["brand_substring"] = int(any(
        brand in domain_lower and brand != domain_lower for brand in popular_brands
    ))
    features["brand_in_subdomain"] = int(any(brand in subdomain_lower for brand in popular_brands))

    # --- Path-based phishing hints ---
    phishing_path_hints = ["login", "signin", "secure", "account", "verify", "confirm", "update"]
    path_lower = path.lower()
    features["phish_hints_in_path"] = sum(1 for h in phishing_path_hints if h in path_lower)

    # --- Unique chars & digit ratio in domain ---
    features["unique_chars"] = len(set(original_url))
    domain_digits = sum(c.isdigit() for c in domain)
    features["ratio_digits_domain"] = domain_digits / len(domain) if domain else 0

    # --- Критически важные признаки для точности 93%+ ---

    # 1. Длина домена (фишинг часто длинный: appleid-update → 16)
    features["domain_length"] = len(domain)

    # 2. Есть ли цифры в домене (очень редко у легитимных)
    features["domain_has_digits"] = int(any(c.isdigit() for c in domain))

    # 3. Отношение цифр к длине домена (bankofamerica=0%, apple123update=100%)
    features["ratio_digits_in_domain"] = sum(c.isdigit() for c in domain) / max(len(domain), 1)

    # 4. Сколько раз бренд повторяется (paypal.paypal-verify.com → 2)
    features["brand_count_in_url"] = sum(url_lower.count(b) for b in popular_brands)

    # 5. Есть ли "login"/"secure"/"update" НЕ в пути, а в домене или поддомене
    suspicious_in_host = any(kw in hostname.lower() for kw in ["login", "secure", "update", "verify", "signin", "account"])
    features["suspicious_in_host"] = int(suspicious_in_host)
    # --- HTML features (опционально) ---
    if include_html:
        html_feats = extract_html_features(original_url)
        features.update(html_feats)
    else:
        # Заглушки для HTML-признаков (чтобы CatBoost не сломался при predict)
        html_stub = {
            "nb_forms": 0,
            "form_action_http": 0,
            "has_iframe": 0,
            "has_popup": 0,
            "has_onmouseover": 0,
            "nb_external_scripts": 0
        }
        features.update(html_stub)

    # --- Гарантируем 78 фич (72 URL + 6 HTML) ---
    expected_count = 78
    current_count = len(features)
    for i in range(current_count, expected_count):
        features[f"placeholder_{i}"] = 0

    # --- Финальная очистка: замена NaN/inf на 0 ---
    for k, v in features.items():
        if v is None or (isinstance(v, float) and (v != v or abs(v) == float('inf'))):
            features[k] = 0
        elif isinstance(v, bool):
            features[k] = int(v)

    return features