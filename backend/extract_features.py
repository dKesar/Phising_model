import tldextract
from urllib.parse import urlparse

def extract_features(url):
    features = {}

    # Основные признаки
    features["length_url"] = len(url)
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path
    features["length_hostname"] = len(hostname)
    features["nb_dots"] = url.count(".")
    features["nb_hyphens"] = url.count("-")
    features["nb_at"] = url.count("@")
    features["https"] = int(url.startswith("https"))
    features["punycode"] = int("xn--" in url)

    # TLD и поддомены
    ext = tldextract.extract(url)
    features["tld_length"] = len(ext.suffix)
    features["nb_subdomains"] = hostname.count(".")
    features["nb_dash_hostname"] = hostname.count("-")
    features["nb_dot_hostname"] = hostname.count(".")

    # Путь и символы
    features["path_length"] = len(path)
    features["nb_slashes_path"] = path.count("/")
    features["nb_qm"] = url.count("?")
    features["nb_and"] = url.count("&")
    features["nb_equal"] = url.count("=")
    features["nb_percent"] = url.count("%")
    features["nb_dollar"] = url.count("$")
    features["nb_underscore"] = url.count("_")
    features["nb_tilde"] = url.count("~")
    features["nb_star"] = url.count("*")
    features["nb_colon"] = url.count(":")
    features["nb_semicolon"] = url.count(";")
    features["nb_comma"] = url.count(",")
    features["nb_hash"] = url.count("#")
    features["nb_exclam"] = url.count("!")
    features["nb_brackets"] = url.count("[") + url.count("]") + url.count("(") + url.count(")")
    features["nb_plus"] = url.count("+")
    features["nb_pipe"] = url.count("|")

    # Цифры и буквы
    digits = sum(c.isdigit() for c in url)
    letters = sum(c.isalpha() for c in url)
    features["ratio_digits_url"] = digits / len(url) if len(url) > 0 else 0
    features["ratio_letters_url"] = letters / len(url) if len(url) > 0 else 0

    # DNS / traffic / Google / PageRank
    features["dns_record"] = 0
    features["google_index"] = 0
    features["page_rank"] = 0
    features["web_traffic"] = 0
    features["nb_query_params"] = path.count("?")
    features["nb_path_segments"] = len(path.split("/")) - 1
    features["ends_with_html"] = int(path.endswith(".html"))  # 38-й признак

    return features