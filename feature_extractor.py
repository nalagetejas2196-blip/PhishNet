import re
import urllib.parse

SHORTENING_SERVICES = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
    'is.gd', 'buff.ly', 'adf.ly', 'tiny.cc', 'shorte.st'
]

PHISH_HINTS = [
    'login', 'signin', 'verify', 'secure', 'account', 'update',
    'banking', 'confirm', 'password', 'credential', 'free', 'lucky',
    'winner', 'prize', 'click', 'urgent', 'suspended', 'blocked'
]

def extract_features(url):
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.netloc
        path = parsed.path
        
        # Length features
        length_url = len(url)
        length_hostname = len(hostname)
        
        # IP address check
        ip = 1 if re.match(r'\d+\.\d+\.\d+\.\d+', hostname) else 0
        
        # Count special characters
        nb_dots = url.count('.')
        nb_hyphens = url.count('-')
        nb_at = url.count('@')
        nb_qm = url.count('?')
        nb_and = url.count('&')
        nb_or = url.count('|')
        nb_eq = url.count('=')
        nb_underscore = url.count('_')
        nb_tilde = url.count('~')
        nb_percent = url.count('%')
        nb_slash = url.count('/')
        nb_star = url.count('*')
        nb_colon = url.count(':')
        nb_comma = url.count(',')
        nb_semicolumn = url.count(';')
        nb_dollar = url.count('$')
        nb_space = url.count(' ')
        
        # WWW and COM count
        nb_www = url.lower().count('www')
        nb_com = url.lower().count('.com')
        nb_dslash = url.count('//')
        
        # HTTP in path
        http_in_path = 1 if 'http' in path.lower() else 0
        
        # HTTPS token
        https_token = 1 if parsed.scheme == 'https' else 0
        
        # Ratio of digits
        digits_url = sum(c.isdigit() for c in url)
        ratio_digits_url = digits_url / len(url) if len(url) > 0 else 0
        digits_host = sum(c.isdigit() for c in hostname)
        ratio_digits_host = digits_host / len(hostname) if len(hostname) > 0 else 0
        
        # Punycode
        punycode = 1 if 'xn--' in url.lower() else 0
        
        # Port
        port = 1 if parsed.port and parsed.port not in [80, 443] else 0
        
        # TLD in path/subdomain
        tld_in_path = 1 if re.search(r'\.(com|org|net|edu|gov)', path.lower()) else 0
        tld_in_subdomain = 1 if re.search(r'\.(com|org|net|edu|gov)\.', hostname.lower()) else 0
        
        # Abnormal subdomain
        subdomains = hostname.split('.')
        nb_subdomains = len(subdomains) - 2 if len(subdomains) > 2 else 0
        abnormal_subdomain = 1 if nb_subdomains > 2 else 0
        
        # Prefix suffix
        prefix_suffix = 1 if '-' in hostname else 0
        
        # Random domain (high consonant ratio)
        vowels = sum(1 for c in hostname.lower() if c in 'aeiou')
        consonants = sum(1 for c in hostname.lower() if c.isalpha() and c not in 'aeiou')
        random_domain = 1 if consonants > 0 and vowels / (vowels + consonants) < 0.3 else 0
        
        # Shortening service
        shortening_service = 1 if any(s in url.lower() for s in SHORTENING_SERVICES) else 0
        
        # Path extension
        path_extension = 1 if re.search(r'\.(exe|zip|rar|dmg|apk|bat|cmd)', path.lower()) else 0
        
        # Redirections
        nb_redirection = url.count('//')  - 1 if url.count('//') > 1 else 0
        nb_external_redirection = 1 if 'redirect' in url.lower() or 'redir' in url.lower() else 0
        
        # Word features
        words = re.split(r'[.\-_/=?&]', url)
        words = [w for w in words if w]
        length_words_raw = len(words)
        char_repeat = sum(url.count(c) > 3 for c in set(url))
        shortest_words_raw = min(len(w) for w in words) if words else 0
        shortest_word_host = min(len(w) for w in hostname.split('.')) if hostname else 0
        path_words = re.split(r'[/\-_=?&]', path)
        path_words = [w for w in path_words if w]
        shortest_word_path = min(len(w) for w in path_words) if path_words else 0
        longest_words_raw = max(len(w) for w in words) if words else 0
        longest_word_host = max(len(w) for w in hostname.split('.')) if hostname else 0
        longest_word_path = max(len(w) for w in path_words) if path_words else 0
        avg_words_raw = sum(len(w) for w in words) / len(words) if words else 0
        avg_word_host = sum(len(w) for w in hostname.split('.')) / len(hostname.split('.')) if hostname else 0
        avg_word_path = sum(len(w) for w in path_words) / len(path_words) if path_words else 0
        
        # Phishing hints
        phish_hints = sum(1 for hint in PHISH_HINTS if hint in url.lower())
        
        # Brand features (simplified)
        BRANDS = ['paypal', 'google', 'facebook', 'amazon', 'apple', 'microsoft', 'netflix', 'instagram']
        domain_in_brand = 1 if any(b in hostname.lower() for b in BRANDS) else 0
        brand_in_subdomain = 1 if nb_subdomains > 0 and any(b in '.'.join(subdomains[:-2]).lower() for b in BRANDS) else 0
        brand_in_path = 1 if any(b in path.lower() for b in BRANDS) else 0
        
        # Suspicious TLD
        SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.link']
        suspecious_tld = 1 if any(url.lower().endswith(t) for t in SUSPICIOUS_TLDS) else 0
        
        # Statistical report (simplified)
        statistical_report = 1 if ip == 1 or suspecious_tld == 1 else 0
        
        # Web page features (default values since we're not fetching)
        nb_hyperlinks = 0
        ratio_intHyperlinks = 0
        ratio_extHyperlinks = 0
        ratio_nullHyperlinks = 0
        nb_extcss = 0
        ratio_intRedirection = 0
        ratio_extRedirection = 0
        ratio_intErrors = 0
        ratio_extErrors = 0
        login_form = 1 if 'login' in url.lower() or 'signin' in url.lower() else 0
        external_favicon = 0
        links_in_tags = 0
        submit_email = 1 if 'submit' in url.lower() else 0
        ratio_intMedia = 0
        ratio_extMedia = 0
        sfh = 0
        iframe = 0
        popup_window = 0
        safe_anchor = 0
        onmouseover = 0
        right_clic = 0
        empty_title = 0
        domain_in_title = 0
        domain_with_copyright = 0
        
        # WHOIS features (default)
        whois_registered_domain = 0
        domain_registration_length = 0
        domain_age = 0
        web_traffic = 0
        dns_record = 1
        google_index = 1
        page_rank = 0

        features = [
            length_url, length_hostname, ip, nb_dots, nb_hyphens, nb_at,
            nb_qm, nb_and, nb_or, nb_eq, nb_underscore, nb_tilde, nb_percent,
            nb_slash, nb_star, nb_colon, nb_comma, nb_semicolumn, nb_dollar,
            nb_space, nb_www, nb_com, nb_dslash, http_in_path, https_token,
            ratio_digits_url, ratio_digits_host, punycode, port, tld_in_path,
            tld_in_subdomain, abnormal_subdomain, nb_subdomains, prefix_suffix,
            random_domain, shortening_service, path_extension, nb_redirection,
            nb_external_redirection, length_words_raw, char_repeat,
            shortest_words_raw, shortest_word_host, shortest_word_path,
            longest_words_raw, longest_word_host, longest_word_path,
            avg_words_raw, avg_word_host, avg_word_path, phish_hints,
            domain_in_brand, brand_in_subdomain, brand_in_path, suspecious_tld,
            statistical_report, nb_hyperlinks, ratio_intHyperlinks,
            ratio_extHyperlinks, ratio_nullHyperlinks, nb_extcss,
            ratio_intRedirection, ratio_extRedirection, ratio_intErrors,
            ratio_extErrors, login_form, external_favicon, links_in_tags,
            submit_email, ratio_intMedia, ratio_extMedia, sfh, iframe,
            popup_window, safe_anchor, onmouseover, right_clic, empty_title,
            domain_in_title, domain_with_copyright, whois_registered_domain,
            domain_registration_length, domain_age, web_traffic, dns_record,
            google_index, page_rank
        ]

        return features

    except:
        return [0] * 87