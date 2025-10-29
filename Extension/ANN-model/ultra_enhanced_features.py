"""
Ultra-Enhanced Feature Extraction for Phishing URL Detection
Version: 3.0 - Production Grade

New Features:
- Expanded whitelist (Top 100+ domains)
- Subdomain trust for whitelisted domains
- Domain age check via WHOIS
- SSL certificate validation
- Advanced pattern recognition
- Intelligent subdomain handling
"""

import re
import math
import unicodedata
from urllib.parse import urlparse
from collections import Counter
import socket
import ssl
import datetime
import warnings
warnings.filterwarnings('ignore')

# Try to import optional libraries
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    print("⚠️ python-whois not installed. Domain age checks disabled.")
    print("   Install with: pip install python-whois")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("⚠️ requests not installed. Some features disabled.")


# ========================================================================
# EXPANDED WHITELIST - Top 100+ Legitimate Domains
# ========================================================================

KNOWN_LEGITIMATE_DOMAINS = [
    # Tech Giants & Their Services
    'google.com', 'youtube.com', 'gmail.com', 'gstatic.com', 'googleapis.com', 'googleusercontent.com',
    'facebook.com', 'fb.com', 'fbcdn.net', 'twitter.com', 'x.com', 'twimg.com',
    'instagram.com', 'cdninstagram.com', 'linkedin.com', 'licdn.com',
    'microsoft.com', 'microsoftonline.com', 'windows.com', 'live.com', 'msn.com', 'bing.com', 'office.com', 'office365.com',
    'apple.com', 'icloud.com', 'me.com', 'apple.news', 'cdn-apple.com',
    'amazon.com', 'amazonws.com', 'awsstatic.com', 'cloudfront.net', 'netflix.com', 'nflximg.net',
    
    # Social Media & Communication
    'whatsapp.com', 'telegram.org', 't.me', 'discord.com', 'discordapp.com', 'discord.gg',
    'reddit.com', 'redd.it', 'redditmedia.com', 'pinterest.com', 'pinimg.com',
    'tumblr.com', 'snapchat.com', 'tiktok.com', 'zoom.us', 'zoomgov.com', 'slack.com', 'slack-edge.com',
    'skype.com', 'teams.microsoft.com', 'messenger.com', 'signal.org',
    
    # Tech & Development
    'github.com', 'githubusercontent.com', 'github.io', 'gitlab.com', 'bitbucket.org',
    'stackoverflow.com', 'stackexchange.com', 'serverfault.com', 'superuser.com',
    'w3schools.com', 'w3.org', 'mozilla.org', 'firefox.com', 'mdn.io',
    'npmjs.com', 'npm.io', 'nodejs.org', 'docker.com', 'docker.io', 'kubernetes.io',
    'jenkins.io', 'atlassian.com', 'jira.com', 'confluence.com',
    'codepen.io', 'jsfiddle.net', 'replit.com', 'glitch.com', 'codesandbox.io',
    
    # Cloud Services & Hosting
    'dropbox.com', 'dropboxusercontent.com', 'box.com', 'onedrive.com', 'sharepoint.com',
    'drive.google.com', 'docs.google.com', 'sheets.google.com',
    'wetransfer.com', 'mediafire.com', 'mega.nz', 'mega.io',
    
    # E-commerce & Retail
    'ebay.com', 'ebaystatic.com', 'alibaba.com', 'aliexpress.com', 'alicdn.com',
    'etsy.com', 'etsystatic.com', 'shopify.com', 'myshopify.com', 'shopifycdn.com',
    'walmart.com', 'target.com', 'bestbuy.com', 'costco.com', 'homedepot.com',
    'ikea.com', 'zara.com', 'hm.com', 'nike.com', 'adidas.com',
    
    # Financial & Banking
    'paypal.com', 'paypalobjects.com', 'stripe.com', 'square.com', 'venmo.com',
    'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com', 'usbank.com',
    'capitalone.com', 'americanexpress.com', 'discover.com', 'ally.com',
    'wise.com', 'transferwise.com', 'revolut.com', 'n26.com', 'monzo.com',
    
    # News & Media
    'cnn.com', 'cnn.it', 'bbc.com', 'bbc.co.uk', 'nytimes.com', 'nyt.com',
    'theguardian.com', 'guardian.co.uk', 'reuters.com', 'apnews.com', 'npr.org',
    'bloomberg.com', 'forbes.com', 'wsj.com', 'ft.com', 'economist.com',
    'washingtonpost.com', 'usatoday.com', 'time.com', 'newsweek.com',
    'techcrunch.com', 'theverge.com', 'wired.com', 'arstechnica.com', 'engadget.com',
    
    # Educational
    'wikipedia.org', 'wikimedia.org', 'wikidata.org', 'mediawiki.org',
    'coursera.org', 'udemy.com', 'udacity.com', 'khanacademy.org', 'edx.org', 'skillshare.com',
    'mit.edu', 'stanford.edu', 'harvard.edu', 'yale.edu', 'princeton.edu',
    'berkeley.edu', 'caltech.edu', 'columbia.edu', 'cornell.edu', 'upenn.edu',
    'oxford.ac.uk', 'cambridge.ac.uk', 'imperial.ac.uk', 'ucl.ac.uk',
    
    # Search Engines
    'bing.com', 'yahoo.com', 'duckduckgo.com', 'baidu.com', 'yandex.com', 'yandex.ru',
    'ask.com', 'aol.com', 'search.yahoo.com',
    
    # Entertainment & Streaming
    'spotify.com', 'scdn.co', 'soundcloud.com', 'bandcamp.com', 'pandora.com',
    'twitch.tv', 'vimeo.com', 'dailymotion.com', 'hulu.com', 'disneyplus.com',
    'hbomax.com', 'hbo.com', 'peacocktv.com', 'paramountplus.com', 'crunchyroll.com',
    'imdb.com', 'rottentomatoes.com', 'metacritic.com',
    
    # Gaming
    'steam.com', 'steamcommunity.com', 'steampowered.com', 'steamstatic.com',
    'epicgames.com', 'unrealengine.com', 'roblox.com', 'rbxcdn.com',
    'minecraft.net', 'mojang.com', 'ea.com', 'origin.com',
    'blizzard.com', 'battle.net', 'activision.com', 'ubisoft.com',
    'nintendo.com', 'playstation.com', 'xbox.com', 'riotgames.com', 'leagueoflegends.com',
    
    # Productivity & Collaboration
    'notion.so', 'notion.site', 'trello.com', 'asana.com', 'monday.com',
    'evernote.com', 'todoist.com', 'airtable.com', 'miro.com', 'figma.com',
    'canva.com', 'grammarly.com', 'lastpass.com', '1password.com', 'bitwarden.com',
    
    # AI & Modern Tech
    'openai.com', 'chat.openai.com', 'anthropic.com', 'claude.ai',
    'huggingface.co', 'kaggle.com', 'colab.research.google.com',
    'deepmind.com', 'midjourney.com', 'stability.ai', 'perplexity.ai',
    
    # Developer Tools & Platforms
    'vercel.com', 'vercel.app', 'netlify.com', 'netlify.app', 'heroku.com', 'herokuapp.com',
    'digitalocean.com', 'linode.com', 'vultr.com', 'cloudflare.com', 'cloudflare.net',
    'fastly.com', 'fastly.net', 'akamai.com', 'akamaized.net',
    'jsdelivr.net', 'unpkg.com', 'cdnjs.cloudflare.com', 'bootstrapcdn.com',
    
    # Business & Professional
    'salesforce.com', 'force.com', 'oracle.com', 'sap.com', 'ibm.com',
    'adobe.com', 'adobelogin.com', 'intuit.com', 'quickbooks.com',
    'zendesk.com', 'mailchimp.com', 'hubspot.com', 'shopify.com',
    'wordpress.com', 'wordpress.org', 'wp.com', 'automattic.com',
    'squarespace.com', 'wix.com', 'weebly.com', 'godaddy.com',
    
    # Email Services
    'gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com', 'protonmail.com', 'proton.me',
    'icloud.com', 'mail.com', 'aol.com', 'zoho.com', 'yandex.com',
    
    # Government & Organizations
    'gov', 'gov.uk', 'gov.au', 'gov.ca', 'gov.in', 'gouv.fr',
    'europa.eu', 'un.org', 'who.int', 'nasa.gov', 'space.gov',
    'nih.gov', 'cdc.gov', 'fda.gov', 'nist.gov',
    
    # Y Combinator & Startups
    'ycombinator.com', 'airbnb.com', 'stripe.com', 'coinbase.com',
    'doordash.com', 'instacart.com', 'robinhood.com',
    
    # Additional Popular Sites
    'medium.com', 'substack.com', 'quora.com', 'tripadvisor.com', 'yelp.com',
    'indeed.com', 'glassdoor.com', 'craigslist.org', 'weather.com', 'accuweather.com',
    'tesla.com', 'spacex.com', 'booking.com', 'expedia.com', 'airbnb.com',
    
    # CDN & Infrastructure
    'cloudfront.net', 'akamaihd.net', 'edgecastcdn.net', 'azureedge.net',
    'ytimg.com', 'ggpht.com', 'twimg.com', 'fbcdn.net'
]

# Trusted subdomains for major platforms
TRUSTED_SUBDOMAINS = {
    'google.com': ['accounts', 'mail', 'drive', 'docs', 'sheets', 'slides', 'forms', 'scholar', 'maps', 'calendar', 
                   'photos', 'play', 'cloud', 'firebase', 'analytics', 'ads', 'support', 'sites', 'translate',
                   'news', 'books', 'hangouts', 'meet', 'chat', 'classroom', 'keep', 'contacts', 'voice',
                   'finance', 'shopping', 'trends', 'patents', 'alerts', 'podcasts', 'myaccount'],
    'microsoft.com': ['login', 'account', 'outlook', 'office', 'azure', 'docs', 'support', 'answers', 'download',
                      'store', 'technet', 'msdn', 'developer', 'learn', 'visualstudio', 'devblogs'],
    'microsoftonline.com': ['login', 'account', 'portal', 'auth', 'secure', 'www', 'common', 'aad', 'graph',
                            'admin', 'compliance', 'security', 'teams'],
    'apple.com': ['support', 'icloud', 'appleid', 'developer', 'store', 'www', 'music', 'tv', 'news',
                  'podcasts', 'books', 'finance', 'maps', 'discussions', 'developer'],
    'amazon.com': ['aws', 'smile', 'music', 'prime', 'video', 'www', 'read', 'kdp', 'associates',
                   's3', 'cloudfront', 'console', 'developer'],
    'facebook.com': ['www', 'web', 'business', 'developers', 'm', 'l', 'secure', 'touch', 'upload'],
    'github.com': ['gist', 'raw', 'api', 'docs', 'help', 'pages', 'status', 'blog', 'education',
                   'enterprise', 'desktop', 'mobile', 'cli'],
    'gitlab.com': ['about', 'docs', 'forum', 'status', 'customers', 'learn'],
    'twitter.com': ['mobile', 'help', 'support', 'developer', 'api', 'analytics', 'ads', 'business'],
    'linkedin.com': ['www', 'help', 'business', 'learning', 'sales', 'talent', 'marketing'],
    'instagram.com': ['www', 'help', 'about', 'business', 'developers'],
    'reddit.com': ['www', 'old', 'new', 'mod', 'blog', 'support'],
    'youtube.com': ['www', 'studio', 'music', 'tv', 'gaming', 'kids', 'artists', 'creators'],
    'netflix.com': ['www', 'help', 'devices', 'media', 'jobs'],
    'spotify.com': ['www', 'open', 'accounts', 'support', 'artists', 'developers', 'news'],
    'dropbox.com': ['www', 'paper', 'help', 'business', 'developers'],
    'slack.com': ['api', 'status', 'help', 'slack-redir'],
    'zoom.us': ['www', 'support', 'marketplace', 'developers', 'blog'],
    'discord.com': ['support', 'status', 'blog', 'developers', 'merch'],
    'paypal.com': ['www', 'business', 'developer', 'support'],
    'stripe.com': ['dashboard', 'docs', 'support', 'status', 'blog'],
    'salesforce.com': ['login', 'help', 'developer', 'trailhead', 'appexchange'],
    'adobe.com': ['www', 'helpx', 'creative', 'stock', 'fonts', 'account'],
    'notion.so': ['www', 'help', 'developers'],
    'figma.com': ['www', 'help', 'forum', 'community'],
    'canva.com': ['www', 'help', 'about', 'design'],
    'atlassian.com': ['www', 'support', 'community', 'developer', 'marketplace'],
    'firefox.com': ['accounts', 'support', 'addons', 'www', 'developer', 'monitor'],
    'yahoo.com': ['mail', 'finance', 'sports', 'news', 'help', 'search', 'weather'],
    'medium.com': ['help', 'blog', 'policy', 'jobs'],
    'wordpress.com': ['wordpress', 'en', 'blog', 'support', 'developer'],
    'shopify.com': ['www', 'help', 'community', 'developers', 'partners', 'apps'],
    'twitch.tv': ['www', 'help', 'dev', 'blog', 'safety'],
    'vimeo.com': ['vimeo', 'help', 'developer', 'stock'],
}

# Educational domain patterns
EDUCATIONAL_TLDS = ['.edu', '.ac.uk', '.ac.jp', '.edu.au', '.edu.cn']

# URL Shorteners
URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
    'adf.ly', 'bit.do', 'short.link', 'rb.gy', 'cutt.ly', 'tiny.cc',
    'shorturl.at', 'clck.ru'
]

# Suspicious TLDs
SUSPICIOUS_TLDS = [
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'click', 'link',
    'date', 'racing', 'stream', 'party', 'trade', 'bid'
]

# Suspicious keywords
SUSPICIOUS_KEYWORDS = [
    'verify', 'account', 'update', 'confirm', 'secure', 'login', 'signin',
    'banking', 'suspend', 'limited', 'alert', 'notification', 'expire',
    'authenticate', 'password', 'reset', 'unlock', 'restore', 'recover'
]


# ========================================================================
# ENHANCED UTILITY FUNCTIONS
# ========================================================================

def levenshtein_distance(s1, s2):
    """Calculate Levenshtein edit distance between two strings"""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]


def get_domain_similarity_score(domain):
    """Get minimum Levenshtein distance to known legitimate domains"""
    if not domain:
        return 1.0
    
    domain_clean = domain.lower().replace('www.', '')
    min_distance = float('inf')
    
    for known_domain in KNOWN_LEGITIMATE_DOMAINS:
        distance = levenshtein_distance(domain_clean, known_domain)
        normalized_distance = distance / max(len(domain_clean), len(known_domain))
        min_distance = min(min_distance, normalized_distance)
    
    return min_distance


def is_domain_whitelisted(domain, subdomain=None):
    """Check if domain or subdomain is whitelisted"""
    if not domain:
        return False
    
    domain_clean = domain.lower().replace('www.', '')
    
    # Direct match
    if domain_clean in KNOWN_LEGITIMATE_DOMAINS:
        return True
    
    # Check if it's a subdomain of a whitelisted domain
    for whitelisted in KNOWN_LEGITIMATE_DOMAINS:
        if domain_clean.endswith('.' + whitelisted) or domain_clean == whitelisted:
            # If subdomain exists, check if it's trusted
            if subdomain:
                if whitelisted in TRUSTED_SUBDOMAINS:
                    if subdomain.lower() in TRUSTED_SUBDOMAINS[whitelisted]:
                        return True
                else:
                    # Not explicitly untrusted, allow common patterns
                    return True
            return True
    
    # Check educational domains
    for edu_tld in EDUCATIONAL_TLDS:
        if domain_clean.endswith(edu_tld):
            return True
    
    # Check government domains
    if domain_clean.endswith('.gov') or '.gov.' in domain_clean:
        return True
    
    return False


def extract_subdomain_info(hostname):
    """Extract subdomain information intelligently"""
    if not hostname:
        return None, None, 0
    
    parts = hostname.split('.')
    
    # Handle special cases
    if len(parts) <= 2:
        return None, hostname, 0
    
    # For domains like accounts.google.com
    # subdomain = 'accounts', domain = 'google.com', count = 1
    if len(parts) == 3:
        return parts[0], '.'.join(parts[1:]), 1
    
    # For longer chains like secure.login.paypal.com
    # subdomain = 'secure.login', domain = 'paypal.com', count = 2
    subdomain = '.'.join(parts[:-2])
    domain = '.'.join(parts[-2:])
    count = len(parts) - 2
    
    return subdomain, domain, count


def get_domain_age_days(domain, enable_whois=False):
    """
    Get domain age in days using WHOIS (requires python-whois)
    Note: WHOIS is disabled by default for performance. Enable only for real URL testing.
    """
    if not WHOIS_AVAILABLE or not enable_whois:
        return -1  # Unknown
    
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        
        # Handle list of dates (some domains return multiple)
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if creation_date:
            age = (datetime.datetime.now() - creation_date).days
            return age
    except Exception:
        pass
    
    return -1  # Unknown or error


def check_ssl_certificate(domain):
    """Check SSL certificate validity"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Check if certificate is valid
                if cert:
                    # Check expiration
                    not_after = cert.get('notAfter')
                    if not_after:
                        expiry = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (expiry - datetime.datetime.now()).days
                        
                        if days_until_expiry > 0:
                            return {
                                'valid': True,
                                'days_until_expiry': days_until_expiry,
                                'issuer': cert.get('issuer', []),
                                'subject': cert.get('subject', [])
                            }
                
                return {'valid': False}
    except Exception:
        return {'valid': False}


def detect_mixed_scripts(text):
    """Detect if text contains mixed character scripts (homograph attack)"""
    if not text:
        return False
    
    scripts = set()
    for char in text:
        if char.isalpha():
            try:
                script_name = unicodedata.name(char).split()[0]
                scripts.add(script_name)
            except:
                pass
    
    # If we have both LATIN and CYRILLIC (or other combinations), it's suspicious
    return len(scripts) > 1


def get_character_script_info(text):
    """Get detailed character script information"""
    if not text:
        return {'has_unicode': False, 'has_cyrillic': False, 'has_arabic': False, 
                'has_chinese': False, 'has_mixed': False}
    
    has_unicode = any(ord(char) > 127 for char in text)
    has_cyrillic = any('CYRILLIC' in unicodedata.name(char, '') for char in text if char.isalpha())
    has_arabic = any('ARABIC' in unicodedata.name(char, '') for char in text if char.isalpha())
    has_chinese = any('CJK' in unicodedata.name(char, '') for char in text if char.isalpha())
    has_mixed = detect_mixed_scripts(text)
    
    return {
        'has_unicode': has_unicode,
        'has_cyrillic': has_cyrillic,
        'has_arabic': has_arabic,
        'has_chinese': has_chinese,
        'has_mixed': has_mixed
    }


def detect_leet_speak(text):
    """Detect leet speak character substitutions"""
    leet_map = {
        '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
        '7': 't', '8': 'b', '@': 'a', '$': 's'
    }
    
    count = 0
    for char in text.lower():
        if char in leet_map:
            count += 1
    
    return count


def is_url_shortener(domain):
    """Check if domain is a URL shortener"""
    if not domain:
        return False
    
    domain_clean = domain.lower().replace('www.', '')
    return domain_clean in URL_SHORTENERS


def calculate_entropy(text):
    """Calculate Shannon entropy of text"""
    if not text:
        return 0
    
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    entropy = -sum(p * math.log2(p) for p in prob if p > 0)
    
    return entropy


# ========================================================================
# ULTRA-ENHANCED FEATURE EXTRACTION (50+ features)
# ========================================================================

def extract_ultra_enhanced_features(url, enable_whois=False, enable_ssl_check=False):
    """
    Extract ultra-enhanced features with all improvements
    Returns 50+ features for maximum accuracy
    
    Args:
        url: URL to analyze
        enable_whois: Enable WHOIS domain age lookup (slow, disabled by default)
        enable_ssl_check: Enable SSL certificate validation (slow, disabled by default)
    
    Note: For training on synthetic data, keep both disabled for speed.
          For real-time URL testing, enable both for maximum accuracy.
    """
    features = {}
    
    # Parse URL
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme
        hostname = parsed.hostname if parsed.hostname else ''
        path = parsed.path if parsed.path else ''
        query = parsed.query if parsed.query else ''
        port = parsed.port
    except:
        hostname = ''
        path = ''
        query = ''
        scheme = ''
        port = None
    
    # Extract subdomain information
    subdomain, domain, subdomain_count = extract_subdomain_info(hostname)
    
    # ===== ORIGINAL FEATURES (18) =====
    features['url_length'] = len(url)
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_at_symbols'] = url.count('@')
    features['has_https'] = 1 if url.startswith('https://') else 0
    features['num_digits'] = sum(c.isdigit() for c in url)
    features['special_characters_count'] = len(re.findall(r'[!#$%&*+=?^_`{|}~]', url))
    features['is_ip_in_url'] = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0
    features['num_subdomains'] = subdomain_count
    features['top_level_domain_length'] = len(domain.split('.')[-1]) if domain and '.' in domain else 0
    features['num_slashes'] = url.count('/')
    features['num_underscores'] = url.count('_')
    features['num_question_marks'] = url.count('?')
    features['num_equals'] = url.count('=')
    features['suspicious_keywords_count'] = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url.lower())
    features['domain_length'] = len(domain) if domain else 0
    features['path_length'] = len(path)
    features['has_port'] = 1 if port else 0
    
    # ===== ENHANCED FEATURES (17 from previous version) =====
    min_distance = get_domain_similarity_score(domain)
    features['min_domain_distance'] = min_distance
    features['is_whitelisted'] = 1 if is_domain_whitelisted(domain, subdomain) else 0
    features['allows_long_urls'] = 1 if features['is_whitelisted'] else 0
    # Only mark as suspicious similarity when the domain is close to a known brand
    # but not an exact whitelist match. Exact matches (distance == 0) should remain trusted.
    if features['is_whitelisted']:
        features['is_suspicious_similarity'] = 0
    else:
        features['is_suspicious_similarity'] = 1 if 0 < min_distance < 0.3 else 0
    
    script_info = get_character_script_info(hostname)
    features['has_unicode'] = 1 if script_info['has_unicode'] else 0
    features['has_cyrillic'] = 1 if script_info['has_cyrillic'] else 0
    features['has_mixed_scripts'] = 1 if script_info['has_mixed'] else 0
    
    features['leet_speak_count'] = detect_leet_speak(hostname)
    features['is_url_shortener'] = 1 if is_url_shortener(domain) else 0
    features['domain_entropy'] = calculate_entropy(domain) if domain else 0
    features['digit_to_letter_ratio'] = (sum(c.isdigit() for c in domain) / len(domain)) if domain and len(domain) > 0 else 0
    
    if domain and '.' in domain:
        tld = domain.split('.')[-1].lower()
        features['has_suspicious_tld'] = 1 if tld in SUSPICIOUS_TLDS else 0
    else:
        features['has_suspicious_tld'] = 0
    
    features['path_to_domain_ratio'] = len(path) / len(domain) if len(domain) > 0 else 0
    features['query_length'] = len(query)
    features['num_parameters'] = query.count('&') + (1 if query else 0)
    
    consonants = 'bcdfghjklmnpqrstvwxyz'
    max_consecutive_consonants = 0
    current_count = 0
    for char in domain.lower():
        if char in consonants:
            current_count += 1
            max_consecutive_consonants = max(max_consecutive_consonants, current_count)
        else:
            current_count = 0
    features['max_consecutive_consonants'] = max_consecutive_consonants
    
    vowels = 'aeiou'
    vowel_count = sum(1 for c in domain.lower() if c in vowels)
    consonant_count = sum(1 for c in domain.lower() if c in consonants)
    features['vowel_to_consonant_ratio'] = vowel_count / consonant_count if consonant_count > 0 else 0
    
    # ===== NEW ULTRA-ENHANCED FEATURES (15+) =====
    
    # 1. Subdomain trust
    features['has_trusted_subdomain'] = 0
    if subdomain and domain in TRUSTED_SUBDOMAINS:
        if subdomain.lower() in TRUSTED_SUBDOMAINS[domain]:
            features['has_trusted_subdomain'] = 1
    
    # 2. Domain age (if available and enabled)
    domain_age = get_domain_age_days(domain, enable_whois=enable_whois) if domain and not features['is_whitelisted'] else -1
    features['domain_age_days'] = domain_age
    features['is_new_domain'] = 1 if 0 <= domain_age < 180 else 0  # < 6 months
    features['is_very_new_domain'] = 1 if 0 <= domain_age < 30 else 0  # < 1 month
    
    # 3. SSL Certificate validation (if enabled)
    ssl_info = {'valid': False}
    if enable_ssl_check and scheme == 'https' and domain:
        ssl_info = check_ssl_certificate(domain)
    features['has_valid_ssl'] = 1 if ssl_info.get('valid', False) else 0
    features['ssl_days_until_expiry'] = ssl_info.get('days_until_expiry', 0) if ssl_info.get('valid') else 0
    
    # 4. Advanced pattern detection
    features['has_multiple_hyphens_in_domain'] = 1 if domain.count('-') > 2 else 0
    features['has_excessive_subdomains'] = 1 if subdomain_count > 3 else 0
    features['url_entropy'] = calculate_entropy(url)
    features['path_entropy'] = calculate_entropy(path) if path else 0
    
    # 5. Suspicious patterns
    features['has_ip_and_domain'] = 1 if features['is_ip_in_url'] and domain else 0
    features['has_port_and_ip'] = 1 if features['is_ip_in_url'] and port else 0
    features['has_at_symbol'] = 1 if '@' in url else 0
    
    # 6. Educational/Government indicators
    features['is_educational'] = 1 if any(url.endswith(tld) for tld in EDUCATIONAL_TLDS) else 0
    features['is_government'] = 1 if '.gov' in domain or domain.endswith('.gov') else 0
    
    # 7. Brand keywords (potential impersonation)
    brand_keywords = ['paypal', 'google', 'facebook', 'amazon', 'microsoft', 'apple', 
                      'bank', 'secure', 'login', 'account']
    features['has_brand_keyword'] = sum(1 for brand in brand_keywords if brand in domain.lower())
    
    # 8. Long URL indicators
    features['is_extremely_long'] = 1 if len(url) > 150 else 0
    features['has_long_path'] = 1 if len(path) > 100 else 0
    
    return features


def get_ultra_feature_names():
    """Get ordered list of all 50+ feature names"""
    return [
        # Original 18 features
        'url_length', 'num_dots', 'num_hyphens', 'num_at_symbols', 'has_https',
        'num_digits', 'special_characters_count', 'is_ip_in_url', 'num_subdomains',
        'top_level_domain_length', 'num_slashes', 'num_underscores', 'num_question_marks',
        'num_equals', 'suspicious_keywords_count', 'domain_length', 'path_length', 'has_port',
        
        # Enhanced features (17)
        'min_domain_distance', 'is_suspicious_similarity', 'is_whitelisted', 'allows_long_urls',
        'has_unicode', 'has_cyrillic', 'has_mixed_scripts', 'leet_speak_count', 'is_url_shortener',
        'domain_entropy', 'digit_to_letter_ratio', 'has_suspicious_tld',
        'path_to_domain_ratio', 'query_length', 'num_parameters', 'max_consecutive_consonants',
        'vowel_to_consonant_ratio',
        
        # Ultra-enhanced features (15+)
        'has_trusted_subdomain', 'domain_age_days', 'is_new_domain', 'is_very_new_domain',
        'has_valid_ssl', 'ssl_days_until_expiry', 'has_multiple_hyphens_in_domain',
        'has_excessive_subdomains', 'url_entropy', 'path_entropy', 'has_ip_and_domain',
        'has_port_and_ip', 'has_at_symbol', 'is_educational', 'is_government',
        'has_brand_keyword', 'is_extremely_long', 'has_long_path'
    ]


# ========================================================================
# TESTING
# ========================================================================

if __name__ == "__main__":
    print("="*70)
    print("ULTRA-ENHANCED FEATURE EXTRACTION - Testing")
    print("="*70)
    
    test_urls = [
        ("https://www.google.com", "Legitimate - Whitelisted"),
        ("https://accounts.google.com", "Legitimate - Trusted subdomain"),
        ("https://openai.com", "Legitimate - Now whitelisted"),
        ("https://www.khanacademy.org", "Legitimate - Educational"),
        ("https://g00gle.com", "Phishing - Typosquatting"),
        ("https://аpple.com", "Phishing - Cyrillic homograph"),
        ("http://paypal.com.verify-session.ru", "Phishing - Subdomain spoofing"),
    ]
    
    print(f"\nTotal whitelisted domains: {len(KNOWN_LEGITIMATE_DOMAINS)}")
    print(f"WHOIS available: {WHOIS_AVAILABLE}")
    print(f"\nFeature count: {len(get_ultra_feature_names())}")
    
    print("\n" + "="*70)
    print("Testing URLs:")
    print("="*70)
    
    for url, description in test_urls:
        print(f"\n{url}")
        print(f"Expected: {description}")
        features = extract_ultra_enhanced_features(url)
        print(f"  Whitelisted: {features['is_whitelisted']}")
        print(f"  Trusted subdomain: {features['has_trusted_subdomain']}")
        print(f"  Min distance: {features['min_domain_distance']:.3f}")
        print(f"  Leet speak: {features['leet_speak_count']}")
        print(f"  Has Unicode: {features['has_unicode']}")
        print(f"  Has HTTPS: {features['has_https']}")
        print(f"  Domain age: {features['domain_age_days']} days")
        print(f"  Educational: {features['is_educational']}")
