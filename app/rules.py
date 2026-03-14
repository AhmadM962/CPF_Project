import re

class RuleEngine:
    def __init__(self):
        # Configuration for rules
        self.suspicious_keywords = ['login', 'verify', 'payment', 'otp', 'update', 'secure', 'account']
        
        # Suspicious TLDs often used for phishing or abuse
        self.suspicious_tlds = ['xyz', 'top', 'pw', 'tk', 'ml', 'ga', 'cf', 'gq', 'online', 'site']
        
        # Common URL shorteners
        self.url_shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly']

    def evaluate(self, url_info: dict, similarity_result: dict) -> dict:
        """
        Evaluate structural risk signals and return a combined score + reasons.
        """
        score = 0
        reasons = []
        
        # 1. Domain length anomalies
        if len(url_info.get("root_domain", "")) > 30:
            score += 2
            reasons.append("Domain length is unusually long (>30 chars)")
            
        # 2. Hyphens
        domain_part = url_info.get("domain", "") # Just the label
        hyphen_count = domain_part.count('-')
        if hyphen_count > 2:
            score += 3
            reasons.append(f"Excessive hyphens in domain ({hyphen_count})")
            
        # 3. Digits usage in domain
        digit_count = sum(c.isdigit() for c in domain_part)
        if digit_count > 4:
            score += 2
            reasons.append(f"High number of digits in domain ({digit_count})")
            
        # 4. Suspicious TLD
        # e.g., google.xyz
        tld = url_info.get("root_domain", "").split('.')[-1]
        if tld in self.suspicious_tlds:
            score += 4
            reasons.append(f"Untrusted TLD used (.{tld})")
            
        # 5. Suspicious keywords in path/subdomain
        combined_path_sub = url_info.get("path", "") + " " + url_info.get("subdomain", "")
        for kw in self.suspicious_keywords:
            if kw in combined_path_sub:
                score += 3
                reasons.append(f"Suspicious keyword '{kw}' found in URL")
                
        # 6. Raw IP Address
        if url_info.get("is_ip", False):
            score += 6
            reasons.append("Domain is a raw IP address")
            
        # 7. URL Shorteners
        if url_info.get("root_domain", "") in self.url_shorteners:
            score += 5
            reasons.append(f"URL Shortener detected ({url_info.get('root_domain')})")

        # 8. Excessive subdomains
        if url_info.get("subdomain", ""):
            sub_count = len(url_info["subdomain"].split('.'))
            if sub_count > 2:
                score += 3
                reasons.append(f"Excessive subdomains used ({sub_count})")

        # 9. Encoded characters (very basic check)
        if '%' in url_info.get("path", "") or '%' in url_info.get("query", ""):
             # Look for excessive encoding
             if url_info["original_url"].count('%') > 3:
                 score += 2
                 reasons.append("High number of encoded characters")
                 
        # 10. Similarity Signals
        if similarity_result.get("suspicious", False):
            score += 8
            closest = similarity_result.get("closest_match")
            sim_score = similarity_result.get("score", 0)
            reasons.append(f"Domain highly similar to {closest} (Score: {sim_score:.1f}%)")

        return {
            "risk_score": score,
            "reasons": reasons
        }
