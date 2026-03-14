import Levenshtein

def check_similarity(root_domain: str, trusted_set: set) -> dict:
    """
    Check for domain similarity against the Authoritative Trust Registry (ATR).
    Uses Levenshtein distance as the primary metric.
    """
    if not root_domain:
        return {"suspicious": False, "score": 0, "closest_match": None}

    highest_similarity_score = 0
    closest_match = None
    
    # We strip the TLD/suffix to compare the core domain strings to avoid TLD bias
    # But since trusted_set contains 'root_domain.suffix', we will compare full names first
    # For a more advanced approach, you'd compare specifically the 'domain' part
    # But for now we compare the full root domain string (ex: bankofjordan.com vs bank-of-jordan.com)
    
    for trusted_domain in trusted_set:
        dist = Levenshtein.distance(root_domain, trusted_domain)
        # Calculate a similarity ratio between 0 and 1
        max_len = max(len(root_domain), len(trusted_domain))
        if max_len == 0:
            continue
            
        sim_ratio = 1 - (dist / max_len)
        score = sim_ratio * 100
        
        if score > highest_similarity_score:
            highest_similarity_score = score
            closest_match = trusted_domain
            
    # If the similarity is high (e.g., > 80%) but it is NOT an exact match
    suspicious = highest_similarity_score >= 80 and highest_similarity_score < 100
    
    return {
        "suspicious": suspicious,
        "score": highest_similarity_score,
        "closest_match": closest_match
    }

# NOTE: Advanced homoglyph detection can be added here using dictionaries of confusable characters
