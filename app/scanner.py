from .domain_registry import DomainRegistry
from .url_normalizer import normalize_url
from .similarity import check_similarity
from .rules import RuleEngine
import os

class PhishingScanner:
    def __init__(self, data_dir: str):
        self.registry = DomainRegistry(data_dir)
        self.rule_engine = RuleEngine()

    def scan_url(self, url: str) -> dict:
        """
        Scan a URL and classify it as SAFE, WARNING, or DANGEROUS based on deterministic rules.
        """
        # Step 2: Normalize
        url_info = normalize_url(url)
        root_domain = url_info.get("root_domain", "")
        
        final_reasons = []

        # Step 3: Exact Trust Match
        if self.registry.is_trusted(root_domain):
            return {
                "risk": "SAFE",
                "confidence": "HIGH",
                "reasons": ["Exact match in Authoritative Trust Registry"]
            }

        # Step 4: Domain Similarity Detection
        sim_result = check_similarity(root_domain, self.registry.trusted_domains_set)
        
        # Step 5: Structural Risk Signals
        rules_result = self.rule_engine.evaluate(url_info, sim_result)
        
        score = rules_result["risk_score"]
        final_reasons.extend(rules_result["reasons"])

        # Step 6: Final Risk Score Logic
        risk_level = "SAFE"
        confidence = "LOW"
        
        # Categorization based on rule score
        if score >= 8:
            risk_level = "DANGEROUS"
            confidence = "HIGH"
        elif score >= 4:
            risk_level = "WARNING"
            confidence = "MEDIUM"
        else:
            # Not in ATR, but no strong signals
            risk_level = "WARNING"
            confidence = "LOW"
            if not final_reasons:
                final_reasons.append("Domain not found in ATR, but no malicious signals detected")
                
        # Get Top 3 reasons
        top_reasons = final_reasons[:3]
                
        return {
            "risk": risk_level,
            "confidence": confidence,
            "reasons": top_reasons
        }
