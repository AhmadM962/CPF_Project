import pandas as pd
import tldextract
import os

class DomainRegistry:
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        self.trusted_domains_set = set()
        self._load_datasets()

    def _normalize_domain(self, domain_str: str) -> str:
        """
        Extract the root (registrable) domain from a given string.
        E.g. 'www.jordan.gov.jo' -> 'jordan.gov.jo'
        """
        if pd.isna(domain_str):
            return ""
        
        domain_str = str(domain_str).strip().lower()
        if not domain_str:
            return ""
        
        # tldextract handles punycode (if input is idna, it extracts properly)
        extracted = tldextract.extract(domain_str)
        # Reconstruct the registrable domain (domain + suffix)
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}"
        elif extracted.domain:
            return extracted.domain
        return ""

    def _load_datasets(self):
        # 1. Load jo_domains.csv
        jo_domains_path = os.path.join(self.data_dir, "jo_domains.csv")
        if os.path.exists(jo_domains_path):
            try:
                df_jo = pd.read_csv(jo_domains_path)
                if 'Domain' in df_jo.columns:
                    for d in df_jo['Domain']:
                        norm_d = self._normalize_domain(d)
                        if norm_d:
                            self.trusted_domains_set.add(norm_d)
            except Exception as e:
                print(f"Error loading {jo_domains_path}: {e}")

        # 2. Load whitelist
        whitelist_path = os.path.join(self.data_dir, "jordan_banks_whitelist_enhanced.csv")
        if os.path.exists(whitelist_path):
            try:
                df_wl = pd.read_csv(whitelist_path)
                if 'Root Domain' in df_wl.columns:
                    for d in df_wl['Root Domain']:
                        norm_d = self._normalize_domain(d)
                        if norm_d:
                            self.trusted_domains_set.add(norm_d)
            except Exception as e:
                print(f"Error loading {whitelist_path}: {e}")

    def is_trusted(self, root_domain: str) -> bool:
        """Check if root domain is explicitly in the authoritative trust registry."""
        return root_domain.lower() in self.trusted_domains_set
