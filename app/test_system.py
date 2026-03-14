import os
import json
from app.scanner import PhishingScanner

def block_print(title):
    print("\n" + "="*50)
    print(f" {title}")
    print("="*50)

def main():
    # Initialize Scanner
    # Data is in the 'data' directory relative to the project root
    data_dir = os.path.join(os.path.dirname(__file__), '..', 'data')
    scanner = PhishingScanner(data_dir=data_dir)
    
    print(f"Loaded {len(scanner.registry.trusted_domains_set)} trusted domains.")

    # Step 7: Test Cases
    test_urls = [
        # SAFE: Trusted domains
        "https://www.jordan.gov.jo/wps/portal/Home",
        "https://bankofjordan.com/en",
        "http://cbj.gov.jo",  # Should be in jo_domains.csv theoretically
        
        # DANGEROUS: Typosquatting / Impersonation
        "http://bank-of-jordan.com/login",
        "https://paypa1.com/secure/payment",
        "http://jordanbank-secure.com/update-account",
        "http://cbj.gov-jo.com/otp",
        
        # WARNING: Unknown domains with no specific risk signals
        "https://example.com/about-us",
        
        # DANGEROUS: Structural risks
        "http://192.168.1.1/login",
        "https://bit.ly/3xyz789",
        "http://very-long-domain-name-with-many-hyphens-1234.xyz/verify"
    ]

    block_print("STARTING TEST CASES")
    
    for idx, url in enumerate(test_urls, 1):
        print(f"\n[Test {idx}] Scanning: {url}")
        result = scanner.scan_url(url)
        print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
