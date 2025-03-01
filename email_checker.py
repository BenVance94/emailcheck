import re
import smtplib
import requests
import os
import json
import dns.resolver
import math
from typing import Tuple, Dict, Any, Optional
from datetime import datetime

class EmailChecker:
    def __init__(self):
        self.dns_record_types = [
            'A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA', 
            'CNAME', 'SPF', 'PTR', 'SRV', 'CERT', 'CAA'
        ]
        # Common disposable email domains
        self.disposable_domains = {
            'tempmail.com', 'temp-mail.org', 'guerrillamail.com', 
            'throwawaymail.com', '10minutemail.com', 'mailinator.com',
            'yopmail.com', 'getairmail.com', 'fakeinbox.com',
            'sharklasers.com', 'guerrillamail.info', 'grr.la',
            'maildrop.cc', 'harakirimail.com', 'trashmail.com',
            'temp-mail.io', 'dispostable.com', 'tempmail.net',
            'temporary-mail.net', 'emailondeck.com'
        }
        
        # Common free email providers (slightly suspicious for business)
        self.free_email_domains = {
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
            'aol.com', 'icloud.com', 'protonmail.com', 'mail.com'
        }
        
        # High-risk TLDs
        self.suspicious_tlds = {
            '.xyz': 25, '.top': 20, '.work': 15, '.bid': 25,
            '.loan': 30, '.click': 20, '.gq': 35, '.ml': 35,
            '.cf': 35, '.ga': 35, '.tk': 35, '.pw': 30,
            '.country': 20, '.stream': 25, '.download': 30,
            '.racing': 25, '.online': 15, '.icu': 25, '.vip': 20,
            '.fun': 20, '.site': 15, '.store': 15, '.space': 20
        }
        
        # Initialize RBL checkers
        self.rbl_servers = [
            'zen.spamhaus.org',
            'bl.spamcop.net',
            'dnsbl.sorbs.net',
            'spam.abuse.ch',
            'cbl.abuseat.org'
        ]

        # Update disposable domains with more comprehensive list
        self.disposable_domains = self._load_disposable_domains()

    def _load_disposable_domains(self) -> set:
        """Load disposable domains from multiple sources and local list"""
        domains = set(self.disposable_domains)  # Start with existing domains
        
        # Add more known disposable email patterns
        additional_domains = {
            'calmpros.com',  # Add the one we just found
            'temp-mail.org',
            'tempmail.com',
            'tempr.email',
            'tmpmail.org',
            'tmpmail.net',
            'tmpeml.com',
            'tempmail.dev',
            # Add more patterns that match common disposable services
            '10minutemail.com',
            '10minutemail.net',
            '10minutemail.org',
            'minutemail.com',
            'tempmail.plus',
            'disposable.com',
            'mailinator.com',
            'mailinator.net',
            'mailinator.org',
        }
        
        domains.update(additional_domains)
        
        try:
            # Try to fetch updated list from online sources
            urls = [
                'https://raw.githubusercontent.com/disposable/disposable-email-domains/master/domains.txt',
                'https://raw.githubusercontent.com/martenson/disposable-email-domains/master/disposable_email_blocklist.conf',
                'https://raw.githubusercontent.com/ivolo/disposable-email-domains/master/index.json'
            ]
            
            for url in urls:
                try:
                    response = requests.get(url, timeout=5)
                    if response.status_code == 200:
                        if url.endswith('.json'):
                            domains.update(json.loads(response.text))
                        else:
                            domains.update(response.text.lower().splitlines())
                except Exception as e:
                    print(f"Error fetching from {url}: {e}")
                
        except Exception as e:
            print(f"Error updating disposable domains: {e}")
        
        return domains

    def check_gibberish(self, text: str) -> float:
        """
        Return a gibberish score between 0 and 1.
        Higher score means more likely to be gibberish.
        """
        # Common letter patterns in English
        common_pairs = {'th', 'er', 'on', 'an', 'en', 'es', 'in', 'ed'}
        vowels = 'aeiou'
        
        # Calculate metrics
        text = text.lower()
        total_chars = len(text)
        if total_chars < 2:
            return 0.0
            
        # Check consonant clusters
        consonant_clusters = len(re.findall(r'[bcdfghjklmnpqrstvwxz]{3,}', text))
        
        # Check vowel/consonant ratio
        vowel_count = sum(1 for c in text if c in vowels)
        if total_chars > 0:
            vowel_ratio = vowel_count / total_chars
            if vowel_ratio < 0.2 or vowel_ratio > 0.6:
                consonant_clusters += 1
        
        # Check common pairs
        pair_count = sum(1 for i in range(len(text)-1) if text[i:i+2] in common_pairs)
        pair_ratio = pair_count / (total_chars - 1) if total_chars > 1 else 0
        
        # Calculate entropy (randomness)
        char_freq = {}
        for char in text:
            char_freq[char] = char_freq.get(char, 0) + 1
        entropy = sum(-freq/total_chars * math.log2(freq/total_chars) 
                     for freq in char_freq.values())
        
        # Combine metrics
        gibberish_score = (
            (consonant_clusters / total_chars) * 0.4 +
            (1 - pair_ratio) * 0.3 +
            (entropy / 4.5) * 0.3  # 4.5 is approx max entropy for English text
        )
        
        return min(1.0, gibberish_score)

    def check_ip_reputation(self, ip: str) -> Tuple[int, Dict[str, Any]]:
        """Check IP reputation against various blacklists"""
        score = 0
        details = {}
        
        # Reverse the IP address for RBL lookup
        reversed_ip = '.'.join(reversed(ip.split('.')))
        
        # Check against RBL servers
        for rbl in self.rbl_servers:
            try:
                lookup = f"{reversed_ip}.{rbl}"
                dns.resolver.resolve(lookup, 'A')
                score += 20
                details[rbl] = True
            except Exception:
                details[rbl] = False
        
        # Check IP reputation APIs
        try:
            # AbuseIPDB
            api_key = os.getenv('ABUSEIPDB_API_KEY')
            if api_key:
                response = requests.get(
                    'https://api.abuseipdb.com/api/v2/check',
                    params={'ipAddress': ip},
                    headers={'Key': api_key},
                    timeout=5
                )
                if response.status_code == 200:
                    data = response.json()
                    abuse_score = data['data']['abuseConfidenceScore']
                    score += min(abuse_score / 2, 25)  # Max 25 points from AbuseIPDB
                    details['abuseipdb_score'] = abuse_score
        except Exception:
            pass
        
        return score, details

    def is_valid_email_format(self, email: str) -> bool:
        regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(regex, email) is not None

    def get_ip_geolocation(self, ip_address: str) -> Optional[Dict[str, Any]]:
        url = f"https://ipinfo.io/{ip_address}/json"
        try:
            response = requests.get(url)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"Error retrieving geolocation information: {e}")
            return None

    def parse_whois(self, output: str) -> Dict[str, str]:
        whois_dict = {}
        for line in output.splitlines():
            if ':' in line:
                key, value = line.split(':', 1)
                whois_dict[key.strip()] = value.strip()
        return whois_dict

    def get_dns_records(self, domain: str) -> Dict[str, Any]:
        records = {}
        for record_type in self.dns_record_types:
            try:
                tmp_records = dns.resolver.resolve(domain, record_type)
                if record_type == 'MX':
                    records[record_type] = [tmp.exchange.to_text() for tmp in tmp_records]
                elif record_type in ['A', 'AAAA']:
                    records[record_type] = [tmp.address for tmp in tmp_records]
                else:
                    records[record_type] = [tmp.to_text() for tmp in tmp_records]
            except Exception as e:
                records[record_type] = f"Error: {e}"
        return records

    def verify_email(self, email: str) -> Tuple[bool, Dict[str, Any]]:
        if not self.is_valid_email_format(email):
            return False, "Invalid email format"

        domain = email.split('@')[1]
        dns_records = self.get_dns_records(domain)
        if not dns_records:
            return False, "No DNS records found for domain"

        # Get IPv4 location
        try:
            ipv4_location = self.get_ip_geolocation(dns_records['A'][0])
            dns_records['ipv4_location'] = ipv4_location
        except Exception:
            dns_records['ipv4_location'] = None

        # Get IPv6 location
        try:
            ipv6_location = self.get_ip_geolocation(dns_records['AAAA'][0])
            dns_records['ipv6_location'] = ipv6_location
        except Exception:
            dns_records['ipv6_location'] = None

        # Get WHOIS data
        try:
            result = os.popen(f"whois {domain}").read()
            whois_data = self.parse_whois(result)
            dns_records['whois_data'] = whois_data
        except Exception:
            dns_records['whois_data'] = None

        # Verify email existence via MX records
        for mx in dns_records['MX']:
            try:
                server = smtplib.SMTP(mx)
                server.set_debuglevel(0)
                server.helo()
                server.mail('test@example.com')
                code, message = server.rcpt(email)
                server.quit()
                if code == 250:
                    dns_records['EMAIL_EXISTS'] = True
                    return True, dns_records
            except Exception as e:
                print(f"Error verifying email: {e}")

        dns_records['EMAIL_EXISTS'] = False
        return True, dns_records

    def get_readable_report(self, score: int, details: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert technical details into an easy-to-understand report
        """
        report = {
            "overall_risk": {
                "score": score,
                "level": "Unknown",
                "description": "Could not determine risk level"
            },
            "summary": [],
            "critical_issues": [],  # New section for highest-impact issues
            "risk_factors": [],
            "security_measures": [],
            "recommendations": []
        }

        # Overall risk level
        if score <= 20:
            report["overall_risk"].update({
                "level": "Very Low Risk",
                "description": "This email appears to be legitimate and trustworthy."
            })
        elif score <= 40:
            report["overall_risk"].update({
                "level": "Low Risk",
                "description": "This email is probably legitimate but has some minor concerns."
            })
        elif score <= 60:
            report["overall_risk"].update({
                "level": "Medium Risk",
                "description": "This email has some suspicious characteristics and should be treated with caution."
            })
        elif score <= 80:
            report["overall_risk"].update({
                "level": "High Risk",
                "description": "This email shows multiple signs of being potentially fraudulent."
            })
        else:
            report["overall_risk"].update({
                "level": "Very High Risk",
                "description": "This email is very likely to be fraudulent or malicious."
            })

        # Add critical issues first
        if details.get('critical_issues'):
            report['critical_issues'] = details['critical_issues']

        # Add summary points
        if details.get('is_disposable'):
            report["summary"].append("This email uses a disposable/temporary email service")
        elif details.get('possible_disposable'):
            report["summary"].append("This domain appears to be a temporary email service")
        
        if details.get('is_free_email'):
            report["summary"].append("This email uses a free email provider")

        # Domain age
        if 'domain_age_days' in details:
            age_days = details['domain_age_days']
            if age_days < 30:
                report["risk_factors"].append(f"This domain was created very recently ({age_days} days ago)")
            elif age_days < 180:
                report["risk_factors"].append(f"This domain is relatively new ({age_days} days old)")
            else:
                report["summary"].append(f"Domain has been registered for {age_days//365} years and {(age_days%365)//30} months")

        # Suspicious patterns
        if details.get('suspicious_patterns'):
            report["risk_factors"].append("The email address contains suspicious patterns")

        # Gibberish detection
        if details.get('username_gibberish_score', 0) > 0.7:
            report["risk_factors"].append("The username appears to be random or meaningless")
        if details.get('domain_gibberish_score', 0) > 0.7:
            report["risk_factors"].append("The domain name appears to be random or meaningless")

        # TLD risk
        if 'suspicious_tld' in details:
            report["risk_factors"].append(f"The domain uses a high-risk top-level domain ({details['suspicious_tld']})")

        # Security measures
        if details.get('has_spf'):
            report["security_measures"].append("Domain has SPF protection")
        else:
            report["recommendations"].append("Domain lacks SPF email security")

        if details.get('has_dmarc'):
            report["security_measures"].append("Domain has DMARC protection")
        else:
            report["recommendations"].append("Domain lacks DMARC email security")

        # IP reputation
        if 'ip_reputation' in details:
            ip_rep = details['ip_reputation']
            if any(ip_rep.values()):
                report["risk_factors"].append("The email server IP address has been flagged for suspicious activity")

        # Length issues
        if details.get('length_issue'):
            report["risk_factors"].append(details['length_issue'])

        return report

    def _check_email_reputation(self, email: str) -> Tuple[int, Dict[str, Any]]:
        """
        Internal method to check email reputation and return a risk score and details
        """
        score = 0
        details = {}
        critical_issues = []  # Track highest-impact issues
        
        if not self.is_valid_email_format(email):
            return 100, {"error": "Invalid email format"}
            
        username, domain = email.split('@')
        
        # Get DNS records first as they're critical for analysis
        dns_check_result, dns_details = self.verify_email(email)
        details['dns_check'] = dns_details
        
        # HIGH IMPORTANCE: Check for missing A/AAAA records
        has_a_record = bool(dns_details.get('A'))
        has_aaaa_record = bool(dns_details.get('AAAA'))
        has_mx_record = bool(dns_details.get('MX'))
        
        if has_mx_record and not (has_a_record or has_aaaa_record):
            score += 40  # Highest penalty for this critical issue
            critical_issues.append("Domain has email configuration but no web hosting capability")
            details['missing_host_records'] = True
        
        # HIGH IMPORTANCE: Check SPF record for suspicious patterns
        spf_records = dns_details.get('TXT', [])
        suspicious_spf = False
        for record in spf_records:
            if 'v=spf1' in record:
                if '1.1.1.1' in record or 'all' in record:
                    suspicious_spf = True
                    score += 30
                    critical_issues.append("Suspicious SPF configuration detected")
                    details['suspicious_spf'] = True
        
        # HIGH IMPORTANCE: Check MX record patterns
        mx_records = dns_details.get('MX', [])
        for mx in mx_records:
            if domain in mx:  # Self-referential MX record
                score += 25
                critical_issues.append("Self-referential MX record detected")
                details['self_referential_mx'] = True
        
        # Enhanced disposable email detection
        if domain in self.disposable_domains:
            score += 75
            critical_issues.append("Confirmed disposable email service")
            details['is_disposable'] = True
        
        # Existing checks with adjusted weights...
        if any(pattern in username for pattern in ['temp', 'tmp', 'disposable', 'junk', 'trash']):
            score += 20
            details['suspicious_patterns'] = True
        
        if len(re.findall(r'\d', username)) > 4:
            score += 15
            details['suspicious_patterns'] = True
        
        # Store critical issues in details
        details['critical_issues'] = critical_issues
        
        # Additional DNS analysis
        if dns_check_result:
            # Check IP reputation if we have DNS records
            if has_a_record:
                ip_score, ip_details = self.check_ip_reputation(dns_details['A'][0])
                score += ip_score
                details['ip_reputation'] = ip_details
        
        return min(100, score), details

    def check_email_reputation(self, email: str) -> Tuple[int, Dict[str, Any], Dict[str, Any]]:
        """
        Check email reputation and return score, technical details, and readable report
        """
        score, details = self._check_email_reputation(email)
        readable_report = self.get_readable_report(score, details)
        
        # Save results to JSON file with enhanced structure
        output = {
            "email": email,
            "score": score,
            "critical_findings": details.get('critical_issues', []),  # Highlight critical issues
            "technical_details": details,
            "readable_report": readable_report,
            "analysis_timestamp": datetime.now().isoformat()
        }
        
        with open('email_report.json', 'w') as f:
            json.dump(output, f, indent=4)
        
        return score, details, readable_report

checker = EmailChecker()
score, details, report = checker.check_email_reputation("jocen88343@calmpros.com")

print(f"\nEmail Risk Assessment Report")
print(f"============================")
print(f"Risk Level: {report['overall_risk']['level']} ({score}/100)")
print(f"Description: {report['overall_risk']['description']}")

if report['summary']:
    print("\nSummary:")
    for point in report['summary']:
        print(f"• {point}")

if report['risk_factors']:
    print("\nRisk Factors Identified:")
    for factor in report['risk_factors']:
        print(f"⚠ {factor}")

if report['security_measures']:
    print("\nSecurity Measures in Place:")
    for measure in report['security_measures']:
        print(f"✓ {measure}")

if report['recommendations']:
    print("\nRecommendations:")
    for rec in report['recommendations']:
        print(f"➤ {rec}") 