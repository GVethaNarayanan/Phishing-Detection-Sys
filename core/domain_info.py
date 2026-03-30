import whois
import dns.resolver
from datetime import datetime


class DomainInfo:

    def get_whois_info(self, domain):

        try:
            w = whois.whois(domain)

            creation = w.creation_date

            if isinstance(creation, list):
                creation = creation[0]

            if creation:
                age_days = (datetime.now() - creation).days
            else:
                age_days = None

            return {
                "domain_age_days": age_days,
                "registrar": w.registrar
            }

        except Exception:

            return {
                "domain_age_days": None,
                "registrar": None
            }


    def get_dns_records(self, domain):

        records = {}

        try:
            for r in ["A", "MX", "NS"]:
                try:
                    answers = dns.resolver.resolve(domain, r)
                    records[r] = [str(a) for a in answers]
                except:
                    records[r] = []

        except:
            pass

        return records
