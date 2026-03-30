class ScoringEngine:

    TRUSTED_DOMAINS = [
        "google.com",
        "microsoft.com",
        "amazon.com",
        "facebook.com",
        "apple.com",
        "wikipedia.org",
        "youtube.com",
        "github.com"
    ]


    def calculate_risk_score(self, results):

        score = 0
        factors = []


        domain = results.get("url_analysis", {}).get("domain", "")


        # -------------------------------
        # Trusted Domain Boost (+25)
        # -------------------------------

        for d in self.TRUSTED_DOMAINS:
            if domain.endswith(d):
                score += 25
                break


        # -------------------------------
        # HTTPS (+20)
        # -------------------------------

        is_https = results.get("url_analysis", {}).get("is_https")

        if is_https is True:
            score += 20
        elif is_https is False:
            factors.append("Website does not use HTTPS")


        # -------------------------------
        # SSL (+15)
        # -------------------------------

        ssl = results.get("ssl_info", {})

        if ssl.get("valid") is True:
            score += 15
        elif ssl.get("valid") is False:
            factors.append("Invalid SSL certificate")


        # -------------------------------
        # Heuristics (+25)
        # -------------------------------

        heur = results.get("heuristics", {})

        h_score = heur.get("heuristic_score")

        if isinstance(h_score, (int, float)):
            score += min(25, h_score / 4)

            if h_score < 50:
                factors.append("Suspicious URL pattern")


        # -------------------------------
        # Domain Age (+10)
        # -------------------------------

        age = results.get("whois_info", {}).get("domain_age_days")

        if isinstance(age, (int, float)):
            if age > 365:
                score += 10


        # -------------------------------
        # Reputation (+15, Neutral Default)
        # -------------------------------

        rep = results.get("reputation", {})

        rep_score = rep.get("reputation_score")

        if not isinstance(rep_score, (int, float)):
            rep_score = 70   # optimistic default

        score += rep_score / 5


        # -------------------------------
        # Final Score
        # -------------------------------

        score = max(0, min(100, int(score)))


        if score >= 70:
            level = "SAFE"
        elif score >= 45:
            level = "SUSPICIOUS"
        else:
            level = "PHISHING"


        return {
            "overall_score": score,
            "risk_level": level,
            "risk_factors": factors
        }