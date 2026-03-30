import re


class HeuristicAnalyzer:

    def analyze_heuristics(self, url, domain):

        score = 100
        flags = []

        # Length check
        if len(url) > 75:
            score -= 15
            flags.append("Long URL")

        # IP address in URL
        if re.search(r"\d+\.\d+\.\d+\.\d+", url):
            score -= 30
            flags.append("IP address in URL")

        # @ symbol
        if "@" in url:
            score -= 25
            flags.append("@ symbol in URL")

        # Suspicious keywords
        bad_words = ["login", "verify", "bank", "free", "offer", "secure"]

        for w in bad_words:
            if w in url.lower():
                score -= 10
                flags.append(f"Contains '{w}'")

        score = max(0, score)

        return {
            "heuristic_score": score,
            "flags": flags
        }
