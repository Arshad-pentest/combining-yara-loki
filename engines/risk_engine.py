def calculate_risk(yara_hits, loki_hits, yara_severities):
    score = 0

    # Engine hits
    if yara_hits:
        score += 40
    if loki_hits:
        score += 30
    if yara_hits and loki_hits:
        score += 20

    # Rule severity weighting
    severity_map = {
        "low": 10,
        "medium": 20,
        "high": 30,
        "critical": 40
    }

    for sev in yara_severities:
        score += severity_map.get(sev.lower(), 0)

    return min(score, 100)
