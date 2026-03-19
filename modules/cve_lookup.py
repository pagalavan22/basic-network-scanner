import requests

def search_cves(service, port):
    """
    Search for real CVEs using NIST NVD public API.
    No API key needed — completely free.
    """
    # Build search keyword from service name
    keyword = service.replace("Windows ", "").replace(" ", "+")

    url = (f"https://services.nvd.nist.gov/rest/json/cves/2.0"
           f"?keywordSearch={keyword}&resultsPerPage=3")

    try:
        response = requests.get(url, timeout=10)
        data     = response.json()

        cves = []
        for item in data.get("vulnerabilities", []):
            cve  = item["cve"]
            cvss = "N/A"

            # Try to get CVSS score
            metrics = cve.get("metrics", {})
            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV2" in metrics:
                cvss = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

            cves.append({
                "id":          cve["id"],
                "score":       cvss,
                "description": cve["descriptions"][0]["value"][:120] + "..."
            })

        return cves

    except Exception as e:
        return []