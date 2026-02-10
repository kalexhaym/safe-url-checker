from safe_url_checker.integrations.base_integration import BaseIntegration, CheckResult, UrlCheckResult
from ssl import SSLError

import requests
import random


class GoogleSafeTransparency(BaseIntegration):
    def required_params(self) -> list[str]:
        return []

    def test(self, urls: list[str]) -> CheckResult:
        result: CheckResult = []

        if not urls:
            return result

        for url in urls:
            try:
                response = requests.get(
                    f"https://transparencyreport.google.com/transparencyreport/api/v3/safebrowsing/status?site={url}",
                    headers={
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (HTML, like Gecko) Chrome/102.0.0.0 Safari/537.36'
                    },
                    timeout=random.randint(10, 15)
                )

                if response.status_code == 200:
                    if 'sb.ssr' in response.text:
                        if 'true' not in response.text:
                            result.append(UrlCheckResult(safe=True, url=url))
                            continue

                    result.append(UrlCheckResult(safe=False, url=url))

            except SSLError as e:
                continue

        return result
