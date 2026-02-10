from safe_url_checker.integrations.base_integration import BaseIntegration, CheckResult, UrlCheckResult
from ssl import SSLError

import requests


class GoogleSafeInterstitial(BaseIntegration):
    def required_params(self) -> list[str]:
        return []

    def test(self, urls: list[str]) -> CheckResult:
        result: CheckResult = []

        if not urls:
            return result

        for url in urls:
            try:
                response = requests.get(f"https://www.google.com/interstitial?url={url}")

                if response.status_code == 200:
                    result.append(UrlCheckResult(safe=False, url=url))
                else:
                    result.append(UrlCheckResult(safe=True, url=url))

            except SSLError as e:
                continue

        return result
