from safe_url_checker.integrations.base_integration import BaseIntegration, CheckResult, UrlCheckResult

import time
import requests


class GoogleSafeBase(BaseIntegration):
    def required_params(self) -> list[str]:
        return ['API_KEY']

    def test(self, urls: list[str]) -> CheckResult:
        result: CheckResult = []

        if not urls:
            return result

        chunk_size = self.params.get('CHUNK_SIZE', 500)
        while urls:
            chunk, urls = urls[:chunk_size], urls[chunk_size:]
            chunk = [{'url': u} for u in chunk]

            response = requests.post(
                'https://safebrowsing.googleapis.com/v4/threatMatches:find',
                params={
                    'key': self.params['API_KEY'],
                },
                json={
                    'threatInfo': {
                        'threatTypes': self.params.get('THREAT_TYPES', ['SOCIAL_ENGINEERING', 'MALWARE', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION']),
                        'platformTypes': self.params.get('PLATFORM_TYPES', ['ANY_PLATFORM']),
                        'threatEntryTypes': ['URL'],
                        'threatEntries': chunk
                    }
                }
            )

            if response.status_code != 200:
                continue

            response = response.json()

            not_safe = [r['threat']['url'] for r in response['matches']] if 'matches' in response else []

            for url in chunk:
                result.append(UrlCheckResult(safe=url['url'] not in not_safe, url=url['url']))

            time.sleep(self.params.get('SLEEP_TIME', 1))

        return result
