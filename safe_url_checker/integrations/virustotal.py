from safe_url_checker.integrations.base_integration import BaseIntegration, CheckResult, UrlCheckResult
from datetime import datetime

import requests
import time


class Virustotal(BaseIntegration):
    def required_params(self) -> list[str]:
        return ['API_KEY']

    def test(self, urls: list[str]) -> CheckResult:
        result: CheckResult = []

        if not urls:
            return result

        i = 0
        count_requests = 0

        api_url = 'https://www.virustotal.com/api/v3/urls'
        headers = {'x-apikey': self.params['API_KEY']}

        for url in urls:
            data = {'url': url}

            while True:
                if count_requests >= 4:
                    i += 1
                    count_requests = 0

                response = requests.post(api_url, headers=headers, data=data)
                count_requests += 1

                if response.status_code in [429, 401]:
                    time.sleep(60)
                    continue
                else:
                    break

            resp = response.json()

            virustotal_id = resp['data']['id'].split('-')[1]

            while True:
                if count_requests >= 4:
                    i += 1
                    count_requests = 0

                response = requests.get(api_url + '/' + virustotal_id, headers=headers)
                count_requests += 1

                if response.status_code in [429, 401]:
                    time.sleep(60)
                    continue
                else:
                    break

            data = response.json()

            if 'error' in data:
                continue

            report = {}

            report['url'] = url

            virustotal = True

            if 'data' in data and 'attributes' in data['data']:
                data = data['data']['attributes']
                report['stats'] = data['total_votes']
                report['results'] = data['last_analysis_results']

                if 'last_analysis_date' in data:
                    report['last_update'] = datetime.utcfromtimestamp(int(data['last_analysis_date'])).strftime('%Y-%m-%d %H:%M:%S')

                for treat in report['results']:
                    treat_result = report['results'][treat]['result']
                    if treat_result not in ["clean", "unrated"]:
                        virustotal = False

            result.append(UrlCheckResult(safe=virustotal, url=url))

        return result
