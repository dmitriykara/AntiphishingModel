import re
import json
import requests
from tld import get_tld
from bson import json_util
from .scoring import Scoring


class URLAnalysis:
    def __init__(self, url):
        self._url = url
        self._real_url = url
        self._html = ''
        self._is_redirect = False
        self._redirects = []
        self._tld_data = {}
        self._domain = {}

        self._check_redirect()
        self._get_domain()

    def _check_redirect(self):
        """ Check redirect using Splash technology
        
        """
        try:
            request = requests.get(
                'http://localhost:8050/render.json',
                params={
                    'url': self._url,
                    'html': 1,
                    'wait': 2,
                    'timeout': 90,
                    'png': 1,
                    'render_all': 1,
                    'history': 1,
                }
            )
            response = request.json()

            if len(response['history']) != 1:
                self._real_url = response['url']
                self._is_redirect = True
                for redirect in response['history'][:-1]:  # Except last url
                    self._redirects.append(redirect['response']['url'])

            elif self._url != response['url']:
                self._real_url = response['url']
                self._is_redirect = True

            self._html = response['html']

        except:
            response = requests.get(self._url)
            if len(response.history) > 0:
                self._real_url = response.url
                self._is_redirect = True
                for redirect in response.history:
                    self._redirects.append(redirect.url)

            self._html = response.text

    def _get_domain(self):
        """ Get domain 

        """
        self._tld_data = get_tld(self._real_url, as_object=True, fail_silently=True)  # Get tld info
        domain = Scoring(self._real_url)
        domain.start_analysis()
        self._domain = domain.get_ml_dict()

    def get_dict(self) -> dict:
        result = {
            "url": self._url,
            "real_url": self._real_url,
            "is_redirect": self._is_redirect,
            "redirects": self._redirects,
            "domain": self._domain,
        }

        return result

    def get_ml_dict(self) -> dict:
        result = self._domain
        redirects = len(self._redirects)
        if self._is_redirect and redirects == 0:
            redirects = 1

        result["is_redirect"] = self._is_redirect
        result["redirects"] = redirects

        return result

    def get_json(self) -> str:
        return json.dumps(self.get_dict(), ensure_ascii=False, default=json_util.default)
