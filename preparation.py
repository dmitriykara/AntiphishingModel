import requests
from parser import URLAnalysis

def prepare_link(url: str, log: bool = False) -> list:
    try:
        code = requests.get(url).status_code 
        if code > 399:
            if log:
                print(f"Link does not response : {code}")
            return None
    except Exception as e:
        if log:
            print(f"Link does not response: {e}")
        return None

    url = URLAnalysis(url)
    return url.get_ml_dict()