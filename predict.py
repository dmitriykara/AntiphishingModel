import pickle
import re
import pandas as pd
import numpy as np
from tqdm import tqdm
from preparation import prepare_link

urls = []
text = ""
regex = r"\b((?:https?://)?(?:(?:www\.)?(?:[\da-z\.-]+)\.(?:[a-z]{2,6})|(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])))(?::[0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])?(?:/[\w\.-]*)*/?)\b"

access_list = []
reject_list = []
positive = []
negative = []
drop = []

model     = pickle.load(open('bin/antiphishing.pkl', 'rb'))
tlds      = pickle.load(open('bin/tlds.pkl', 'rb'))
countries = pickle.load(open('bin/countries.pkl', 'rb'))

def code_tld(x):
    for i in range(len(tlds)):
        if x == tlds[i]:
            return i
    return -1
        
def code_country(x):
    for i in range(len(countries)):
        if x == countries[i]:
            return i
    return -1

def check_lists(x):
    if f'{x.domain}.{x.tld}' in access_list:
        positive.append(x.url)
        drop.append(x.name)
        return x
    if f'{x.domain}.{x.tld}' in reject_list:
        negative.append(x.url)
        drop.append(x.name)
        return x
    return x

if __name__ == "__main__":
    extra_urls = re.findall(regex, text)
    urls.extend(extra_urls)

    results = []
    successful = []
    for url in tqdm(urls):
        try:
            res = prepare_link(url)
        except Exception as e:
            print(e)
            res = None
        if res is not None:
            results.append(res)
            successful.append(url)
    df = pd.DataFrame(results)
    df['url'] = successful

    df = df.apply(check_lists, axis=1).drop(df.index[drop])

    df.notbefore = pd.to_datetime(df.notbefore, errors='coerce')
    df.notbefore = df.notbefore.apply(lambda x: x is not pd.NaT)
    df.notafter = pd.to_datetime(df.notafter, errors='coerce')
    df.notafter = df.notafter.apply(lambda x: x is not pd.NaT)
    df.asn_date = pd.to_datetime(df.asn_date, errors='coerce')
    df.asn_date = df.asn_date.apply(lambda x: (pd.to_datetime('today').to_period('M') - x.to_period('M')).n if x is not pd.NaT else np.NaN)
    df.tld = df.tld.apply(code_tld).astype('int32')
    df.country = df.country.apply(code_country).astype('int32')
    df.asn_date = df.asn_date.fillna(0).astype('float32')
    df.html_len = df.html_len.astype('int32')
    df.text_len = df.text_len.astype('int32')
    df.domain_age = df.domain_age.astype('int32')
    df.number_of_pages = df.number_of_pages.astype('int32')
    df.san = df.san.astype('int32')
    df.redirects = df.redirects.astype('int32')
    df = df.drop(columns=['domain', 'ssl_gived_by', 'text_ratio', 'is_accessible',])
    df = df.drop_duplicates()

    predict = model.predict(df.drop(columns=['url']))

    for i in range(df.shape[0]):
        if predict[i]:
            negative.append(df.iloc[i].url)
        else:
            positive.append(df.iloc[i].url)

    print('These links are clear:')
    for url in positive:
        print(f'\t{url}')
    print('Be careful with this links:')
    for url in negative:
        print(f'\t{url}')
    print('If you trust these resources, please add them to the access list')

