import logging
import sys
import datetime
import os
import csv
from pathlib import Path
import unicodedata
import textdistance
import pandas as pd
import tldextract
import whois
import certstream
from detectidna import unconfuse


USERDATA_DIRECORY = Path(__file__).parents[0] / 'userdata'


def damerau(keyword, domain) -> str:
    # Based on / Inspired by (c) Everton Gomede, PhD
    domain_name = tldextract.extract(domain, include_psl_private_domains=True).domain
    len_s1 = len(keyword)
    len_s2 = len(domain_name)
    d = [[0] * (len_s2 + 1) for _ in range(len_s1 + 1)]

    for i in range(len_s1 + 1):
        d[i][0] = i
    for j in range(len_s2 + 1):
        d[0][j] = j

    for i in range(1, len_s1 + 1):
        for j in range(1, len_s2 + 1):
            cost = 0 if keyword[i - 1] == domain_name[j - 1] else 1
            d[i][j] = min(
                d[i - 1][j] + 1,
                d[i][j - 1] + 1,
                d[i - 1][j - 1] + cost,
            )
            if i > 1 and j > 1 and keyword[i - 1] == domain_name[j - 2] and keyword[i - 2] == domain_name[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + cost)

    damerau_distance = d[len_s1][len_s2]

    if 4 <= len(keyword) <= 6:
        if damerau_distance <= 1:
            return domain


    elif 6 < len(keyword) <= 9:
        if damerau_distance <= 2:
            return domain


    elif len(keyword) >= 10:
        if damerau_distance <= 3:
            return domain


def jaccard(keyword, domain, n_gram):
    domain_letter_weight = tldextract.extract(domain, include_psl_private_domains=True).domain
    keyword_letter_weight = keyword
    ngram_keyword = [keyword_letter_weight[i:i + n_gram] for i in range(len(keyword_letter_weight) - n_gram + 1)]
    ngram_domain_name = [domain_letter_weight[i:i + n_gram] for i in range(len(domain_letter_weight) - n_gram + 1)]
    intersection = set(ngram_keyword).intersection(ngram_domain_name)
    union = set(ngram_keyword).union(ngram_domain_name)
    similarity = len(intersection) / len(union) if len(union) > 0 else 0

    if similarity > 0.6:
        return domain


def jaro_winkler(keyword, domain):
    domain_name = tldextract.extract(domain, include_psl_private_domains=True).domain
    similarity = textdistance.jaro_winkler.normalized_similarity(keyword, domain_name)
    if similarity >= 0.9:
        return similarity


def make_whois_request(domain) -> tuple:

    creation_date = ''
    registrar = ''

    try:
        registered = whois.whois(domain)
        if registered.creation_date is not None:
            creation_date = registered.creation_date.strftime('%d-%m-%y')

        if registered.registrar is not None:
            registrar = registered.registrar.replace(',', '')

    except Exception as e:
        print(f'{type(e)}: Something went wrong with WHOIS Request for {domain}. Error Message: {e}')

    return creation_date, registrar


def createfile():
    conso_file_path = f"CERT_Monitoring_Calender_Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv"
    if not os.path.exists(conso_file_path):
        header = ['(Sub-)Domain', 'Registered Domain', 'Keyword', 'Registrar', 'Domain Creation_Date', 'Monitored Date']
        with open(conso_file_path, 'w') as f:
            writer = csv.writer(f)
            writer.writerow(header)


def writetocsv(domain, all_domains, keyword):
    registered_domain = tldextract.extract(domain, include_psl_private_domains=True).registered_domain
    creation_date, registrar = make_whois_request(domain=registered_domain)
    df = pd.DataFrame([all_domains[0]])
    df['Registered Domain'] = registered_domain
    df['Keyword'] = pd.Series(keyword, dtype='object')
    df['Registrar'] = pd.Series(registrar, dtype='object')
    df['Domain Creation_Date'] = pd.Series(creation_date, dtype='object')
    df['Monitored Date'] = pd.Series(datetime.date.today(), dtype='object')
    df.to_csv(f"CERT_Monitoring_Calender_Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv", index=False, mode='a', header=False)


def get_keywords():
    main_keywords = []
    file_keywords = open(f'{USERDATA_DIRECORY}/keywords.txt', 'r', encoding='utf-8-sig')
    for my_domains in file_keywords:
        domain = my_domains.replace("\n", "").lower().replace(",", "").replace(" ", "").strip()
        if domain is not None and domain != '':
            main_keywords.append(domain)
    file_keywords.close()

    return main_keywords


def get_blacklist_keywords():
    black_keywords = []
    file_blacklist = open(f'{USERDATA_DIRECORY}/blacklist_keywords.txt', 'r', encoding='utf-8-sig')
    for my_domains in file_blacklist:
        domain = my_domains.replace("\n", "").lower().replace(",", "").replace(" ", "").strip()
        if domain is not None and domain != '':
            black_keywords.append(domain)
    file_blacklist.close()

    return black_keywords


def print_callback(message, context):

    logging.debug("Message -&gt; {}".format(message))

    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']

        if len(all_domains) == 0:
            domain = "NULL"
        else:
            domain = all_domains[0]

        sys.stdout.write(u"[{}] {} (SAN: {})\n".format(datetime.datetime.now().strftime('%m/%d/%y %H:%M:%S'), domain, ", ".join(message['data']['leaf_cert']['all_domains'][1:])))
        sys.stdout.flush()

        for keyword in keywords:
            if keyword in domain and all(black_keyword not in domain for black_keyword in blacklist_keywords):
                writetocsv(domain, all_domains, keyword)

            elif jaccard(keyword, domain, 2) is not None:
                writetocsv(domain, all_domains, keyword)

            elif damerau(keyword, domain) is not None:
                writetocsv(domain, all_domains, keyword)

            elif jaro_winkler(keyword, domain) is not None:
                writetocsv(domain, all_domains, keyword)

            elif unconfuse(domain) is not domain:
                latin_domain = unicodedata.normalize('NFKD', unconfuse(domain)).encode('latin-1', 'ignore').decode('latin-1')
                if keyword in latin_domain and all(black_keyword not in latin_domain for black_keyword in blacklist_keywords):
                    writetocsv(domain, all_domains, keyword)


if __name__ == '__main__':
    keywords = get_keywords()
    blacklist_keywords = get_blacklist_keywords()
    createfile()
    logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)
    certstream.listen_for_events(print_callback, url='wss://certstream.calidog.io/')
