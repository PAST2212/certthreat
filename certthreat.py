from pathlib import Path
import os
import csv
import datetime
import logging
import unicodedata
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
import textdistance
import whois
import tldextract
import certstream
import pandas as pd
from detectidna import unconfuse

USERDATA_DIRECORY = Path(__file__).parents[0] / 'userdata'

MAX_QUEUE_SIZE = 1500
STANDARD_THREADS = min(4, os.cpu_count())


def damerau(keyword: str, domain: str, tld_extract: tldextract.tldextract.TLDExtract) -> str:
    # Based on / Inspired by (c) Everton Gomede, PhD
    domain_name = tld_extract(domain).domain
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


def jaccard(keyword: str, domain: str, n_gram: int, tld_extract: tldextract.tldextract.TLDExtract) -> str:
    domain_letter_weight = tld_extract(domain).domain
    keyword_letter_weight = keyword
    ngram_keyword = [keyword_letter_weight[i:i + n_gram] for i in range(len(keyword_letter_weight) - n_gram + 1)]
    ngram_domain_name = [domain_letter_weight[i:i + n_gram] for i in range(len(domain_letter_weight) - n_gram + 1)]
    intersection = set(ngram_keyword).intersection(ngram_domain_name)
    union = set(ngram_keyword).union(ngram_domain_name)
    similarity = len(intersection) / len(union) if len(union) > 0 else 0

    if similarity > 0.6:
        return domain


def jaro_winkler(keyword: str, domain: str, tld_extract: tldextract.tldextract.TLDExtract) -> str:
    domain_name = tld_extract(domain).domain
    similarity = textdistance.jaro_winkler.normalized_similarity(keyword, domain_name)
    if similarity >= 0.9:
        return domain


def make_whois_request(domain: str) -> tuple:

    creation_date = ''
    registrar = ''

    try:
        registered = whois.whois(domain)
        if registered.creation_date is not None:
            creation_date = registered.creation_date.strftime('%d-%m-%y')

        if registered.registrar is not None:
            registrar = registered.registrar.replace(',', '')

    except Exception as e:
        logging.exception(f'{type(e)}: Something went wrong with WHOIS Request for {domain}. Error Message: {e}')

    return creation_date, registrar


def create_file() -> None:
    conso_file_path = f"CERT_Monitoring_Calender_Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv"
    if not os.path.exists(conso_file_path):
        header = ['(Sub-)Domain', 'Registered Domain', 'Keyword', 'Registrar', 'Domain Creation_Date', 'Monitored Date']
        with open(conso_file_path, 'w') as f:
            writer = csv.writer(f)
            writer.writerow(header)


def write_to_csv(domain: str, all_domains: list, keyword: str) -> None:
    registered_domain = tldextract.extract(domain, include_psl_private_domains=True).registered_domain
    creation_date, registrar = make_whois_request(domain=registered_domain)
    df = pd.DataFrame([all_domains[0]])
    df['Registered Domain'] = registered_domain
    df['Keyword'] = pd.Series(keyword, dtype='object')
    df['Registrar'] = pd.Series(registrar, dtype='object')
    df['Domain Creation_Date'] = pd.Series(creation_date, dtype='object')
    df['Monitored Date'] = pd.Series(datetime.date.today(), dtype='object')
    df.to_csv(f"CERT_Monitoring_Calender_Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv", index=False, mode='a', header=False)


def get_keywords() -> list[str]:
    main_keywords = []
    file_keywords = open(f'{USERDATA_DIRECORY}/keywords.txt', 'r', encoding='utf-8-sig')
    for my_domains in file_keywords:
        domain = my_domains.replace("\n", "").lower().replace(",", "").replace(" ", "").strip()
        if domain is not None and domain != '':
            main_keywords.append(domain)
    file_keywords.close()

    return main_keywords


def get_blacklist_keywords() -> list[str]:
    black_keywords = []
    file_blacklist = open(f'{USERDATA_DIRECORY}/blacklist_keywords.txt', 'r', encoding='utf-8-sig')
    for my_domains in file_blacklist:
        domain = my_domains.replace("\n", "").lower().replace(",", "").replace(" ", "").strip()
        if domain is not None and domain != '':
            black_keywords.append(domain)
    file_blacklist.close()

    return black_keywords


def process_domain(domain: str, all_domains: list, keywords: list[str], blacklist_keywords: list[str], tld_extract: tldextract.tldextract.TLDExtract) -> None:
    for keyword in keywords:
        if (keyword in domain and all(black_keyword not in domain for black_keyword in blacklist_keywords)) or jaccard(keyword, domain, 2, tld_extract) is not None or damerau(keyword, domain, tld_extract) is not None or jaro_winkler(keyword, domain, tld_extract) is not None:
            write_to_csv(domain, all_domains, keyword)
            return None

        latin_domain = unicodedata.normalize('NFKD', unconfuse(domain)).encode('latin-1', 'ignore').decode('latin-1')
        if keyword in latin_domain and all(black_keyword not in latin_domain for black_keyword in blacklist_keywords):
            write_to_csv(domain, all_domains, keyword)
            return None

    return None


def worker(queue, keywords: list[str], blacklist_keywords: list[str], tld_extract: tldextract.tldextract.TLDExtract) -> None:
    while True:
        item = queue.get()
        if item is None:
            break
        domain, all_domains = item
        process_domain(domain, all_domains, keywords, blacklist_keywords, tld_extract)
        queue.task_done()


def print_callback(message, context, queue) -> None:
    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']

        if len(all_domains) == 0:
            domain = "NULL"
        else:
            domain = all_domains[0]

        logging.info(f"[{datetime.datetime.now().strftime('%m/%d/%y %H:%M:%S')}] {domain} (SAN: {', '.join(all_domains[1:])})")

        queue.put((domain, all_domains))


def main():

    keywords = get_keywords()
    blacklist_keywords = get_blacklist_keywords()
    create_file()

    tld_extract_object = tldextract.TLDExtract(include_psl_private_domains=True)
    tld_extract_object('google.com')

    logging.basicConfig(format='[%(levelname)s:%(name)s] - %(message)s', level=logging.INFO)

    queue = Queue(maxsize=MAX_QUEUE_SIZE)

    with ThreadPoolExecutor(max_workers=STANDARD_THREADS) as executor:
        for _ in range(STANDARD_THREADS):
            executor.submit(worker, queue, keywords, blacklist_keywords, tld_extract_object)

        certstream.listen_for_events(lambda message, context: print_callback(message, context, queue), url='wss://certstream.calidog.io/')


if __name__ == '__main__':
    main()
