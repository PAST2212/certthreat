import certstream
import logging
import sys
import datetime
import pandas as pd
import tldextract
import whois
from detectidna import unconfuse
import unicodedata
import textdistance
import os
import csv

# Strings or brand names to monitor
# e.g. brands or mailing domain names that your company is using for sending mails
# Keyword File as List
list_file_keywords = []

# Important if there are common word collisions between brand names and other words to reduce false positives
# e.g. blacklist "lotto" if you monitor brand "otto"
# Blacklist File as List
list_file_blacklist_keywords = []


desktop = os.path.join(os.path.expanduser('~'), 'certthreat')


def damerau(keyword, domain):
    domain_name = tldextract.extract(domain, include_psl_private_domains=True).domain
    similarity = textdistance.damerau_levenshtein(keyword, domain_name)

    if 4 <= len(keyword) <= 6:
        if similarity <= 1:
            return domain


    elif 6 < len(keyword) <= 9:
        if similarity <= 2:
            return domain


    elif len(keyword) >= 10:
        if similarity <= 3:
            return domain



def jaccard(keyword, domain, n_gram):
    domain_letter_weight = '#' + tldextract.extract(domain, include_psl_private_domains=True).domain + '#'
    keyword_letter_weight = '#' + keyword + '#'
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


def whois_creation_date(domain):
    try:
        registered = whois.whois(domain).creation_date
        if registered is not None:
            return registered.strftime('%d-%m-%y')

    except Exception as e:
        print(domain, e)


def whois_registrar(domain):
    try:
        registered = whois.whois(domain).registrar
        if registered is not None:
            registered_1 = registered.replace(',', '')
            return registered_1

    except Exception as e:
        print(domain, e)



def createfile():
    conso_file_path = f"{desktop}/CERT_Monitoring_Calender_Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv"
    if not os.path.exists(conso_file_path):
        header = ['(Sub-)Domain', 'Registered Domain', 'Keyword', 'Registrar', 'Domain Creation_Date', 'Monitored Date']
        with open(conso_file_path, 'w') as f:
            writer = csv.writer(f)
            writer.writerow(header)


def writetocsv(domain, all_domains, keyword):
    tlds = tldextract.extract(domain)
    df = pd.DataFrame([all_domains[0]])
    df['Registered Domain'] = tlds.registered_domain
    df['Keyword'] = pd.Series(keyword, dtype='object')
    df['Registrar'] = df.apply(lambda x: whois_registrar(tlds.registered_domain), axis=1)
    df['Domain Creation_Date'] = df.apply(lambda x: whois_creation_date(tlds.registered_domain), axis=1)
    df['Monitored Date'] = pd.Series(datetime.date.today(), dtype='object')
    df.to_csv(f"{desktop}/CERT_Monitoring_Calender_Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv", index=False, mode='a', header=False)


def read_input_keywords_file():
    file_keywords = open(desktop + '/User Input/keywords.txt', 'r', encoding='utf-8-sig')
    for my_domains in file_keywords:
        domain = my_domains.replace("\n", "").lower().replace(",", "").replace(" ", "").strip()
        if domain is not None and domain != '':
            list_file_keywords.append(domain)
    file_keywords.close()


def read_input_blacklist_file():
    file_blacklist = open(desktop + '/User Input/blacklist_keywords.txt', 'r', encoding='utf-8-sig')
    for my_domains in file_blacklist:
        domain = my_domains.replace("\n", "").lower().replace(",", "").replace(" ", "").strip()
        if domain is not None and domain != '':
            list_file_blacklist_keywords.append(domain)
    file_blacklist.close()


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

        for keyword in list_file_keywords:
            if keyword in domain and all(black_keyword not in domain for black_keyword in list_file_blacklist_keywords):
                writetocsv(domain, all_domains, keyword)

            elif jaccard(keyword, domain, 2) is not None:
                writetocsv(domain, all_domains, keyword)

            elif damerau(keyword, domain) is not None:
                writetocsv(domain, all_domains, keyword)

            elif jaro_winkler(keyword, domain) is not None:
                writetocsv(domain, all_domains, keyword)

            elif unconfuse(domain) is not domain:
                latin_domain = unicodedata.normalize('NFKD', unconfuse(domain)).encode('latin-1', 'ignore').decode('latin-1')
                if keyword in latin_domain and all(black_keyword not in latin_domain for black_keyword in list_file_blacklist_keywords):
                    writetocsv(domain, all_domains, keyword)


if __name__ == '__main__':
    createfile()
    read_input_keywords_file()
    read_input_blacklist_file()
    logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)
    certstream.listen_for_events(print_callback, url='wss://certstream.calidog.io/')

