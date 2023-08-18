import certstream
import logging
import sys
import datetime
import pandas as pd
import tldextract
import whois
from confusables import unconfuse
import unicodedata
import textdistance
import os
import csv
import whoisit
import re

# Strings or brand names to monitor
# e.g. brands or mailing domain names that your company is using for sending mails
# Keyword File as List
list_file_keywords = []

# Important if there are common word collisions between brand names and other words to reduce false positives
# e.g. blacklist "lotto" if you monitor brand "otto"
# Blacklist File as List
list_file_blacklist_keywords = []

whoisit.bootstrap()

desktop = os.path.join(os.path.join(os.environ['HOME']), 'certthreat')

# Using Edit-based Textdistance Damerau-Levenshtein for finding look-a-like Domains
# Lenght of brand name or string decides threshold
def damerau(keyword, domain):
    domain_name = tldextract.extract(domain).domain
    damerau = textdistance.damerau_levenshtein(keyword, domain_name)

    if 4 <= len(keyword) <= 6:
        if damerau <= 1:
            return domain

    elif 6 <= len(keyword) <= 9:
        if damerau <= 2:
            return domain

    elif len(keyword) >= 10:
        if damerau <= 3:
            return domain

# Using Token-based Textdistance Jaccard for finding look-a-like Domains
# Threshold is independent from brand name or string lenght
def jaccard(keyword, domain, n_gram):
    domain_name = tldextract.extract(domain).domain
    ngram_keyword = [keyword[i:i+n_gram] for i in range(len(keyword)-n_gram+1)]
    ngram_domain_name = [domain_name[i:i+n_gram] for i in range(len(domain_name)-n_gram+1)]

    intersection = set(ngram_keyword).intersection(ngram_domain_name)
    union = set(ngram_keyword).union(ngram_domain_name)

    similarity = len(intersection) / len(union) if len(union) > 0 else 0

    if similarity > 0.5:
        return domain

# Using Edit-based Textdistance Jaro Winkler for finding look-a-like Domains
# Threshold is independent from brand name or string lenght
def jaro_winkler(keyword, domain):
    domain_name = tldextract.extract(domain).domain
    Jaro_Winkler = textdistance.jaro_winkler.normalized_similarity(keyword, domain_name)
    if Jaro_Winkler >= 0.9:
        return domain


# Make WHOIS or RDAP Domain Creation Date lookup
def whois_creation_date(domain):
    try:
        registered = whoisit.domain(domain, allow_insecure_ssl=True)['registration_date']
        creation_date = registered.strftime('%d-%m-%y')
        return creation_date

    except (whoisit.errors.UnsupportedError, KeyError, AttributeError, whoisit.errors.QueryError):
        try:
            registered = whois.whois(domain)
            creation_date = registered.creation_date
            return creation_date[0].strftime('%d-%m-%y')

        except (TypeError, AttributeError):
            if creation_date is not None:
                return creation_date.strftime('%d-%m-%y')
            else:
                pass

        except Exception:
            pass
        except whois.parser.PywhoisError:
            pass

    except whoisit.errors.ResourceDoesNotExist:
        pass


# Make WHOIS or RDAP Domain Creation Date lookup
def whois_registrar(domain):
    try:
        registered = whois.whois(domain)
        registered_1 = registered.registrar.replace(',', '')
        return registered_1

    except:
        try:
            registered = whoisit.domain(domain)
            registered_1 = registered['entities']['registrar'][0].get('name').replace(',', '')
            return registered_1

        except:
            pass


# Create File if not existed with fixed columns
def createfile():
    conso_file_path = f"{desktop}/CERT Log Results_Calender-Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv"
    if not os.path.exists(conso_file_path):
        header = ['(Sub-)Domain', 'Registered Domain', 'Registrar', 'Domain Creation_Date', 'Keyword', 'Monitored Date']
        with open(conso_file_path, 'w') as f:
            writer = csv.writer(f)
            writer.writerow(header)


# Create Pandas to manage Data columns
def writetocsv(domain, all_domains, keyword):
    tlds = tldextract.extract(domain)
    df = pd.DataFrame([all_domains[0]])
    df['TLDS'] = tlds.registered_domain
    df['WHOISRegistrar'] = pd.Series(whois_registrar(tlds.registered_domain), dtype='object')
    df['WHOISCreation_date'] = pd.Series(whois_creation_date(tlds.registered_domain), dtype='object')
    df['Keyword'] = pd.Series(keyword, dtype='object')
    df['Monitored Date'] = pd.Series(datetime.date.today(), dtype='object')
    df.to_csv(f"{desktop}/CERT Log Results_Calender-Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv", index=False, mode='a', header=False)


createfile()

# Read Keywords TXT File as List
def read_input_keywords_file():
    file_keywords = open(desktop + '/User Input/keywords.txt', 'r', encoding='utf-8-sig')
    for my_domains in file_keywords:
        domain = my_domains.replace("\n", "").lower().strip().replace(",", "")
        list_file_keywords.append(domain)
    file_keywords.close()


read_input_keywords_file()


# Read Blacklist for Keywords TXT File as List
def read_input_blacklist_file():
    file_blacklist = open(desktop + '/User Input/blacklist_keywords.txt', 'r', encoding='utf-8-sig')
    for my_domains in file_blacklist:
        domain = my_domains.replace("\n", "").lower().strip().replace(",", "")
        list_file_blacklist_keywords.append(domain)
    file_blacklist.close()


read_input_blacklist_file()


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
            if keyword in domain and all(black_keyword not in domain for black_keyword in list_file_blacklist_keywords) is True:
                writetocsv(domain, all_domains, keyword)

            elif jaccard(keyword, domain, 2) is not None:
                writetocsv(domain, all_domains, keyword)

            elif damerau(keyword, domain) is not None:
                writetocsv(domain, all_domains, keyword)

            elif jaro_winkler(keyword, domain) is not None:
                writetocsv(domain, all_domains, keyword)

            elif unconfuse(domain) is not domain:
                latin_domain = unicodedata.normalize('NFKD', unconfuse(domain)).encode('latin-1', 'ignore').decode('latin-1')
                if keyword in latin_domain:
                    writetocsv(domain, all_domains, keyword)


logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)

certstream.listen_for_events(print_callback, url='wss://certstream.calidog.io/')
