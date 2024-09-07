# certthreat

As a Supplement to my other Project: https://github.com/PAST2212/domainthreat

Using CERT Transparency Logs via https://certstream.calidog.io/ API to monitor phishing domains or brand impersonations. This is interesting to find newly domain registrations that are not published on a daily basis by domain authorities  (e.g. DENIC does not publish domains with .de TLD - ICANN does publish .com domains).

**You can recognize:**
- full-word matching (e.g. amazon-shop.com), 
- regular typo squatting cases (e.g. ammazon.com), 
- typical look-alikes / phishing / so called CEO-Fraud domains (e.g. arnazon.com (rn = m),
- IDN Detection / look-alike Domains based on full word matching (e.g. 𝗉ay𝞀al.com - greek letter RHO '𝞀' instead of latin letter 'p'),

**Features**:
- False Positive Reduction Instruments (e.g. self defined Blacklists, Thresholds depending on string lenght)
- IDN / Homoglyph Detection
- CSV Export
- Find domains and **Subdomains** that are identical or confusingly similar to your name/brand/mailing domain name/etc 
- Mix of Edit-based and Token-based textdistance algorithms to increase result quality by considering degree of freedom in choosing variations of domain names from attacker side
- Domain Registrar and Domain Creation Date WHOIS are included.
- Possibility to change pre-defined thresholds of fuzzy-matching algorithms if you want to

**Example Screenshot CSV Output**
![image](https://user-images.githubusercontent.com/124390875/220607184-017fc523-8148-42ca-ba70-fe6bbe8d96fe.png)

**How to install:**
- git clone https://github.com/PAST2212/certthreat.git
- cd certthreat
- pip install -r requirements.txt

**How to run:**
- python3 certthreat.py

**Example Screenshot real-time request CERT Logs**
![image](https://user-images.githubusercontent.com/124390875/220610681-6f2bbb30-82af-42d5-9e66-2e06020b246f.png)

**How it Works**:

1. Put your brand names or mailing domain names into this TXT file "userdata/keywords.txt" line per line for monitoring operations (without the TLD). Some "TUI" Names are listed per default.

2. Put common word collisions into this TXT file "userdata/blacklist_keywords.txt" line per line you want to exclude from the results to reduce false positives.

- e.g. blacklist "lotto" if you monitor keyword "otto", e.g. blacklist "amazonas" if you want to monitor "amazon", ...

**Authors**
- Patrick Steinhoff (https://www.linkedin.com/in/patrick-steinhoff-168892222/)

**Aditional Info**
- Written in Python 3.10
- Recommended Python Version >= 3.8
- CERT STREAM Monitoring works with Multithreading: Parallel Processing Paramater "STANDARD_THREADS" and "MAX_QUEUE_SIZE" can be tuned based on your specific environment:
  - Default Value STANDARD_THREADS are CPU core based
  - Default Value MAX_QUEUE_SIZE is 1500
  - Increase STANDARD_THREADS, if CPU usage is low and queue is often full.
  - Decrease STANDARD_THREADS, if CPU usage is a concern. 
  - Increase MAX_QUEUE_SIZE, if too many certificates are issued during high-volume periods
  - Decrease MAX_QUEUE_SIZE, if memory usage is a concern.