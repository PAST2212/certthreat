# certthreat

As a Supplement to my other Project: https://github.com/PAST2212/domainthreat

Using CERT Transparency Logs https://github.com/CaliDog/certstream-python to monitor phishing domains or brand impersonations. This is interesting to find newly domain registrations that are not published on a daily base by domain authorities  (e.g. DENIC does not publish domains with .de TLD - ICANN does publish .com domains).

Features:

- False Positive Reduction Instruments (e.g. self defined Blacklists, Thresholds depending on string lenght)
- IDN / Homoglyph Detection
- CSV Export ("Ubuntu\home\User\Desktop" path is default path to create output)
- Find domains that are identical or confusingly similar to your name/brand/mailing domain name/etc.
- Mix of Edit-based and Token-based textdistance algorithms to increase result quality by considering degree of freedom in choosing variations of domain - names from attacker side
- Domain Registrar and Domain Creation Date WHOIS as well as RDAP lookups are included.
- Possibility to change pre-defined thresholds of fuzzy-matching algorithms if you want to


How it Works:

![image](https://user-images.githubusercontent.com/124390875/217082812-6a7260dd-2da7-4b2b-989e-66339ac5b6ed.png)
Put your brands or mailing domain names into this list for monitoring operations (without the TLD).

![image](https://user-images.githubusercontent.com/124390875/217082944-c81d8f11-b953-409d-8bb7-9fad5cdcc1f6.png)
Put here common word collisions you want to exclude from the results to reduce false positives.


Written in Python 3.7
