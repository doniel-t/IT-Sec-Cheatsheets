## Anti-Spam
### **Was ist Spam?**
- UCE: Unsolicted Commercial Email (Spam Werbung (auf einen selbst abgestimmt))
- UBE: Unsolicted Bulk Email (Generelle Spam Mail)

### Business Case: Why Spam?
- Verkauf von:
  - Dienstleistungen, (in-)tangible Güter
- Vermittlungsprovisionen
- Betrug

### `Filter Methoden`
- Absender Adresse (known Spammer)
- Absender IP
  - DNS Black-List
- Inhalt
  - static analysis
  - Bayes-Filter
  - Wortmuster
- Spam Traps
- `Verbesserung durch Kombination`
  - Erzeugt Score (ggf. mit Gewichtung)
  - Score > Threshold = spam
  - `ABER` still usesless, da:
    - False Positives
    - False Negatives

### `Alternative Verfahren`
- **Greylisting**
  - via OpenBSD spamd
  - `How:`
    - SMPT-Server melded temp Fehler (4xx) on purpose
    - real mail will resend, spammer wont resend
    - `ABER:` Anbieter wie outlook.com senden von n Servern und nutzen für jeden try einen anderen
    - `FIX:` Whitelisting
- **Prävention**
  - `Adress-Quellen` (How they get the Email-Adresses)
    - Data-Breaches
    - Web-Scraping (Harvesting)
      - scan nach `<a href="mailto:..."`
      - scan nach links
      - `Gegenmaßnahme:`
        - **Obfuscating**
          - Email als image hochladen
          - Pattern matching stören (random spaces in email)
          - Use JS to display email (hydration instead of static generation)
          - `Use contact fomulars instead! `
        - Web Scraper blocken (disable js for bots / captchas etc)
    - Adress-Handel
    - Malware
    - "Freiwillige" Teilnahmen
  - **`Minimize Adress-Quellen as much as possible`**  
- **Forensik**
  - Analyse von Email-Headern
  - Harvester beobachten
  - Goal: Find sender, but its very difficult nowaydas due to bot nets

### `OpenBSD spamd`
- Has Black List, White List and Grey List
- `Ablauf:`
  - Has 3 smtp ports open (for Black-, Grey- und WhiteList)
  - Email comes in:
    ```js
    if(isBlackListed) {
        //Teergrube
        drop();
    } else {
        if (isWhiteListed) {
            accept();
        } else {
            if(isInGreyList) {
                isWhiteListed = true;
                reject({ statusCode: "4xx"});
                return;
            }
            reject({ statusCode: "4xx"});
            isInGreyList = true;
        }
    }
    ```


### `Honeypot-Adressen`
- Zusätzliche Emails
- Mails an diese Adressen werden temporär geblacklisted

