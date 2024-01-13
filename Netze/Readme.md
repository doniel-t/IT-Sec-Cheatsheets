## **`Angriffsziele`**
- **Reconnaissance**
  - **`Goals`**
    - Zielsystem identifizieren
      - IP-Ranges
      - DNS-Einträge
      - Social Engineering
        - Kommunikationswege belauschen
        - Reverse Engineering
    - Einstiegspunkte (angriff) finden
    - Möglichst unentdeckt
  - Aufklärung / Erkundung
  - Angriffsvorbereitung
  - **(Schlechte) Gegenmaßnahmen**
    - Security by obscurity
    - Security by complexity
- **Datenübertragung**
- **Verfügbarkeit**
  - Denial of Service
- **Manipulieren**
  - Man In The Middle Attack durch
    - ARP / DNS-Spoofing
    - Proxy
  - Angriffe auf Anwendungen
    - Cross-Site Scripting
- **Unterdrücken / Stören**
  - Technische Störmaßnahme
  - DoS (Denial of Service)
    - "Einzelner Absturz" durch:
      - Programmabsturz
      - Routing-Angriffe
      - Ping of Death 
  - DDoS (Distributed Denial of Service)
    - `SYN-Flooding`
    - Also uses: `IP-Spoofing`
    - DNS-Amplification
      - Small Request -> Big Response (Verstärkungsfaktor)
      - Durch Spoofed-IP is Attack Source (Netzwerküberlastung dort)
        - Make target Spoofed-IP
      - DNSSEC / EDNS verstärkt attack (more Data) 
    - `Smurf-Angriff`
      - Ping von Opfer-IP UND an Broadcast-Adresse eines Netzwerks
      - Every PC answers -> BOMBA
    - `Gegenmaßnahme`
      - SYN-Cookie
        - Spart: Verbindungstabelle
        - **ABER:** Verzögert DDoS nur
      - Rate-Limit für TCP und ICMP-Pakete
        - Can deny legit requests (but still worth)
      - Load-Balancing
      - "Cloud Computing" (Have services hosted in cloud - eg. AWS, Vercel, Google Cloud)
    - `Alternative "DoS" Angriffe`
      - `Ping of Death`:
        - Manipuliertes fragmentiertes ICMP Echo Paket > 64KB
          - Server wants to Echo with (impossible) Paket and crashes
        - Bomba (Absturz)
      - `WinNuke`
        - Win95, Win NT, Win3.11 / 3.10 had vulnearability in NetBIOS
        - Send Paket with Port: 139 TCP with URG-Flag
          - Dies
      - `TearDrop`
        - TCP-Paket mit negativer Fragmentlänge
          - Crash be Re-Assembly
      - `Land Angriff`
        - Fake IP-Paket where Goal AND Source Adress = target IP
        - Set SYN Flag
        - Sends infinite Pakets to himself because of SYN/ACK - SYN loop
      - `TR-069`
        - Shell Injection in DSL Router because of vulnearability of their remote config system
        - Geringer Schaden, weil Telekom-Speedport Router unter eigenem OS liefen (shellcode didnt execute)
        - ABER Router still crashed because it got overloaded lmao
      - `Shell Injection`
        - Execute Shell commands in running programms
          - **`ALWAYS SANITIZE AND CHECK USER INPUTS`**
- **Belauschen**
  - `Sniffen`
    - **Wireshark**
  - `ARP-Poisoning`
    - Same as ARP Spoofing (mappes wrong IP to MAC on ARP request)
      - "Wrong IP" can now listen into it
    - can use **etercap**
    - `Gegenmaßnahme`
      - Statisches ARP
      - Port Überwachung am Switch
      - Verschlüsselung
      - Steganographie
  - DNS-Poisoning
    - Fucks with DNS Servers cache to setup wrong DNS response 
    - Goal: Legitime DNS Anträge auf hostile Websiten umzuleiten
    - **Gegenmaßnahme:**
      - Ignoriere "Zufallspakete"
      - Guessing
      - DNSSEC - kryptographisch abgesichert
        - Adds Public-Private-Key Signature (DNS Messages > 512 Byte)
      - DNSCurve
  - Man in the Middle


## **`Einstieg finden`**
- Erreichbarkeit
  - `Portscan` / `ping` cmd
- Netzinfrastruktur
  - `traceroute`
- Angebotene Dienste
  - `Portscan`
- Dienstversionen
  - `Connect Scan` / `Version Scan`
- OS
  - `OS Fingerprint`
- Firewalls

## **`3/4 Way-Handshakes`**
- **3 Way-Handshake**
  - Client SYN -> Server
  - Client <- SYN + ACK Server
  - Client ACK -> Server
  - Client FIN -> Server
  - Client <- FIN + ACK Server
  - Client ACK -> Server
- **4 Way-Handshake**\
  ...
  - Client FIN -> Server
  - Client <- ACK Server
  - **Client can only receive | Server can only send**
  - Client <- FIN Server
  - Client ACK -> Server

## **`Types of Scans`**
- **`SYN Scan`** 
  - Used for reachable **Ports**
  - Attack is done using nmap to manipulated pakets
  - [How To] (might still be in test)
  1. Attacker sends SYN Pakets to Target IP (on diff ports)
     1. SYN Pakets are 1st phase of TCP Handshake
  2. Target PC sends SYN/ACK if Port wants to establish connection
  3. Attacker sends RST instead of ACK to deny connection (ACK -> further establish connection, RST = Reset, connection denied)

- `TCP-Connect Scan`
  - Same as SYN Scan but it establishes a connections to make sure the port(s) really are open
  - Not as stealthy as SYN scan
- ACK Scan
- FIN Scan
- Xmas Scan

- `IP Scan`
  - can be used to scan ips etc but in this case we looking at ports
  - [How To] / Results:
    1. Any answer | open
    2. ICMP protocol unreachable | geschlossen
    3. ICMP unreachable | filtered
    4. No answer | offen / filtered

- `UDP Scan`
  - Scan for reachable **ports**
  - [How To] / Results:
    1. UDP answer received | open
    2. No UDP answer | offen / filtered
    3. ICMP port unreachable | closed
    4. ICMP unreachable | filtered

- **`Idle Scan`**
  - uses Zombie-Host (other PC) as "attacker"
  - IDS (Intrusion Detection System) hält Zombie für Angreifer
  - Actual attacker never communicates with target
  - Attacker finds info out based on IP-ID of Pakets with zombie
  - Relatively slow tho
  - [How To:]
    - Attacker sends SYN to Zombie and uses targets IP Adresse (as his own)
    - Zombie sends packages to target and updates attacker based on IP-ID

- **`Alt. Angriffsziele`**
  - Bordcomputer (TCP / IP)
  - Fernsteuerung (iOS, Google Glass, Web-Interface-API)
  - Offene Dienste wie z.B. Mittelkonsole (z.b. via ssh 22/tcp, 80/tpc httpd )

- **`hping`**
  - Multi-Funktionswerkzeug
    - Port Scanner
    - Fragmentierung variieren
    - Path MTU erkennen
    - Traceroute z.B. via TCP
    - Flooding
    - `TCP und UDP-Pakete selber bauen`
  - **Fragmentierung:**
    - Big Pakete werden aufgeteilt in Fragmente mit jeweils angegebenen Offset
    - `Attack:`
      - Set wrong offset to override pakets
      - `GOAL:` IDS & Firewall täuschen

### Schutz vor Portscan?
- Scan urself and close unneeded ports
- Use deny instead of reject -> Portscan time increases
- Add more Firewalls  

## Bridge vs Switch
- `Bridge`
  - used to connect 2 LANs and controls data flow between them
  - forwards data based on MAC
  - 2 ports
  - uses software to passthrough pakets
- `Switch`
  - "smart bridge"
  - learns which device on which port and thus can pass through packets wayy more efficiently 
  - has multiple ports
  - pakets are forwarded using hardware


## Tarnen & Täuschen
- `IP-Spoofing`
  - faking ones IP-Adresse
- `MAC-Spoofing`
  - faking ones MAC-Adresse
  - via:
    - Manuell
    - nmap
    - ARP-Poisoning
      - ARP = I have this IP - which MAC has this IP ?
      - ARP-Poisoning = Say you have wanted IP and give wrong MAC
- Passive Scans
  - similiar to idle scans  

## Angriffe erkennen

- `IDS Intrusion Detection System`
  - `HIDS` Host Based
    - Log File Analyse
    - Changes in File System
    - Zeichen von Schadsoftware
    - BSP: `AIDE` (Open Source) - Überwacht File System
      - Defines Rules and can apply Rules to certain directories like /etc `MyRule`
      - Rules include: Permissions, inode, Anzahl links, user, group, size, mtime, ctime, checksum
    - BSP: `tripwire` (Paid & Open Source version) - same as `AIDE`
    - BSP: `Afick` - Config files for tripwire
    - BSP: `LogSentry` Analysiert Logfiles via Cron-Job
      - Ist ein Shellscript
    - BSP: `chkrootkit`
      - .sh Array - scans system for rootkits
    - Combined Systems
      - `Samhain`, `Ossec` -> Überwachung per Agent (Results are safed on remote PC)
  
  - `NIDS` Network Based
    - `Snort` (Open Source)
      - Regelbasiert (paid updates on rules)
      - Alamiert Admins
      - **Alternative:** `Suricata`
    - Mögliche Placements:
      - Vor Firewall
        - Sieht alles, warnt viel
      - Hinter Firewall
        - Sieht nur relevante Angriffe
        - Warnt zielgenau
- `IPS Intrusion Prevention System`
  - IDS mit Firewall Zugriff (z.B. mit `Snort`)
    - blocking of sus IPs
    - Rewrite von sus packets
    - `Pro:` doenst need Admin to prevent attacks
  
  - **`Firewalls`**
    - Can Accept, Drop (doesnt answer initiater) or Reject (sends "stop" to initiater) Pakets
    - `Architektur`
      - Demilitirized Zone
        - Pufferzone zwischen Internen Netz und Internet
        - Resourcen, die für externe notwendig sind befinden sich dort (Mail-Server, Webserver etc)
        - Internet -> | FIREWALL | -> DMZ -> | FIREWALL | -> Internes Netz
      - Incomming Messagefilter
        - Prevents malicious pakets etc
      - Outcomming Messagefilter
        - Prevents leak of sensitive data / responses that can help attackers
    
    - `Firewall typen`
      - Filter Headerdaten
        - `Paketfilter` (stateless)
          - most simple filter
          - Every paket filtered individually
          - no context
          - `Pro:`
            - Easy & Robust
          - `Con:`
            - "leicht" knackbar
            - FTP hard to filter 
        - `Stateful Firewall`
          - remembers connection (status, participants)
          - recognized connections (eg. ftp_conntrack)
          - better filter than stateless
          - `Con:` DoS theoretically easier
          - `Stateful UDP` durch stateful Firewalls
            - Merkt sich Parameter (wie port, IPs etc.. und erkennt same connection)
            - Allows fitting answers (from UDP Partners)
            - Timeouts
            - BSP: DNS
      - Filterung Inhaltsdaten
        - Application Layer Firewall
    
    - `Timeouts`
      - UDP: Wont stop
      - TCP: Verbindungsabbruch
      - Solution: Timeouts **ABER** Verbindungsabbruch
        - Solution: `Keep-Alive` / `tcp_keepalive_time`

    - `SMTP`, `IMAP` `POP3` beschränken + HTTP-Zwangs-Proxy
    - **`SEGMENTIERUNG`**
      - Es ist so sinnvoll das interne Netzwerk in Logische Segmente durch firewalls einzuteilen
      - Aufbau: Internet | Firewall | DMZ | Firewall | n "logische Segmente" mit jeweils Firewall vor sich
      - `Pro:` Durch verschiedene Firewalls, verschiedene Angriffslücken -> Angriff aufwendiger
    - `DEDICATED FIREWALL BLEIBT FIREWALL **ONLY**`
      - ABER Services wie Webserver, Mailserver etc können eine extra Firewall haben (schadet nicht)

    - `iptables`
      - Benutzt **"chains"** (rule chaining) um Pakete "local am Rechner" zu filtern
        - [HOW TO]
          - Chains
            - Input
            - Output
            - Forward
            - Prerouting
            - Postrouting
          - Targets
            - DROP
            - REJECT
            - ACCEPT
            - DNAT
            - SNAT
            - LOG
            - MASQUERADE
            - TPROXY
  
    - `OpenBSD`
      - TCP-SYN-Proxy gegen TCP-SYN-Flooding
      - Passive OS fingerprinting
      - FTP Proxy
      - `Pro:`
        - Very strong
        - Ez config
  
    - `Firewalling von IPv6 (vs IPv4)`
      - `ICMPv4`
        - "Optional"
        - Ping, Traceroute
        - Fehlermeldungen
        - `wird häufig komplett gefiltert`
      - `ICMPv6`
        - Neighbour discovery === ARP aus IPv4
        - Router Ad | Path MTU Discovery | Mobile IPv6
        - `DO NOT FILTER ICMPv6`
      - `Multicast` IPv6 (Besseres Broadcast von IPv4)
        - Verstärkt DoS
        - `Ratelimit Multicast (or Filter)`
      - `Extension Header?`
        - can be used for infinite possible scenarios
        - `Check if header is plausible also check content of header`
      - `Hop-By-Hop`
        - Padding possible
        - `check padding`
      - `Fragmentation`
        - Can bypass IDS
        - `use (virtual) Fragment Reassembly (fix Fragments and check if fine)`
    
    - `Honeypot / Teergrube`
      - Fake open Ports / Services
        - **Honeypot**: To observe Attacker
        - **Teergrube**: Stören / Behindern / Blockieren
    
  ### `Proxy` (Application Layer Firewall)
  - Usecases: 
    - Proxy with content filter
    - checks application data
    - stops (simple) tunnels
  
  - `Forward Proxy`
    - Proxy kontrolliert, überwacht und filtert den Datenfluss
    - Proxy Server is in clients network
    - Client sends request to Server
    - Actually client sends request to Proxy server, who then forwards it to the wanted server
    - Proxy recieves answer, checks it and then forwards it back to the client
 
  - `Reverse Proxy`
    - Proxy sits infront of server instead of client
    - Otherwise same function as forward Proxy
  
  - `Transparent Proxy`
    - "Transparent btw" user doesnt know proxy is there
    - Setup: Firewall redirects requests to proxy first and proxy forwards it
  
  - `Bridge Proxy`
    - Technisch aufwendig
    - Completely "transparent"
 
  - `Web-Content-Filter`
    - Jugendschutz
    - Werbefilter
    - Zensur
    - Malware Schutz
    - `Anti-Virus-Proxy`
      - `Squid`
        - ClamAV (server) is a Proxy, that checks URL for malware first
        - If ok requester gets the ok and bypasses ClamAV to answer instantly to server
        - `Pro:`
          - very generic
          - very flexible
        - `Con:`
          - Complex Setup
          - loads twice
      - `DansGuardian`
        - Content Filter (Viren, Jugendschutz etc..)
        - Daisy Chaining with Squit (add to squid)
          - Setup: Client -> Dans Guardian -> Squid -> Web -> Server 

- `NAT`
  - Router as seperation of Internet and local Network
  - Router "spins up" new IP Adresse Range in local Network 
  - Router has public IP to internet and forwards messages to corresponding pc in local network based on given Port


## Tunneling (VPN)
- Concepts
  - Variant A: Use other protocol port
  - Variant B: Make requests look like other protocol
  - Variant C: Verpacke wie IPSec, IPv4 in IPv6 etc
  
- **Possible Tunnels**:
  - Can do everything `BESIDES` `IPv6 in Tunnel IPv6` 
  - `IPSec`
  - IPv4 in IPv4 Tunnel
  - IPv6 in IPv4 Tunnel
  - IPv4 in IPv6 Tunnel
  - VPN = Virtual Private Network

- `How it works`
  - "Simulates private network"
  - VPN Client (runs on Client PC) has virtual Network-card
  - VPN Client send paket to VPN Server
  - VPN Server distributes paket to desired client

- `VPN mit IPSec`
  - `Transportmodus`
    - Genutzt zwischen Endgeräten für End-To-End-Sicherheit
    - Sicherheitsdienste werden nur auf den Payload angewendet
    - Ursprünglicher IP Header bleibt gleich
  - `Tunnelmodus`
    - Flexibler als Transport Modus
    - Tunnel durch unsichere Netze
    - Üblich bei Routern, Netzwerkgateways
    - Gesamte IP-Datenverkehr wird verschlüssel / signiert
    - Adds new IP Header

  - `Möglichkeiten`
    - `AH - Authentication Header`
      - Wird zwischen IP Header und Payload geadded
      - Enthält infos über: Integrität, Authentizität, Checksums etc
      - `KEINE VERSCHLÜSSELUNG`
      - `Transportmodus`  
        - `Pro:`
          - Low Overhead
          - Fälschungssicher
          - Sicher gegen Replay Angriffe
        - `Con:`
          - NAT: Goal- and Source-IP changed
          - Port-Translation: Goal-Port changed

    - `ESP - Encapsulated Security Payload`
      - `Verschlüsselung + Echtheit`
      - `Transportmodus`
        - Encapsulates only TCP Header and TCP Payload
      - `Tunnelmodus`
        - Encapsulates **complete** olld Paket

    - `Weiter Varianten`
      - Wireguard (UDP)
      - OpenVPN (TLS über UDP oder TCP)

    - `DNS Tunnel`
      - Uses DNS as a way to let Client and Server communicate
  