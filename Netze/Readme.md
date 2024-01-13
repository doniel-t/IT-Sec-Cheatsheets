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
  - DDOS / DOS

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

    - Mindestregel
    - iptables
    - Test mit Portscan
    - Transparent Proxy 