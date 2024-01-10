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
- `MAC-Spoofing`
  - via
    - Manuell
    - nmap
    - ARP-Poisoning
      - ARP = I have this IP - which MAC has this IP ?
      - ARP-Poisoning = Say you have wanted IP and give wrong MAC
- Passive Scans
  - similiar to idle scans  

## Angriffe erkennen