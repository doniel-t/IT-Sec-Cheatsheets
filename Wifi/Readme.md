## `History`
### `Keine Verschlüsselung`
### `WEP-Verschlüsselung`
   - Verschlüsselung durch `Cäsar` "moderner" durch `XOR`
   - Pseudorandom Keys
   - Seed for Randomkeys: `WEP-Key` or `Initialisierungsvektor`
   - Auch `RC4` (ist Seed vorhersehbar ist pseudorandom key bekannt)
   - **`WEP`**
     - RC4-Key aus WEP-Key + Initialisierungsvektor -> Datenstrom XOR RC4
     - `Shared Key Auth`
       - Request from Client
       - Server sends Challenge 1 (Random num)
       - Client decrypts rand num -> sends to server
       - Server meldet Ergebnis
       - `Attacks`
         - **Lauschen:** Bei ausreichend Paketen -> Key berechenbar
         - **Re-Injection:** Unterbricht "Handshake" durch einschleusen von Paketen (z.B. ARP spam)
           - viele neue Pakete zum belauschen
         - `Tools to Attack`
           - **airsnort**
           - **aircrack(-ng)**
           - **airmon(-ng)**
           - **Kismet**
  
### `WPA2 IEEE 802.11i`
   - `AES-Verschlüsselung`
   - Auth via
     - PSK (Pre-Shared-Key aka Wifi PW)
     - Radius
   - `Angriffe`
     - Brute-Force
     - `KRACK` (Key Reinstallation AttaCK)
       - WPA2 uses 4 Way Handshake to auth
         - random secret key (`PTK` = Pairwise Transient Key)
         - generate: `PMK` = Pairwise Master Key
       - `Attack Idea:`
         - Messages can be lost
         - Retransmission possible (Replay-Counter refreshes)
         - Client accepts message 3 (of 4 way handshake) even tho key is initialized
         - `Man In the Middle` with message 3
     - `WPS Pin Cracking`
       - PIN = 7 Ziffern + Prüfziffer
       - Server answeres: Correct or Incorrect
       - Ez Brute-Force
     - `Attack on Energy-saving Mode`
       - **Background INFO:**
         - AP speicher Key von Netzwerkgeräten
         - Netzwerkgerät in Energiesparmodus (AP buffered Msgs unencrypted)
         - Netzwerkgerät (Client) wacht auf -> AP encrypts Key and sends it to Client
       - **Attack:**
         - Attacker uses Targets MAC and says it woke up (pakets go to attacker)
         - Attacker still cant read Key XD **BUT** can request Key Re-Association-Request (like KRACK)
  
### WPA3
- `New Features`
  - Protected Management Frames
  - Ez Einbindung ins Netz (buff for IoT)
  - Verbesserte Privatsphäre in offenen Netzen
  - Sicherere Verschlüsselung
  - Konzepte zur Vermeidung von Dictionary Attacks
  - KRACK geht nicht mehr
  - `WiFi Easy-Connect`
    - AP tauscht Key (von Configurator) via QR Code
    - Configurator liest Public Key von IoT via NFC, QR-Code, Cloud -> Sign in