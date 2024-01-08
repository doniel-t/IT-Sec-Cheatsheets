## **`Kryptanalyse`**:
- **Monogramme**: Zählen wo welcher Buchstabe am Häufigsten ist z.B. Allg: E>N>I>S>R 
    - -> Häufigkeit wird benutzt um Keys der Verschlüsselung rauszufinden
- **Bigramme**: 2 Buchstaben die aufeinander folgen
    -> Use info to crack Keys
- **Trigramme**: 3 Buchstaben
- **Bruteforce**



##  **`Symmetrische Kryptographie:`**
- ``Pro``
  - Schnell | Hardware-Unterstützung mögl
  - Moderne Verfahren sind sehr sicher
- ``Con``
  - **Schlüsselübertragung**


### **`Monoalphabetische Verfahren:`**
- `Cäsar, ROT13`
- **IMPROVEMENT:**
  - turn similiar looking symbols into same (eg. I, l wird zu X)
  - remove ["," | "." | ":"] and remove world length (eg. split word at randon length)
- **XOR**: (A XOR B) XOR B = A  (B is the key)
  - Problem: 1 <= B <= 255 -> Simple Bruteforce
    
### **`Polyaphabetische Kryptographie:`**

- **Vignere Verschlüsselung:**
    - [How To]:
        - Build Table where each row is shifted by 1 letter of alphabet
        - Have Key (phrase) and Text to Encrypt, repeat key until its as long as text
        - map Letter of Text to Letter of Key and look it up at the table at table[clearTextLetter][keyPhraseLetter] -> encryped letter
    - **[Pro / Con]**:
      - Len Key is important
      - Len(K) >> Len(Text) machts anfällig für Bi-Trigramme

### **`Stromchiffren`**: == Byte-weise verschlüsseln
- **RC4**:
    - S-Box mit 256 Values, initialized with Key
    - crypt(Eingabe[i]) = Eingabe[i] XOR S[i]
    - SBox wird Pseudo-Randomized each step
    => Gleicher Pseudo-Random String bei Sender, Receiver
    
    **[RISKS]**:
    - Known key = broken
    - Same key for long time = ez to break
    - Solution: Hash key with random val 

### **`Blockchiffren`**:
- **Concept: Blockwise encription [eg: 64Bit] or n*64 Bit padding**
- ``Bsp: DES / 3DES | IDEA | AES``
- [How To]:
    - Split messages if msg > n Bit
        - **Elcectronic Code Book Mode**
            - Every Block independantly encrypted
                - **Pro**: Errors only hits Error Blocks
                - **Con**: Same Blocks same encrypted Blocks
                
        - **Cipher Block Chaining Mode**
            - Like Electronic Code Book Mode but you encript Block i+1 with Block i
                - **Pro**: Errors cascade through blocks, Same Input - -  Block -> Diff output Block
                - **Con**: Cant be parallelized

        - **Cipher Feedback Mode**
            - Like Cipher Block Chaining Mode but:
                - n bit aus Input Strom ersetzen n bit aus Key (no padding)
                - => Block Chiffre als Strom Chiffre

- **`DES: Data Encryption Standard (USA, 1977)`**
    - Schlüssellänge DES: 64 Bit is split into 56 Bit (chosen by User) + 8 Bit parity
    - Multiple Step encryption: [Permutation, halbieren, (multiple times), add all split parts (xor), permutations -> done ]

- **`IDEA: ETH Zürich (1990)`**
    - 128 Bit Key mit 64 Bit Blocks
    - 8 Splits + 1-2 Ausgaberunden
    - Komplexe Key gen

- **`AES: Advanced Encryption Standard`**
    - 128 Bit Blöcke
    - Key Length 128, 160, 192, 224, 256 Bit (**192** und **256** zugelassen für **TOP SECRET US Documents**)
    - Guter Hardware support
    - Theoretisch gebrochen, praktisch unrealistisch => Sicher
  
    - [How To]
        - Key expansion
        - Rundenschlüssel generieren
        - [Verschlüsselungsrunden (Anz. Keylen)]
            - Substitute Bytes
            - Shift Rows
            - Mix Columns
            - Rundenschlüssel generieren
        - [Schlussrunde]
            - SubBytes
            - ShiftRows
            - Rundenschlüssel generieren


## `Schlüsselübertragung`
- **`Diffie-Hellmann`**
  - **Primitve Wurzel (hier) P**
    - P mod 7 ist eine Zahl deren Potenzen, alle möglichen Reste von 1 bis 6 (7 - 1) erzeugt, also P^1 mod 7, P^n mod 7 etc..
    - 3 ist eine primitve Wurzel von 7
  - [How To] (Kommt maybe dran)
    - Client und Server wählen Primzahl `p` und Primitiv Wurzel `g mod p`
    - Client und Server wählen jeweils geheime Zahl `a` und `b`
    - Public Key Gen
      - Partei A: `A = g^a mod p`
      - Partei B: `B = g^b mod p`
    - Austausch der Pub Keys
    - Private Key Gen
      - Partei A: K = `B^a mod p`
      - Partei B: K = `A^b mod p`
      - **Private Key ist für beide gleich**
- Verzicht auf Übertragung -> `Asymmetrische Kryptographie`


## `Asymmetrische Kryptographie`
- Everyone has (different) Public and Private Key
- Public Keys encrypt everyones Data **only** owner of private Key can decrypt
- `Pro`
  - ez key transmition
- `Con`
  - Calculations more expensive than symmetrical
  - Need for longer keys (if u want same security)

- **Concept**
  - Partei A: Has **Pa (Public Key a)** and **Sa (Secret/Private Key a)**
  - Partei B: Has **Pb (Public Key b)** and **Sb (Secret/Private Key b)**
  - B gives A Pb
  - A encrypts Sa with Pb
  - A gives B encrypted Sa, B can decrypt it -> A can send secret messages to B
  - => established secure way to msg

- **`RSA`**
  - Uses Public and Private Keys
  - Basiert auf **Primfaktorzerlegung**
  - Big Primes = more secure
  - Public Key has 2 Parts: Exponent e und Modul n
    - e is known and *n* = product of *2 large primes*
  - Private Key: Exponent d which is calculated to encrypt
  - **Why safe?**
    - Hard to calculate the 2 primes of Modul **n**
    - BUT easy to decrypt if someone has the private key d

- **`Hybride Verschlüsselung`**
- **Why?**
  - Schlüsselaustausch symmetrisch ist org. aufwändig
  - asymmetrisch ist rechenaufwendig
- **Concept**
  - Generate Random Session Key Sk
  - Data is encrypted using Sk
  - Sk is encrypted using receivers Public Key
  - Receiver can decrypt Sk and with that Data

## `Integrität`
- Goal: Proof Message wasnt changed
- Lösung Hash **ABER** Kollisionsgefahr
- Relevant Hash Funktionen: SHA, SHA256, SHA512, MD5 (sadly)
- **How to proof with Hashes?**
  - Lösung **Signaturen**
  - Send msg, and Signature (= hash msg) encrypted to receiver
  - Receiver encrypts message, and Signatur -> hashes msg
  - Integrität bestätigt wenn **hash(msg) == Signatur**
- Use case (Password DB):
  - Passwords are safed as hashes
  - Salt (Zusatzwert pro Pw) added
  - Pepper (Globaler Zusatzwert) added
  - **Salt & Pepper increase security**

## `Authentizität`
- Goal: Proof Sender really is the Sender
- example irl == Perso (trusted store(Staat) == Perso is real)
- Solution: **Zertifikate**
- trusted store: **Root-CA**
- Signed cert or key (echtheit)

## `SSL / TLS`
- TLS is used **a LOT** HTTPS / OpenVPN / NTPS etc...
- Goals: 
  - Auth des Servers (und Clients)
  - Integrität der Datenübertragung
  - Trusted communication
- Idea:
  - Gen symmetrischen Key
  - Tausch ihn asymmetrisch aus
  - Kommunizier symmetrisch
- **TLS Handshake**
  - Schlüsselaustausch
  - Auth
    - [How To] (maybe still in Klausur)
    - (Client) Client Hello -> (Server) Server Hello | Keyaustausch etc
    - `Encrypted from now on`
    - (Server sends:) Server-Cert, (ggf) Client Cert Req, ServerHello Done
    - (Client sends:) (ggf) Client Cert, ClientHello Done + Daten
- **TLS Record**
  - Datenübertragung mit Vertraulichkeit, Integrität und Auth

- **Perfect Forward Secrecy**
  - Added in `TLS 1.3`
  - **Before:**
    - Session Key encrypted via Pub Key
    - Risk: Private Key loss = all pakets are readable
    - Heartbleed Attack
  - **After:**
    - Session Key secure via Key Transmition method
    - Private Key independant
    - 
- **Session Resumption**
- 0 Round Trips instead of 1
- Safes ~4% CPU time
- No Perfect Forward Secrecy (Recommended: reset Session every 24hrs)
  
- **`Improving TLS Security`**
  - TLS can fall victim to Man in the Middle attacks while generating RSA Export Key
  - Solution: **Paketanalyse durch NIDS** (Network Intrusion Detection System) **ABER** Pakete sind Verschlüsselt
    - Solution: Enterprise TLS
    - Local Server | NIDS | [PC1, PC2 ... PCn]
    - eTLS zu NIDS mit gleichem Key -> NIDS kann mitlesen, TLS zu PCs
    - `Pro & Con`
      - RIP Forward secrecy
      - Monitoring des Netzwerktraffics mögl
      - Datenschutz? Geheimschutz?

- **`Alt. HTTPS Proxy`**
- Same concept but uses Proxy Cert on Clients
- trustworthy
- Web-Server | (Internet) | Proxy | Local Network (Clients with Proxy Cert)
- Proxy TLS with Web-Server, Clients TLS with Proxy
- **Important:** **`Proxy can scan Pakets`**
- `Pro / Con`
  - Needs proxy abled protocol
  - Verschlüsselung hinfällig, wenn Proxy kompromittiert
  - Datenschutz? Geheimschutz?

- **`Heartbleed`**
- OpenSSL 1.0.1 bis 1.0.1f betroffen
- Attack on Heart-Beat-Function of TLS/SSL
- Could read **any** Data on Server (eg. SSL secret keys -> allowed to read old and new messages)
- Why did it work?
  - OpenSSL trusted the payload_length header which didnt have to be the true size
  - Example in Heartbeat message: Attacker set payload_length, like this "Server are you still there? If so, reply "Bing Chilling" (payload_length = 500) -> Server replies "Bing Chilling + [ 486 chars of SENSITIVE DATA]"