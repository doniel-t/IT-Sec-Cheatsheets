## **Kryptanalyse**:
- Monogramme: Zählen wo welcher Buchstabe am Häufigsten ist z.B. Allg: E>N>I>S>R 
    - -> Häufigkeit wird benutzt um Keys der Verschlüsselung rauszufinden
- Bigramme: 2 Buchstaben die aufeinander folgen
    -> Use info to crack Keys
- Trigramme: 3 Buchstaben
- Bruteforce



##  **Symmetrische Kryptographie:**
- ``Pro``
  - Schnell | Hardware-Unterstützung mögl
  - Moderne Verfahren sind sehr sicher
- ``Con``
  - **Schlüsselübertragung**


### **Monoalphabetische Verfahren:**
- `Cäsar, ROT13`
- IMPROVEMENT
  - turn similiar looking symbols into same (eg. I, l wird zu X)
  - remove ["," | "." | ":"] and remove world length (eg. split word at randon length)
- XOR: (A XOR B) XOR B = A  (B is the key)
  - Problem: 1 <= B <= 255 -> Simple Bruteforce
    
### **Polyaphabetische Kryptographie:**
- **Vignere Verschlüsselung:**
    - [How To]:
        - Build Table where each row is shifted by 1 letter of alphabet
        - Have Key (phrase) and Text to Encrypt, repeat key until its as long as text
        - map Letter of Text to Letter of Key and look it up at the table at table[clearTextLetter][keyPhraseLetter] -> encryped letter
    - **[Pro / Con]**:
      - Len Key is important
      - Len(K) >> Len(Text) machts anfällig für Bi-Trigramme

### **Stromchiffren**: == Byte-weise verschlüsseln
- **RC4**:
    - S-Box mit 256 Values, initialized with Key
    - crypt(Eingabe[i]) = Eingabe[i] XOR S[i]
    - SBox wird Pseudo-Randomized each step
    => Gleicher Pseudo-Random String bei Sender, Receiver
    
    **[RISKS]**:
    - Known key = broken
    - Same key for long time = ez to break
    - Solution: Hash key with random val 

### **Blockchiffren**:
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

- **DES: Data Encryption Standard (USA, 1977)**
    - Schlüssellänge DES: 64 Bit is split into 56 Bit (chosen by User) + 8 Bit parity
    - Multiple Step encryption: [Permutation, halbieren, (multiple times), add all split parts (xor), permutations -> done ]

- **IDEA: ETH Zürich (1990)**
    - 128 Bit Key mit 64 Bit Blocks
    - 8 Splits + 1-2 Ausgaberunden
    - Komplexe Key gen

- **AES: Advanced Encryption Standard**
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


## Schlüsselübertragung
- **Diffie-Hellmann**
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


## Asymmetrische Kryptographie
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

- **RSA**
  - Uses Public and Private Keys
  - Basiert auf **Primfaktorzerlegung**
  - Big Primes = more secure
  - Public Key has 2 Parts: Exponent e und Modul n
    - e is known and *n* = product of *2 large primes*
  - Private Key: Exponent d which is calculated to encrypt
  - **Why safe?**
    - Hard to calculate the 2 primes of Modul **n**
    - BUT easy to decrypt if someone has the private key d