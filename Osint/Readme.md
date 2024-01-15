## OSINT
- Process to find out sensitive information with openly available info (eg Social Engineering)

### `Social Engineering`
- Geburtstage etc rausfinden um passwörter "zu eraten"
  - **REASON:** Meisten Passwörter sind schlecht / Standart Passwörter

### `FIDO`
- FIDO Alliance > 250 Mitglieder (Amazon, Google, Leonovo, PayPal etc)
- **GOALS:**
  - Replace Passwords with new auth methods
  - safe web auth
- **VARIANTS:**
  - UAF: Universtal Auth Framework
  - U2F: Universal Second Factor
  - CTAP: Cleint Auth Protocol
    - Improved with WebAuthn (W3c) -> FIDO2
  - **FIDO2:**
    - passwordless auth
    - 2/ Multifaktor auth mit:
      - externen auth (Token)
      - biometric auth (fingerprint)
      - shared secrets (Passwords / PIN)
      - RFID, NFC, BLE und Bluetooth
 
- Why not auth like SSH?
  - You know every sever you want to connect via SSH (you dont for web)
  - Server kennt PubKey des Clients (Web: Server - Client dont know eachother)
  - Web: Many Services / Many ServiceProviders | SSH: Bekannter Service