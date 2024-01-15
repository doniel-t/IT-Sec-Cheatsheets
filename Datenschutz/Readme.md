## Datenschutz
- `Datenschutz ist die base Regel`
- Wenn man Daten will muss man nach permission fragen 

## Anonymität
- **Mix Concept**
  - "Mix" (Server that recieves Messages) receives Messages from users and will be processed in random order
  - End receiver will get shuffled messages
  - End receiver wont know who the og sender was (because mix sent it)
  
- **JAP** Java Anonymous Proxy
  - Supports HTTP, HTTPS, FTP
  - Pakets will be made same size, and sent with a certain delay (JAP is Mix)

- **TOR** 
  - Uses Tor Network
  - Hides IP-Adresses (only knows, last and next Tor Server IP)
  - Wechselnde Routen
    - `Opposite to JAP`: Feste Mixkaskaden
    - `Pro:`
      - Weniger Bandbreite pro Router

- **Anonymous Remailer**
  - Same as above aber für SMTP (Mail)
  - Besonderheiten:
    - Received Header removed
    - Rückantwort-Adresse generiert