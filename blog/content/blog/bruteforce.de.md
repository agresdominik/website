---
title: "Bruteforce-Analyse"
draft: false
date: "2025-11-02"
description: "Einen Parser für meine fail2ban-Logs vom VPS schreiben und diese analysieren"
---

## Einleitung

Vor Kurzem habe ich diese Website als kleines Nebenprojekt aufgesetzt, um ein wenig HTML, CSS und den Umgang mit Static-Site-Generatoren zu lernen. Zum Hosten der Website nutze ich meinen VPS bei [IONOS](https://www.ionos.de/). Da ich viel Zeit in der Cybersecurity-Welt verbracht habe, habe ich mein Bestes gegeben, den VPS so gut wie möglich abzusichern. Der Login per SSH ist nur über Private-/Public-Key-Authentifizierung möglich und [Fail2Ban](https://github.com/fail2ban/fail2ban) ist so eingerichtet, dass jeder gebannt wird, der mehr als fünf Mal versucht, sich anzumelden. Nachdem das eingerichtet war, habe ich eine Möglichkeit geschaffen, die Logs von nginx und fail2ban auf meinen privaten Proxmox-Server zu „ziehen“ und diese in Grafana zu verarbeiten. Dabei ist mir aufgefallen, dass die fail2ban-Logdatei über 31.000 Zeilen hat. Nichts Verdächtiges für eine öffentliche IP-Adresse, aber dennoch eine interessante Menge an Daten.

Nachdem ich diese Dateien in die Hände bekommen hatte, beschloss ich, diese Bruteforce-Angriffe zu parsen und zu analysieren. Außerdem schreibe ich das Ganze in Go, weil ich meine Fähigkeiten darin verbessern möchte und es uns erlaubt, extrem effizienten, schnellen und leichtgewichtigen Code zu schreiben.

<!--more-->

## Daten

Der Datensatz (die Datei fail2ban.log) besteht aus relativ einfachen und verständlichen Logs. Hier ein Ausschnitt eines durchschnittlichen Log-Abschnitts:

```txt
// I will not be exposing the IP addresses for obvious reasons
2025-10-25 17:04:35,850 fail2ban.filter         [77278]: INFO    [sshd] Found xxx.xxx.xxx.xxx - 2025-10-25 17:04:35
2025-10-25 17:04:36,414 fail2ban.actions        [77278]: WARNING [sshd] xxx.xxx.xxx.xxx already banned
2025-10-25 17:04:37,099 fail2ban.filter         [77278]: INFO    [sshd] Found xxx.xxx.xxx.xxx - 2025-10-25 17:04:36
2025-10-25 17:04:40,100 fail2ban.filter         [77278]: INFO    [sshd] Found xxx.xxx.xxx.xxx - 2025-10-25 17:04:39
2025-10-25 17:04:40,420 fail2ban.actions        [77278]: NOTICE  [sshd] Ban xxx.xxx.xxx.xxx
```

Es gibt außerdem einige Fehlereinträge in der Logdatei, die nicht eindeutig gekennzeichnet sind. Sie sind zwar für die Datenanalyse nicht so wichtig, müssen aber beim Parsen berücksichtigt werden:

```txt
2025-10-25 17:04:40,426 fail2ban.utils          [77278]: ERROR   7f57b0136b10 -- exec: { iptables -w -C f2b-sshd -j RETURN >/dev/null 2>&1; } || { iptables -w -N f2b-sshd || true; iptables -w -A f2b-sshd -j RETURN; }
for proto in $(echo 'tcp' | sed 's/,/ /g'); do
{ iptables -w -C INPUT -p $proto -m multiport --dports 22  # or your custom SSH port -j f2b-sshd >/dev/null 2>&1; } || { iptables -w -I INPUT -p $proto -m multiport --dports 22  # or your custom SSH port -j f2b-sshd; }
done
```

## Implementierung

Das Folgende wird in drei Abschnitte unterteilt: Parsing, Datenerfassung und Visualisierung.

### Parsing & Regex

Ich habe entschieden, dass der einfachste Weg ist, die Logs in einer JSON-Datei zu speichern, mit einem Objekt für jeden Log-Eintrag. Das vereinfacht das Schreiben und Lesen derselben Datei in Zukunft. In Go machen wir das, indem wir ein Struct mit Tags dafür definieren, wie die JSON-Struktur später aussehen soll:

```go
type Logs struct {
	Timestamp string  `json:"timestamp"`
	Handler   string  `json:"handler"`
	Level     string  `json:"level"`
	Source    string  `json:"source"`
	IpAddress  string  `json:"ipAddress"`
	Message   string  `json:"message"`
}
```

Das sind die Key-Value-Felder, die wir mit den Informationen aus der Logdatei füllen wollen. Die Logdatei wird mit Gos `os`- und `bufio`-Paketen gelesen. Damit öffnen wir die Logdatei und übergeben sie an eine Scanner-Instanz. Der Scanner bietet uns dann eine Vielzahl von Funktionen für das Lesen der Datei.
Am einfachsten ist es, eine for-Schleife wie diese zu erstellen:

```go
for scanner.Scan() {

  line := scanner.Text()

  ...
}
```

Das stellt sicher, dass in jeder Iteration der Schleife die Variable `line` die nächste Zeile erhält, bis keine mehr verfügbar ist. `line` enthält nun eine Zeile aus der Logdatei.
Jetzt kommt das Parsing. Ich habe beschlossen, dass ich mich selbst hasse und dass ich reguläre Ausdrücke (Regex) verwende, um die üblichen Werte in den fail2ban-Logs zu finden und zu extrahieren. Dafür habe ich für jeden der oben genannten JSON-Tags einen regulären Ausdruck definiert, nämlich[^2]:

```go
// For (probably much) better efficiency these expressions can be grouped into one large expression with matching groups for each field.
// Because I do not like Regex, I will not do this.
dateRegex, _ := regexp.Compile(`\d{4}-\d{2}-\d{2}`)
handlerRegex, _ := regexp.Compile(`fail2ban\.\w+`)
ipRegex, _ := regexp.Compile(`(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}`)
levelRegex, _ := regexp.Compile(`\s*(?:[A-Z]+)\s+`)
serviceRegex, _ := regexp.Compile(`\s*(?:\[[a-z]+\])\s+`)
actionRegex, _ := regexp.Compile(`(Found|already banned|Ban|Unban)`)
```

Theoretisch sollte dieses Regelwerk, angewendet auf die Variable `line`, Werte wie diese extrahieren:

```text
2025-10-25 17:04:35,850 fail2ban.filter         [77278]: INFO    [sshd] Found xxx.xxx.xxx.xxx - 2025-10-25 17:04:35
[       dateRegex      ][ handlerRegex ]         [levelRegex][serviceRegex][actionRegex][ipRegex]
```

Und sie damit in ein sauberes JSON exportieren:

```json
...
{
   "timestamp": "2025-10-25 17:04:35,850",
   "handler": "fail2ban.filter",
   "level": "INFO",
   "source": "[sshd]",
   "ipAddress": "xxx.xxx.xxx.xxx",
   "message": "Found"
}
...
```

Während ich meinen Code geschrieben, umgeschrieben und korrigiert habe, hatte ich auch die Performance im Blick. Ich habe meinen Parser-Funktionsaufruf zwischen zwei `time.Now().UnixMilli()` gepackt, um zu berechnen, wie lange das Parsen der 31.456 Zeilen dauern würde. Mein bestes Ergebnis lag um die `580 ms`, was bedeutet, dass mein Code ca. 55.000 Zeilen pro Sekunde parsen kann, oder – da die Datei 3,6 MB groß ist – ca. 6,2 MB pro Sekunde in einem Stream. (Deine Ergebnisse können je nach Festplatte, Single-Core-CPU-Leistung usw. variieren.)

Und da haben wir es, ich habe einen sehr einfachen fail2ban-Log-zu-JSON-Parser geschrieben. Ab jetzt wird es einfacher (und performanter).

### Analyse

Um die gesammelten Daten zu analysieren, lese ich unsere JSON-Datei mit allen Logs und erstelle eine neue Datei, die die verschiedenen Log-Nachrichten nach IP-Adresse aggregiert. Das bedeutet, wir erstellen ein neues Struct, das so aussieht:

```go
type StatsByIp struct {
	IpAddress      string  `json:"ipAddress"`
	TotalLogs      int     `json:"totalLogs"`
	TotalFound     int     `json:"totalFound"`
	TotalBanned    int     `json:"totalBanned"`
	TotalUnbanned  int     `json:"totalUnbanned"`
	Country        string  `json:"county"`
}
```
_Hinweis: Wenn du jemals Gos `encoding/json` verwendest, um das Marshalling und Unmarshalling der JSON-Dateien selbst zu übernehmen, beachte, dass du deine Variablen mit Großbuchstaben benennen **musst**. Go verwendet Groß-/Kleinschreibung, um zu unterscheiden, ob deine Variable oder Funktion öffentlich oder privat ist. Nur das Struct mit Großbuchstaben zu benennen reicht nicht aus, und wenn du das nicht tust, funktionieren die eingebauten Funktionen `json.Marshal()` und `json.Unmarshal()` nicht – ebenso wie einige andere Eigenheiten, wenn du externe Funktionen und Pointer verwendest._

Sobald diese Werte nach IP-Adresse aggregiert wurden, können wir sehen, wie oft sich welche IP erfolglos auf unserem SSH-Server authentifizieren wollte und wie oft sie gebannt und entbannt wurde.

Für zusätzliche Informationen habe ich ein einfaches Skript implementiert, das das Herkunftsland der IP-Adresse abfragt. Das geht leicht mit öffentlichen APIs wie [ipadress.com](https://www.ipaddress.com/apis/ip-to-country-api). Auch wenn das eine schöne Information ist, ist sie nicht zu 100 % korrekt, da sich IP-Adressen ändern und sie am Tag der Abfrage nicht demselben Nutzer gehören muss wie vor 10 oder mehr Tagen, als das Log sie erfasst hat.[^3]

### Visualisierung

#### Statisch

Ich bin ein großer Fan von Data Science und habe die meiste Zeit meiner „Software“-Entwicklung Python verwendet. Das erste Tool, das einem beim Visualisieren von Daten in den Sinn kommt, ist Pythons matplotlib. Ich habe es in allen Data-Science-nahen Projekten verwendet, bis hin zu meiner Bachelorarbeit. Daher war ich froh, herauszufinden, dass es für Go ein ähnliches Paket gibt. Dafür habe ich [gonum/plot](https://github.com/gonum/plot) verwendet. Damit habe ich eine einfache Wrapper-Funktion zum Erstellen von Balkendiagrammen geschrieben und alle relevanten Daten aus unseren Analyseschritten gesammelt. Die meisten einzelnen IPs kommen aus China mit insgesamt 180 individuellen IP-Adressen. Wenn man sich die meisten Bans ansieht, sieht das Diagramm so aus:

![Diagramm der Bans nach Land](/blog/bruteforce/Ban_by_country.png)

Interessanterweise führen die IPs aus den Niederlanden das Rennen an, wenn es darum geht, sich mit meinem VPS zu verbinden und zu authentifizieren.

#### Dynamisch

Ein paar Tage später habe ich mir das angesehen und beschlossen, dass ich es in ein Dashboard integrieren und meine Daten live anzeigen lassen möchte. Dazu habe ich die Parsing-Funktion so umgeschrieben, dass sie das zuletzt gelesene Byte in der Logdatei verfolgt. Jetzt kann ich das Synchronisieren der Logs von meinem VPS und das Ausführen meines Log-Parsers in einem LXC-Container automatisieren, in dem ich Grafana bereitgestellt habe. Über Grafana habe ich JSON-Dateien als Datenquelle eingerichtet (ich musste außerdem einen einfachen Python-HTTP-Server aufsetzen, um das geparste JSON über eine REST-API bereitzustellen) und begonnen, ein Dashboard zu erstellen.

![Fertiges Grafana-Dashboard](/blog/bruteforce/grafana_fail2ban.png)

Alles in allem ein interessantes kurzes Projekt. Eines Tages werde ich mir selbst die Herausforderung stellen, den Code so weit wie möglich zu optimieren.

## Post Scriptum

Keine Texte, Bilder, Codes, Konzepte oder Ideen wurden mit Slop-Generatoren[^1] erstellt. Auch wenn ich nicht glaube, dass Slop-Generatoren grundsätzlich schlecht sind, noch dass man sie nicht produktiv einsetzen kann (wie ich es in manchen Fällen tue), sind alle Dinge, die ich hier schreibe, Dinge, die mich wirklich interessieren und die ich selbst erstellen und bearbeiten möchte. Ich glaube, ein Mensch kann nur besser in dem werden, was er tut, wenn er nicht ständig nach sofortiger Befriedigung sucht, die einem bei der Verwendung von Slop-Generatoren oft gegeben wird.

[^1]: [Slop-Generatoren](https://asahilinux.org/docs/project/policies/slop/)
[^2]: [Danke an ihateregex.io](https://ihateregex.io/expr/ip/)
[^3]: [DSGVO: Erwägungsgrund 49 erkennt Netz- und Informationssicherheit ausdrücklich als berechtigtes Interesse an.](https://eur-lex.europa.eu/eli/reg/2016/679/oj#rct_49)
