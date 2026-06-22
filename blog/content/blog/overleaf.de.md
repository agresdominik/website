---
title: "LaTeX für Anfänger"
date: "2026-06-22"
description: "Hoste deine eigene Overleaf-Instanz"
---

## Einleitung

Vor ein paar Monaten habe ich mein Masterstudium in Medizinischer Informatik an der Universität Heidelberg und der Hochschule Heilbronn begonnen. Eine der allerersten Aufgaben ist das Schreiben eines Systematic Reviews zu einem vorgegebenen Special Issue, das wir natürlich als Gruppe schreiben.[^ai]

<!--more-->

## LaTeX & co.

Nahezu jede ernst zu nehmende wissenschaftliche Arbeit wird heutzutage in LaTeX geschrieben, mit ein paar Ausnahmen[^*]. Falls du noch nie damit zu tun hattest: LaTeX ist einfach eine Sprache wie jede andere. Es definiert ein Regelwerk und eine Syntax, an die du dich hältst, um eine erwartete Ausgabe zu erhalten, in diesem Fall eine saubere `pdf`.

Es gibt zwei Wege, es zu nutzen. So, wie es gedacht war: lokal, auf dem eigenen Rechner, indem man alles selbst kompiliert. Oder der andere Weg: über eine aufgeblähte, teils kostenpflichtige Webanwendung. Und doch ist genau diese Webanwendung, Overleaf, die Art und Weise, wie die meisten Menschen es nutzen, und das aus gutem Grund. Sie bietet Zusammenarbeit in Echtzeit, verständliche Fehlermeldungen, eine zugängliche Dokumentation und ein Dutzend weiterer Annehmlichkeiten. Man sagt gerne, dass *Linux nur dann kostenlos ist, wenn man seine Zeit nicht wertschätzt*, und derselbe Witz gilt für handgemachtes, blankes LaTeX auf der Kommandozeile im Vergleich zu Overleaf. Overleaf ist schlicht einfacher.

## Was jetzt?

Universitätsprojekte sind selten Einzelarbeit, was bedeutet, dass man mit Menschen zusammenarbeitet, die aus unterschiedlichen Hintergründen kommen und unterschiedliche Prioritäten haben. Ich komme aus dem Software Engineering, genauer gesagt aus der Softwareentwicklung, und lebe daher tendenziell in einer bestimmten Blase. Zum Kontext: Ich nutze täglich ein MacBook M1 mit Linux, ermöglicht durch ein kleines Team, das Apples Treiber zurückentwickelt, in einem Projekt, das offiziell noch in der Alpha-Phase ist[^1]. Die meisten Menschen wollen, ganz nachvollziehbar, einfach den bequemsten Weg zu einem fertigen Dokument, also haben wir uns darauf geeinigt, Overleaf für unsere Arbeit zu nutzen.

Es gibt allerdings einen Haken. Zusammenarbeit in Echtzeit erfordert bei Overleaf ein kostenpflichtiges Abo. Ohne dieses muss jeder das Dokument nacheinander statt gleichzeitig bearbeiten, und das war für uns von vornherein keine Option. Wie die meisten Studierendengruppen erledigen wir den Großteil der Arbeit in den letzten zwei Tagen vor der Deadline, alle auf einmal, also genau dann, wenn mehrere Personen gleichzeitig dieselbe Datei bearbeiten müssen. Ein Abo zu kaufen hätte das gelöst, aber es fühlte sich unnötig an, wenn es kostenlose Alternativen gibt. Die erste, die mir in den Sinn kam, war, Git als VCS zu verwenden und die `.tex`-Dateien auf GitHub zu hosten.

Das bringt allerdings seine eigenen Reibungspunkte mit sich. Nicht jeder arbeitet täglich mit Git über `add`, `commit` und `push` hinaus. (Ich habe selbst erst kürzlich herausgefunden, dass man alte Commits ziemlich bequem umbenennen kann, neben anderen Dingen.) Git entfaltet sein Potenzial außerdem erst dann richtig, wenn sich alle an dieselben Konventionen halten, und eine Handvoll Studierender, die zusammen eine Arbeit schreiben, ist nun einmal ein anderes Umfeld als ein Team von Entwicklern, die den ganzen Tag in Git leben. Keines ist besser oder schlechter, es sind einfach unterschiedliche Kontexte.

Also, was jetzt? Die Antwort war am Ende wunderbar einfach:

Overleaf.

Vor ein paar Tagen habe ich erfahren, dass man die Overleaf Community Edition selbst hosten kann. Sie hat denselben Funktionsumfang wie die gehostete kostenlose Version, jedoch ohne die künstlichen Beschränkungen wie die Obergrenze gleichzeitiger Bearbeiter und die Timeouts beim Kompilieren größerer Dokumente.

## Zurück zu FOSS

Das Aufsetzen von Overleaf CE hat mich auf einem VPS, den ich noch herumliegen hatte, insgesamt etwa 20 Minuten gekostet. Overleaf liefert einen vereinfachten Wrapper namens [Toolkit](https://docs.overleaf.com/on-premises/configuration/overleaf-toolkit) mit. Nachdem man fünf oder sechs Umgebungsvariablen gesetzt hat, führt man einen einzigen Befehl aus, der eigentlich nur ein Bootstrapper für `docker compose` ist, und schon läuft die Instanz. Wenn du eine Domain besitzt und einen Schritt weiter gehen möchtest, verschafft dir eine minimale Nginx-Reverse-Proxy-Konfiguration plus ein einziger Let's-Encrypt-Befehl eine ordentliche Domain mit TLS.

Das war's. Kein Abo, keine Begrenzung der Bearbeiter, keine Timeouts, und jeder im Team bekommt die vertraute Overleaf-Oberfläche, die er ohnehin schon kennt.

## Abschließende Gedanken

Falls du jemals in einem Team landest, das gemeinsam LaTeX schreiben muss, und du den Git-Weg lieber nicht gehen willst, hoste deine eigene Overleaf-Instanz. Es geht schnell, es ist kostenlos, und es lässt alle auf vertrautem Boden arbeiten.

Eine letzte Sache: Sichere, was auch immer du hostest. In einem gemeinsamen LaTeX-Projekt steckt viel gemeinsame Arbeit, und es ein paar Tage vor der Deadline zu verlieren, macht niemandem Spaß. Deshalb gilt: immer Backups machen.

[^ai]: Dieser Beitrag wurde von einer KI aus dem [englischen Original]({{< relref path="/blog/overleaf.md" lang="en" >}}) übersetzt.
[^*]: Alternativen: Typst, Word
[^1]: [Asahi Linux: Linux auf Apple Silicon, offiziell noch in der Alpha-Phase](https://asahilinux.org/)
