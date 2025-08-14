Mit Hilfe des Microsoft Azure Active Directory (AD) Target Connectors kannst du Microsoft Azure AD über die Identity & Access Management (IAM)-Lösung HelloID von Tools4ever mit deinen Quellsystemen verbinden. Diese Verbindung vereinfacht die Verwaltung von Zugriffsrechten und Benutzerkonten innerhalb deiner Organisation. Zudem sorgt die Integration für Konsistenz und verringert die Fehleranfälligkeit. In diesem Artikel erfährst du mehr über diese Verbindung und die Möglichkeiten.

## Was ist Microsoft Azure AD

Microsoft Azure AD, mittlerweile bekannt als [Microsoft Entra ID](https://www.tools4ever.nl/connectoren/entraid/), ist eine Identitäts- und Zugangsverwaltungslösung des US-amerikanischen Tech-Giganten Microsoft. Die Lösung unterstützt Organisationen dabei, Identitäten sicher zu halten und zu verwalten, sowohl für hybride als auch für Multi-Cloud-Umgebungen. Microsoft Azure AD ist vollständig cloudbasiert und gewährt Mitarbeitern Zugriff auf verschiedene externe Ressourcen. Beispiele hierfür sind Microsoft 365 und das Azure-Portal, ebenso wie ein breites Spektrum an SaaS-Anwendungen.

Warum ist eine Microsoft Azure AD-Verbindung sinnvoll?

Die Produktivitätssteigerung innerhalb deiner Organisation erfordert den Zugang zu den richtigen Diensten, Systemen und Ressourcen für Benutzer, die dafür Benutzerkonten und Autorisierungen benötigen. Über Microsoft Azure AD regelst du Berechtigungen durch Microsoft 365-Gruppen. So verwaltest du den Zugang zu den meisten Cloud-Services von Microsoft, wie etwa Microsoft Teams, SharePoint, Yammer und Power BI. Durch die Integration deiner Quellsysteme und Microsoft Azure AD automatisierst du diesen Prozess, sodass du dich darum nicht mehr kümmern musst. Der Microsoft Azure AD Connector ermöglicht eine Verbindung mit verschiedenen beliebten Quellsystemen, darunter:

* AFAS
* TOPdesk

Weitere Details zur Verbindung mit diesen Zielsystemen findest du weiter unten im Artikel.

## HelloID für Microsoft Azure AD hilft dir bei

**Fehlerfreiem Kontenmanagement**: Dank der Verbindung zwischen deinen Quellsystemen und Microsoft Azure AD arbeitest du konsistent und fehlerfrei. Die Integration sorgt dafür, dass Benutzer nie mehr Berechtigungen besitzen, als unbedingt notwendig, und dass sie immer über die erforderlichen Konten und Berechtigungen verfügen. Gleichzeitig stellst du sicher, dass Konten nach dem Ausscheiden eines Mitarbeiters rechtzeitig deaktiviert werden, um unautorisierten Zugang zu verhindern.

**Schnellerer Kontenerstellung**: Der Microsoft Azure AD Connector automatisiert deine Benutzerbereitstellung, was viel Zeitersparnis bedeutet. Erstellst du einen neuen Benutzer in einem Quellsystem, erkennt HelloID die Änderung und erstellt auf Wunsch in Azure AD ein Konto für den Benutzer, ohne dass manuelle Eingriffe erforderlich sind. So sind Benutzer schneller produktiv.

**Verbesserung des Serviceniveaus**: Die Verbindung deiner Quellsysteme und Microsoft Azure AD vermeidet Fehler und sorgt für Konsistenz. So hebst du das Serviceniveau auf ein höheres Level. Zum Beispiel, indem Benutzer immer über die Konten und Berechtigungen verfügen, die sie benötigen. Gleichzeitig vermeidest du vermeidbare Fehler, wie das zu frühe Entziehen von Berechtigungen oder die Zuweisung falscher Berechtigungen.

**Erfolgreiches Bestehen von Audits**: Alle Aktionen und Änderungen, die HelloID durchführt, werden von der IAM-Lösung in einem vollständigen Audit-Trail festgehalten. So kannst du jederzeit nachweisen, dass du die Kontrolle hast und behältst, und bist immer optimal auf Audits vorbereitet.

**Arbeiten mit einem hybriden Setup**: Die Verbindung unterstützt eine hybride Aufstellung, zum Beispiel, wenn du deine Postfächer in die Cloud migriert hast, aber noch mit einem lokal installierten Active Directory arbeitest. HelloID sorgt dafür, dass du in dieser hybriden Umgebung nahtlos arbeiten kannst. So kannst du unter anderem Benutzer in deine On-Premises-Active-Directory-Umgebung bereitstellen und dabei Berechtigungen für Cloud-Services zuweisen.

Die Sicherheit von Microsoft Azure AD-Konten verstärken: Mit Hilfe von Multi-Faktor-Authentifizierung (MFA) hebst du die Sicherheit der Microsoft Azure AD-Konten auf ein höheres Niveau. Aktivierst du MFA, melden sich Benutzer nicht nur mit einem Benutzernamen und Passwort an, sondern verifizieren ihre Identität auch über einen Code, den sie über eine Mobilnummer oder E-Mail-Adresse erhalten.

## Wie HelloID in Microsoft Azure AD integriert wird

HelloID ermöglicht es, Microsoft Azure AD mit Hilfe eines Connectors als Zielsystem mit deinen Quellsystemen zu verbinden. HelloID fungiert dabei als Vermittler, wobei die IAM-Lösung einen Übersetzungsprozess zwischen den Quellsystemen und Microsoft Azure AD durchführt. Notwendig, denn Systeme sprechen in der Regel nicht die gleiche Sprache. Mithilfe der Verbindung automatisierst du den Lebenszyklus von Konten und die Verwaltung von Berechtigungen in Microsoft Azure AD.

| **Änderung im Quellsystem** |  **Vorgang in Microsoft Azure AD** | 
| --------------------------- | --------------------------------- | 
| **Neuer Mitarbeiter** | HelloID erstellt auf Basis von Informationen aus deinen Quellsystemen für neue Mitarbeiter in Microsoft Azure AD die benötigten Konten. Die IAM-Lösung kann dabei alle Attribute eines Azure AD-Kontos verwalten. Die Verbindung nutzt dabei die Microsoft Graph API. Neue Konten sind standardmäßig nicht aktiv. Auf Wunsch kann HelloID das Konto automatisch aktivieren, sobald das Arbeitsverhältnis beginnt. |
| **Änderungen der Mitarbeiterdaten** |  Wenn sich Daten von Mitarbeitern in deinen Quellsystemen ändern, passt HelloID ihre Microsoft Azure AD-Konten entsprechend an. Zum Beispiel bei Änderungen eines Anzeigenamens oder Anmeldenamens. Die IAM-Lösung verwaltet die Konten auf Attributebene. | 
| **Funktionsänderung** |  Falls sich die Funktion eines Mitarbeiters ändert, kann dies andere Berechtigungen erfordern. HelloID passt die Berechtigungen in Microsoft Azure AD automatisch an Funktionsänderungen in deinen Quellsystemen an. Zum Beispiel kann ein Benutzer Mitglied einer Cloud-Gruppe werden, wodurch ihm Berechtigungen zugewiesen werden. Oder es werden Berechtigungen entzogen, wenn ein Benutzer nicht länger die dafür geltenden Voraussetzungen erfüllt. |
| **Ausscheiden eines Mitarbeiters** |  Wenn ein Mitarbeiter aus dem Unternehmen ausscheidet, möchtest du das Azure AD-Konto rechtzeitig deaktivieren. HelloID automatisiert diesen Prozess und vermeidet Fehler. Auf Wunsch entfernt HelloID das Konto auch nach einer gewissen Zeitspanne automatisch. |

Arbeiten mit dynamischen Berechtigungen spart dir viel Zeit. Dynamische Berechtigungen arbeiten in HelloID vollständig auf Basis von Quelldaten. So kannst du zum Beispiel alle Abteilungsgruppen auf Basis einer einzigen Business-Regel einrichten. HelloID kartiert dabei Korrelationen zwischen Quelldaten und den betreffenden Gruppen. Ein wichtiger Vorteil gegenüber regulären, nicht-dynamischen Berechtigungen ist, dass dynamische Berechtigungen automatisch mit der sich wandelnden Struktur deiner Organisation mitlaufen. Erstellst du beispielsweise in deinem HR-System eine neue Abteilung, erkennt HelloID dies und ordnet dank dynamischer Berechtigungen automatisch die richtigen Mitgliedschaften zu den relevanten Benutzern. Ein weiterer wichtiger Vorteil ist die Verfügbarkeit eines vollständigen Audit-Trails dieses Prozesses in HelloID.

HelloID setzt die Microsoft Graph API für den Datenaustausch zwischen deinen Quellsystemen und Microsoft Azure AD ein. Die Microsoft Graph API ist eine RESTful Web-API und gewährt Zugriff auf Ressourcen von Microsoft Cloud-Services. Um mit dieser API zu beginnen, muss dies innerhalb von Azure AD eingerichtet sowie an die richtigen Berechtigungen gekoppelt werden.

## Maßgeschneiderter Datenaustausch

Die Konfiguration deines Target Connectors bestimmt maßgeblich, wie HelloID Daten zwischen deinen Quellsystemen und Microsoft Azure AD austauscht. So kannst du die Funktionsweise maßgeblich auf deine Organisation abstimmen, wobei deine spezifischen Bedürfnisse im Mittelpunkt stehen. In Azure AD bestimmst du mit Hilfe von Berechtigungen genau, was HelloID tun darf und was nicht.

Für die Einrichtung des Connectors organisieren wir von Tools4ever stets eine Aufnahme- und Designsitzung. In einem Aufnahmedokument legen wir fest, wie du Azure AD-Konten erstellen möchtest. Wir spezifizieren auch auf Attributebene, was HelloID aktualisieren darf. Du bist selbst am Steuer und kannst diese Konfiguration jederzeit über das Dashboard der IAM-Lösung ändern.

Mit Hilfe eines Satzes strukturierter Geschäftsregeln gibt dir HelloID Kontrolle über die Berechtigungen eines Mitarbeiters. Wir entscheiden uns dabei bewusst für Geschäftsregeln anstelle einer Autorisierungsmatrix. Geschäftsregeln sind nicht nur flexibler und vielseitiger, du kannst diese auch über eine benutzerfreundliche Schnittstelle direkt aus HelloID verwalten.

## Microsoft Azure AD mit Quellsystemen über HelloID verbinden

HelloID kann verschiedene Quellsysteme mit deiner Microsoft Azure AD-Umgebung verbinden. Auf diese Weise kann HelloID auf Basis von Informationen aus deinen Quellsystemen vollständig automatisiert Änderungen in Microsoft Azure AD durchführen. Angenehm, da du so viel Zeit sparst und das Management von Benutzern und Berechtigungen auf ein höheres Niveau hebst. Beispiele für häufige Integrationen sind:

**AFAS - Microsoft Azure AD Verbindung**: Diese Verbindung nimmt dir dank Automatisierung viel Arbeit ab. Die Verbindung sorgt unter anderem dafür, dass die geschäftliche E-Mail nach der Bereitstellung des Microsoft Azure AD-Kontos automatisch an das Quellsystem zurückgemeldet wird. HelloID kann auf Wunsch auch Benutzer in AFAS verwalten. Denk dabei an das Aktivieren eines Benutzers in AFAS oder das rechtzeitige Sperren eines Kontos, sodass es nicht in die AFAS-Lizenzzählung einfließt. Ein weiteres Beispiel ist das Registrieren des UserPrincipalName (UPN)-Feldes für Single Sign-On (SSO).

**TOPdesk - Microsoft Azure AD Verbindung**: Diese Verbindung stellt sicher, dass TOPdesk und Microsoft Azure AD immer vollständig synchron sind im Hinblick auf SSO. Wichtig, denn mit SSO optimierst du die Benutzererfahrung und verstärkst die Sicherheit, da Benutzer sicher einloggen können. Gleichzeitig vereinfacht die Verbindung das Management von Benutzerkonten und Berechtigungen.

Für HelloID stehen 200 Connectoren zur Verfügung, mit denen du die IAM-Lösung an eine breite Palette von Quell- und Zielsystemen anschließen kannst. Dank dieser breiten Integrationsmöglichkeiten kannst du HR2day an alle gängigen Zielsysteme anbinden.