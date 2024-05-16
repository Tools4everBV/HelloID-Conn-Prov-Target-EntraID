Met behulp van de Microsoft Azure Active Directory (AD) Target Connector koppel je Microsoft Azure AD via de Identity & Access Management (IAM)-oplossing HelloID van Tools4ever aan je bronsystemen. De koppeling vereenvoudigt het beheer van toegangsrechten en gebruikersaccounts binnen je organisatie. Ook zorgt de integratie voor consistentie en vermindert de foutgevoeligheid. In dit artikel lees je meer over deze koppeling en de mogelijkheden. 

## Wat is Microsoft Azure AD

Microsoft Azure AD - inmiddels beschikbaar onder de naam Microsoft Entra ID - is een oplossing voor identiteits- en toegangsbeheer van de Amerikaanse techgigant Microsoft. De oplossing ondersteunt organisaties met het veilig houden en beheren van identiteiten, zowel voor hybride als multicloud-omgevingen. Microsoft Azure AD is volledig cloudgebaseerd en geeft werknemers toegang tot diverse externe resources. Voorbeelden zijn Microsoft 365 en Azure Portal, maar ook een breed scala aan SaaS-toepassingen.

Waarom is een Microsoft Azure AD koppeling handig?

Het optimaliseren van de productiviteit binnen je organisatie vraagt om de toegang tot de juiste diensten, systemen en middelen voor gebruikers, die hiervoor gebruikersaccounts en autorisaties nodig hebben. Via de Microsoft Azure AD regel je permissies in via onder meer Microsoft 365 groepen. Je beheert zo de toegang tot de meeste cloud services van Microsoft, zoals Microsoft Teams, SharePoint, Yammer en Power BI. Dankzij de integratie van je bronsystemen en Microsoft Azure AD automatiseer je dit proces, waardoor jij hiernaar geen omkijken hebt. De Microsoft Azure AD connector maakt een koppeling mogelijk met diverse populaire bronsystemen, waaronder:

* AFAS
* TOPdesk

Verdere details over de koppeling met deze doelsystemen zijn te vinden verderop in het artikel.

## HelloID voor Microsoft Azure AD helpt je met

**Foutloos accountbeheer**: Dankzij de koppeling tussen je bronsystemen en Microsoft Azure AD stel je zeker dat je consistent en foutloos werkt. Zo zorgt de integratie dat gebruikers nooit over meer autorisaties beschikken dan strikt noodzakelijk, en gebruikers altijd over de accounts en autorisaties beschikken die zij nodig hebben. Tegelijkertijd weet je zeker dat je accounts na het vertrek van een medewerker tijdig deactiveert om ongeautoriseerde toegang te voorkomen. 

**Accounts sneller aanmaken**: De Microsoft Azure AD connector automatiseert je user provisioning, wat veel tijdwinst oplevert. Maak je een nieuwe gebruiker aan in een bronsysteem? Dan detecteert HelloID deze wijziging en maakt desgewenst in Azure AD een account aan voor de gebruiker, zonder dat dit handmatige handelingen vereist. Zo zijn gebruikers sneller productief.

**Serviceniveau verbeteren**: De koppeling van je bronsystemen en Microsoft Azure AD voorkomt fouten en zorgt voor consistentie. Zo til je het serviceniveau naar een hoger niveau. Onder meer doordat gebruikers altijd over de accounts en autorisaties beschikken die zij nodig hebben. Tegelijkertijd voorkom je vermijdbare fouten, zoals het (te vroeg) intrekken van autorisaties of het toekennen van verkeerde autorisaties. 

**Het succesvol doorlopen van audits**: Alle acties en mutaties die HelloID uitvoert legt de IAM-oplossing vast in een volledige audittrail. Zo kan je te allen tijde aantonen dat je in control bent en blijft, en ben je altijd optimaal voorbereid op audits.

**Het werken met een hybride opzet**: De koppeling ondersteunt een hybride opstelling, bijvoorbeeld indien je je mailboxen naar de cloud hebt gemigreerd maar nog wel werkt met een on-premises Active Directory. HelloID zorgt dat je in deze hybride omgeving naadloos kunt werken. Zo kan je onder meer users provisioneren naar je on-premises Active Directory-omgeving, en daarbij permissies voor cloudservices toekennen aan gebruikers.

Het versterken van de beveiliging van Microsoft Azure AD-accounts: Met behulp van multi-factor authentificatie (MFA) til je de beveiliging van Microsoft Azure AD-accounts naar een hoger niveau. Indien je MFA inschakelt loggen gebruikers niet alleen met een gebruikersnaam en wachtwoord in, maar verifiëren hun identiteit ook via een code die zij via een mobiel telefoonnummer of e-mailadres ontvangen.

## Hoe HelloID integreert met Microsoft Azure AD
HelloID maakt het mogelijk Microsoft Azure AD met behulp van een connector als doelsysteem te koppelen aan je bronsystemen. HelloID doet daarbij dienst als tussenpersoon, waarbij de IAM-oplossing een vertaalslag maakt tussen de bronsystemen en Microsoft Azure AD. Noodzakelijk, want systemen spreken doorgaans elkaars taal niet. Met behulp van de koppeling automatiseer je de levenscyclus van accounts en het beheer van permissies in Microsoft Azure AD.

| **Wijziging in bronsysteem** | 	**Procedure in Microsoft Azure AD**| 
----------------------------| ------------------------------| 
| **Nieuwe medewerker**|HelloID maakt op basis van informatie uit je bronsystemen voor nieuwe medewerkers in Microsoft Azure AD de benodigde accounts aan. De IAM-oplossing kan daarbij alle attributen van een Azure AD-account beheren. De koppeling maakt daarbij gebruik van de Microsoft Graph API. Nieuwe accounts zijn standaard niet actief. Desgewenst kan HelloID zodra het dienstverband van start gaat het account automatisch activeren.|
| **Gegevens van medewerker wijzigen** |	Indien gegevens van medewerkers in je bronsystemen veranderen, past HelloID hun Microsoft Azure AD-accounts hierop aan. Denk daarbij aan het wijzigen van een weergave- of inlognaam. De IAM-oplossing beheert de accounts op attribuutniveau.| 
| **Functiewijziging** |	Indien de functie van een medewerker wijzigt, kan dit om andere autorisaties vragen. HelloID past de permissies in Microsoft Azure AD automatisch aan op functiewijzigingen in je bronsystemen. Denk daarbij aan een gebruiker lid maken van een cloudgroep, waardoor deze permissies toegekend krijgt. Of juist aan het intrekken van permissies indien een gebruiker niet langer aan de daarvoor geldende voorwaarden voldoet.|
| **Medewerker treedt uit dienst** |	Indien een medewerker uit dienst treedt wil je het Azure AD-account tijdig deactiveren. HelloID automatiseert dit proces en voorkomt fouten. Desgewenst verwijdert HelloID na verloop van tijd ook automatisch het account.| 


Werken met dynamische permissies bespaart je veel tijd. Dynamische permissies werken in HelloID volledig op basis van brondata. Zo kan je bijvoorbeeld alle afdelingsgroepen op basis van één business rule inregelen. HelloID brengt daarbij correlaties in kaart tussen brongegevens en de desbetreffende groepen. Een belangrijk voordeel ten opzichte van reguliere niet-dynamische permissies is dat dynamische persmissies automatisch meewegen met de veranderende structuur van jouw organisatie. Creëer je in je HR-systeem bijvoorbeeld een nieuwe afdeling? Dan herkent HelloID dit en kent dankzij dynamische permissies automatisch de juiste lidmaatschappen toe aan relevante gebruikers. Een belangrijk ander voordeel is de beschikbaarheid van een volledige audittrail van dit proces in HelloID.

HelloID zet de Microsoft Graph API in voor de uitwisseling van data tussen je bronsystemen en Microsoft Azure AD. De Microsoft Graph API is een RESTful web API en geeft toegang tot Microsoft Cloud service resources. Om aan de slag te gaan met deze API moet je dit inregelen binnen Azure AD, en daarnaast koppelen aan de juiste permissies.

## Gegevensuitwisseling op maat 
De inrichting van je target connector bepaalt in belangrijke mate de manier waarop HelloID gegevens uitwisselt tussen je bronsystemen en Microsoft Azure AD. Zo kan je de werking in belangrijke mate afstemmen op jouw organisatie, waarbij jouw specifieke behoeften centraal staan. In Azure AD bepaal je met behulp van permissies exact wat HelloID wel en niet mag doen.

Voor de inrichting van de connector organiseren we vanuit Tools4ever altijd een intake- en designsessie. In een intakedocument leggen we vast hoe je Azure AD-accounts wilt aanmaken. Ook specificeren we op attribuutniveau wat HelloID mag bijwerken. Je staat zelf aan de knoppen en kunt deze configuratie altijd via het dashboard van de IAM-oplossing zelf wijzigen. 

Met behulp van een set gestructureerde business rules geeft HelloID je grip op de autorisaties van een medewerker. We kiezen daarbij bewust voor business rules in plaats van een autorisatiematrix. Niet alleen zijn business rules flexibeler en veelzijdiger, ook kan je deze via een gebruiksvriendelijke interface direct vanuit HelloID beheren. 

## Microsoft Azure AD via HelloID koppelen met bronsystemen
HelloID kan diverse bronsystemen aan je Microsoft Azure AD-omgeving koppelen. Op deze manier kan HelloID op basis van informatie uit je bronsystemen volledig geautomatiseerd mutaties doorvoeren in Microsoft Azure AD. Prettig, want je bespaart zo veel tijd en tilt daarnaast het beheer van gebruikers en autorisaties naar een hoger niveau. Voorbeelden van veelvoorkomende integraties zijn: 

**AFAS - Microsoft Azure AD koppeling**: Deze koppeling neemt je dankzij automatisering veel werk uit handen. Zo zorgt de koppeling onder meer dat zakelijke e-mail na het provisioneren van het Microsoft Azure AD-account automatisch wordt teruggekoppeld naar het bronsysteem. HelloID kan desgewenst ook gebruikers in AFAS voor je beheren. Denk daarbij aan het activeren van een gebruiker in AFAS, of juist het tijdig blokkeren van een account zodat deze niet meetelt in de licenties voor AFAS. Een ander voorbeeld is het registreren van het userPrincipalName (UPN)-veld voor single sign-on (SSO).

**TOPdesk - Microsoft Azure AD koppeling**: Deze koppeling zorgt dat TOPdesk en Microsoft Azure AD altijd volledig in sync zijn met het oog op SSO. Belangrijk, want met SSO stroomlijn je de gebruikerservaring en versterk je daarnaast de beveiliging doordat gebruikers veilig kunnen inloggen. De koppeling vereenvoudigt tegelijkertijd het beheer van gebruikersaccounts en autorisaties.

Voor HelloID zijn 200 connectoren beschikbaar, waarmee je de IAM-oplossing aan een breed scala aan bron- en doelsystemen kunt koppelen. Dankzij deze brede integratiemogelijkheden kan je HR2day dan ook koppelen aan alle populaire doelsystemen.
