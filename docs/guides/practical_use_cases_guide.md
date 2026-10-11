# Praktijkgids & Use-Case Handleiding: IT Risk, Red Teaming & AI Probing
**Doelgroep:** Head of IT Risk Management, CISO, Security Officers & IT Risk Auditors  
**Omgeving:** Hetzner Cloud Linux VPS & OpenClaw Autonomous Engine  
**Frameworks:** DORA (Articles 26 & 27), TIBER-EU, NIST SP 800-115, OWASP Top 10 for LLMs, MITRE ATT&CK / ATLAS  

---

## 1. Executive Context: Waarom deze tooling in jouw dagelijkse praktijk?

In een enterprise IT-landschap (zoals Life & Pensions en verzekeraars) staat de tweede lijn (IT Risk) traditioneel voor een uitdaging: **je bent afhankelijk van wat de eerste lijn of externe consultants rapporteren.**

Met dit custom **IT Risk & Red Teaming Engine** framework verschuift IT Risk van passief toetsen naar **onafhankelijke, geautomatiseerde en proactieve risicovalidatie**. Je hoeft niet te wachten op een jaarlijkse pentest van €50.000; je toetst continu, non-destructief en direct binnen de kaders van wet- en regelgeving.

### Belangrijkste compliance-drijvers:
1. **DORA (Digital Operational Resilience Act - Art. 26 & 27):**  
   DORA verplicht financiële entiteiten tot periodieke *Threat-Led Penetration Testing* (TLPT) en continue evaluatie van ICT-risico's. Deze engine automatiseert de pre-engagement scoping, veilige uitvoering en deconflictie met het SOC.
2. **TIBER-EU:**  
   Het framework dwingt strikte *Rules of Engagement* (RoE), scope-grenzen en een onmiddellijke noodstop (*Kill Switch*) af. Dit zit hard gecodeerd in de kern van de engine.
3. **Generative AI & LLM Governance (OWASP LLM Top 10 & EU AI Act):**  
   Wanneer business units interne chatbots, agents of API's van derden introduceren, ontbreekt vaak inzicht in *Prompt Injection* (LLM01), *Data/System Prompt Leakage* (LLM06) en *Excessive Agency* (LLM08). Deze tooling voert geautomatiseerde stresstests uit op deze endpoints.

---

## 2. De Kracht van de Hetzner + OpenClaw Omgeving

Waarom is de combinatie van een **Hetzner Cloud VPS** (`ubuntu-4gb-nbg1-1`) en de **OpenClaw-architectuur** zo effectief?

* **Data Soevereiniteit & Compliance:** De Hetzner server draait in Neurenberg (Duitsland / EU). Alle scanlogs, auditbestanden en geëvalueerde data blijven strikt binnen de EU-jurisdictie en verlaten de server nooit.
* **Geen Vendor Lock-in of Torenhoge SaaS-kosten:** Traditionele Enterprise EASM (External Attack Surface Management) en AI-red teaming tools kosten tienduizenden euro's per jaar. Deze opzet draait op een dedicated cloud node met 100% eigenaarschap en flexibiliteit.
* **Autonome Orchestratie via OpenClaw:** OpenClaw fungeert als intelligente scheduler en assistent. Via heartbeats en automations kan de engine wekelijks buiten kantooruren non-destructieve scans draaien, logs analyseren en automatisch een management-ready rapport klaarzetten.
* **Ingebouwde Hetzner AUP-Veiligheid:** Dankzij de strikte `ScopeManager` (met DNS-verificatie) scant de server uitsluitend vooraf geautoriseerde assets. Hierdoor wordt het *Acceptable Use Policy* van Hetzner nooit geschonden.

---

## 3. Vier Concrete Praktijk Use-Cases

### Use-Case 1: DORA TLPT Pre-Assessment & Scope Validatie
* **Situatie:** Over drie maanden start een formeel TIBER-EU/DORA red teaming traject met een externe toezichthouder of extern team.
* **Toepassing:** Je definieert `scope.yaml` voor de externe assets. De engine scant de perimeter op open poorten en ontbrekende webheaders (HSTS, CSP, Clickjacking). 
* **Waarde voor Peter:** De IT-organisatie lost basale hygiëne-bevindingen op *vóórdat* het officiële onderzoek start, waardoor het externe team zich moet richten op geavanceerde TTP's in plaats van triviale configuratiefouten.

### Use-Case 2: Vendor AI & Interne GenAI Gatekeeper Audit
* **Situatie:** Een softwareleverancier levert een nieuwe klantenservice-chatbot of claimbeoordelings-agent op basis van OpenAI of Azure AI.
* **Toepassing:** Voordat het model groen licht krijgt voor productie, draai je `LLMRedTeamModule`. De engine vuurt geautomatiseerde OWASP testvectoren af (zowel single-turn injecties als sneaky multi-turn conversational priming) om te verifiëren of het systeem zijn interne instructies lekt of beheerdersrechten toekent.
* **Waarde voor Peter:** Je levert een onafhankelijk IT Risk rapport op met CVSS-scores en concrete bewijslast over de robuustheid van de AI guardrails.

### Use-Case 3: Onweerlegbare Audit Trails & SOC Deconflictie
* **Situatie:** Tijdens een assessment signaleert het Security Operations Center (SOC) ongebruikelijke probes en escaleert dit als een mogelijk security incident.
* **Toepassing:** Je exporteert direct het `soc_deconfliction.json` bestand. Dankzij de SHA-256 hash-chaining in `AuditLogger` kan het SOC timestamp-voor-timestamp en hash-voor-hash verifiëren dat het verkeer afkomstig was van jouw geautoriseerde assessment.
* **Waarde voor Peter:** Geen paniek of verstoorde incident response processen; 100% traceerbaarheid en compliance met TIBER-EU deconflictie-protocollen.

### Use-Case 4: Continue Perimeter Hygiëne Monitoring
* **Situatie:** Ontwikkelaars introduceren per ongeluk nieuwe openbare testomgevingen of vergeten HTTP Strict Transport Security (HSTS) in te schakelen.
* **Toepassing:** Een periodieke cronjob via OpenClaw controleert wekelijks geautoriseerde web-endpoints.
* **Waarde voor Peter:** Vroegtijdige detectie van "perimeter drift" zonder afhankelijkheid van ad-hoc handmatige controles.

---

## 4. Hands-on Testcases: Wat kun je nu direct demonstreren?

Hieronder staan 4 concrete testcases die je direct vanaf je terminal op de server kunt uitvoeren als live demonstratie.

### Testcase A: De Beveiligde Scope & Kill Switch Demonstreren
Toon aan dat de engine onmiddellijk weigert om ongeautoriseerde doelen aan te raken.

```bash
cd /root/repos/it-risk-redteam-engine

# Voer de specifieke scoping tests uit
python3 -m pytest tests/test_scope_safety.py -v
```
* **Wat zie je:** 
  1. IP `192.168.1.254` wordt hard geblokkeerd omdat deze in `out_of_scope` staat.
  2. Extern IP `8.8.8.8` wordt geblokkeerd omdat deze niet in het geautoriseerde netwerkbereik zit.
  3. De `Emergency Kill Switch` onderbreekt direct alle lopende async threads.
  4. De SHA-256 hash chain detecteert direct als iemand handmatig in het auditlog probeert te rommelen.

---

### Testcase B: Web Surface & Security Headers Audit
Voer een non-destructieve header audit uit op een geautoriseerd doeldomein.

```bash
cd /root/repos/it-risk-redteam-engine

python3 -m src.orchestrator \
  --scope configs/scope.example.yaml \
  --web https://api.example.internal \
  --host 192.168.1.50
```
* **Wat gebeurt er:**
  - De `ScopeManager` controleert eerst of `api.example.internal` geautoriseerd is.
  - De `ExternalSurfaceScanner` analyseert security headers (HSTS, CSP, X-Frame-Options, MIME-sniffing).
  - Alle bevindingen worden vastgelegd in `audit_log.jsonl` met een cryptografische hash.

---

### Testcase C: OWASP LLM Guardrail Stress-Test (Single- & Multi-Turn)
Voer de geavanceerde LLM testvectoren uit tegen een AI-endpoint.

```bash
cd /root/repos/it-risk-redteam-engine

python3 -m src.orchestrator \
  --scope configs/scope.example.yaml \
  --llm https://ai-agent.example.internal/v1/chat
```
* **Wat gebeurt er:**
  - De engine laadt `data/vectors/owasp_llm_vectors.yaml`.
  - Vectoren voor **LLM01** (Direct Override, Delimiter Hijack, Multi-turn Priming), **LLM06** (System Prompt Extraction, Env Var Leaks) en **LLM08** (Excessive Agency) worden afgevuurd met rate-limiting en token-accounting.
  - De evaluatie-heuristiek classificeert de respons als `DEFENDED` of `VULNERABLE`.

---

### Testcase D: Volledig DORA/TIBER-EU Rapport & SOC Deconflictie Genereren
Genereer met één commando direct management-rapportages en SOC-exports:

```bash
cd /root/repos/it-risk-redteam-engine

python3 -m src.orchestrator \
  --scope configs/scope.example.yaml \
  --web https://api.example.internal \
  --llm https://ai-agent.example.internal/v1/chat \
  --report-dir reports/
```

Bekijk de gegenereerde rapporten:
```bash
ls -la reports/
```
In de `reports/` directory vind je:
1. `executive_summary_*.md`: Een beknopt overzicht met risicostatistieken, CVSS verdeling en DORA/TIBER compliance conclusie voor het management.
2. `technical_report_*.md`: Gedetailleerde technische bevindingen met CVSS v3.1 vectoren, MITRE ATT&CK & ATLAS koppelingen en concrete hersteladviezen.
3. `soc_deconfliction_*.json`: Gestructureerd JSON-bestand voor het SOC/SIEM om alerts direct te ontkrachten.

---

## 5. Stakeholder Presentatie Script (Hoe pitch je dit intern?)

Wanneer je dit presenteert aan de **CISO**, de **Auditcommissie** of het **Risk Committee**:

1. **De Invalshoek:**  
   *"In het kader van DORA en de snelle adoptie van Generative AI moeten we aantonen dat onze beheersmaatregelen continu en aantoonbaar effectief zijn."*
2. **De Oplossing:**  
   *"We hebben een eigen, onafhankelijke IT Risk & Red Teaming engine operationeel die werkt volgens TIBER-EU standaarden. Deze toetst zowel onze externe perimeterhygiëne als de guardrails van onze AI-modellen."*
3. **De Veiligheidswaarborg:**  
   *"Dit gebeurt 100% veilig: we gebruiken harde scope-whitelisting op DNS- en CIDR-niveau, rate-limiting, een noodstop en onweerlegbare cryptografische auditlogging voor het SOC."*
4. **Het Resultaat:**  
   *"Met één druk op de knop beschikken we over geautomatiseerde DORA- en TIBER-conforme rapportages, inclusief CVSS-scores en MITRE ATT&CK/ATLAS mappings."*
