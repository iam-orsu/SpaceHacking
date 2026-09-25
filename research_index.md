# research_index.md

Space Systems Security Curriculum — Phase 1 Research Index

All sources in this document are publicly available and verified as of September 2026. No CVEs are documented here. This index covers misconfigurations, operational failures, design weaknesses, and the research that explains them. Every curriculum document from 00 through 11 cites sources from this index.

---

## Table of Contents

1. [Real Satellite Incidents](#1-real-satellite-incidents)
2. [DEF CON and Black Hat Talks](#2-def-con-and-black-hat-talks)
3. [Open-Source Projects](#3-open-source-projects)
4. [Academic Papers](#4-academic-papers)
5. [Technical Standards and Design Rationale](#5-technical-standards-and-design-rationale)
6. [Design Weaknesses and Why They Persist](#6-design-weaknesses-and-why-they-persist)

---

## 1. Real Satellite Incidents

### 1.1 Viasat KA-SAT Attack (2022)

**What happened:**
On February 24, 2022, the same hour Russia invaded Ukraine, an attacker executed a targeted destructive cyberattack against Viasat's KA-SAT satellite broadband network. Approximately 30,000 residential modems across Ukraine and Europe were rendered permanently inoperable. The attack also knocked offline roughly 5,800 wind turbines in Germany that used KA-SAT for remote monitoring.

**The misconfiguration that enabled it:**
The attacker exploited a misconfigured VPN appliance to gain remote access to the trusted management segment of the KA-SAT network. This single entry point gave the attacker lateral movement capability into the segment used to manage and operate the network.

**Why this misconfiguration existed:**
Satellite internet provider management networks are typically built for operational efficiency: remote access is built in by design so that network operators can manage equipment across geographically distributed ground infrastructure. VPN access to management segments is standard practice. The error was in the VPN appliance configuration itself, not in having remote access at all. This is a common operational tradeoff: operators need to manage equipment remotely, but remote access requires hardening that is often treated as secondary to uptime.

**What the attacker did:**
After entering the management network via the misconfigured VPN, the attacker issued legitimate management commands to a large number of residential modems simultaneously. These commands overwrote key data in flash memory on the modems, rendering them unable to connect to the network. The modems were bricked. No physical access to the satellite was required.

**Impact:**
Tens of thousands of broadband customers offline across Europe. Wind turbines in Germany lost remote monitoring capability. Communications disruption to Ukrainian military and government users at the start of the invasion.

**Lab relevance:**
The lab scenario mirrors this incident in its ground segment architecture. The Mission Operations Center (MOC) at 192.168.60.11 accepts remote connections from any IP in the lab network. This models the "trusted management segment accessible via VPN" configuration. The ground station at 192.168.60.10 has no source IP verification on command input. Document 03 (ground_station_attacks.md) exploits this directly.

**Sources:**
- Viasat incident report: https://www.viasat.com/perspectives/corporate/2022/ka-sat-network-cyber-attack-overview/
- Technical analysis: https://www.databreachtoday.com/viasat-traces-outage-to-exploit-vpn-misconfiguration-a-18815
- Threat analysis with SPARTA framework: https://www.periculo.co.uk/cyber-security-blog/anatomy-of-a-satellite-hack-deconstructing-the-viasat-incident-through-sparta

---

### 1.2 NOAA Satellite Data Network Breach (2014)

**What happened:**
In September 2014, attackers breached NOAA's National Environmental Satellite, Data, and Information Service (NESDIS) network. Four NOAA websites were compromised. The breach forced cybersecurity teams to take down data feeds vital to weather forecasting, disaster planning, aviation, and shipping. Suspected attribution: Chinese state-sponsored actors.

**The misconfiguration that enabled it:**
NOAA had not addressed publicly known security weaknesses for years. POES, GOES, and ESPC systems had thousands of vulnerabilities, some of which had been publicly disclosed for up to 13 years before the breach. The systems were exposed because NOAA failed to patch them and failed to segment satellite data networks from less secure corporate networks.

**Why this misconfiguration existed:**
NOAA's satellite data infrastructure is a legacy system. Many components were designed and deployed before cybersecurity was a primary operational concern. Patching satellite ground support systems is difficult: patches must be tested against mission-critical software, downtime is unacceptable during weather events, and budget for security operations competes with mission operations. This is the classic legacy system problem: operational continuity is prioritized over security hygiene.

**What the attacker did:**
The attacker moved from compromised perimeter systems into NOAA's internal satellite data network. Satellite data feeds were disrupted. The full scope of data accessed was not publicly disclosed.

**Impact:**
NOAA took satellite data feeds offline for two days while conducting emergency response. Weather forecasting and aviation support were affected. NOAA did not publicly confirm the full scope of access.

**Lab relevance:**
Document 02 (ground_reconnaissance.md) covers NOAA-style ground station enumeration: identifying exposed network services, discovering legacy system components, and finding interfaces that have not been patched or segmented. The lab MOC at 192.168.60.11 runs an older COSMOS configuration with default credentials, modeling exactly this failure.

**Sources:**
- CNN coverage: https://money.cnn.com/2014/11/12/technology/security/weather-system-hacked/index.html
- Washington Post original report: https://www.washingtonpost.com/local/chinese-hack-us-weather-systems-satellite-network/2014/11/12/bef1206a-68e9-11e4-b053-65cea7903f2e_story.html
- NOAA security lapses analysis: https://www.cyberwar.news/2016-09-06-longstanding-security-lapses-lead-to-hack-of-noaa-weather-computers.html

---

### 1.3 Turla Group Satellite Link Hijacking (2015)

**What happened:**
The Turla APT group (Russian state-sponsored) was discovered using commercial satellite DVB-S (Digital Video Broadcasting - Satellite) links as command and control infrastructure. Kaspersky Lab published detailed analysis in September 2015. Turla had been using this technique for several years prior to discovery.

**How DVB-S works, and why it is exploitable:**
DVB-S is the standard used to deliver commercial satellite television. The downlink signal from the satellite is a broadcast: anyone with a satellite dish pointing at the correct satellite can receive it. DVB-S broadcasts were unencrypted at the time of this attack. Turla identified satellite TV broadcast beams covering geographic areas of interest (Middle East, Africa, Central Asia) and targeted ISPs in those regions that did not implement anti-spoofing on their upstream connections.

**The attack mechanism:**
Turla implants on already-compromised victim machines were configured to send forged UDP packets. These packets had source IP addresses set to legitimate addresses belonging to satellite ISP subscribers in the target region. The packets were addressed to a Turla listener server. When the packet traveled upstream through the satellite ISP's network, the ISP's router — seeing a packet destined for a downstream subscriber on its network — broadcast that packet on the satellite downlink. Turla's infrastructure, equipped with a satellite dish and a DVB-S receiver card, received the satellite broadcast containing the C2 response. Traffic appeared to originate from thousands of potential satellite subscribers. No uplink from Turla's infrastructure was required.

**The misconfiguration that enabled it:**
Two misconfigurations worked together. First: DVB-S satellite ISPs in the targeted regions did not implement source address validation (BCP38 anti-spoofing). This allowed Turla to forge source IPs with no technical barrier. Second: DVB-S downlink traffic was completely unencrypted, making the broadcast readable by anyone with consumer-grade hardware pointing at the correct satellite.

**Why these misconfigurations existed:**
Anti-spoofing (BCP38) requires configuration effort and ISP infrastructure investment. Many smaller ISPs, especially in developing regions, do not implement it. It does not affect most users and is perceived as an optional hardening step. DVB-S encryption requires additional hardware and per-subscriber key management, which adds cost and operational complexity. Most commercial satellite TV broadcasts were unencrypted because the content was not considered sensitive enough to justify the cost.

**Equipment cost:**
Less than $1,000 USD. A satellite dish, a low-noise block downconverter (LNB), a DVB-S PCIe receiver card (TBS Technologies), and a Linux PC. Operating cost under $1,000 USD per year.

**What Turla gained:**
Near-anonymous C2 channel. Attribution was extremely difficult because the downlink covered thousands of subscribers in the target region. The technique was in active use for several years before discovery.

**Lab relevance:**
Document 05 (signal_interception.md) covers DVB-S style passive signal interception in the lab context. The lab simulates unencrypted downlink at 192.168.60.100. Document 09 (detection_evasion.md) covers C2 traffic obfuscation techniques derived from the Turla methodology.

**Sources:**
- Kaspersky Lab original analysis: https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/
- Security Affairs summary: https://securityaffairs.com/40008/cyber-crime/turla-apt-abusing-satellite.html
- CSO Online technical coverage: https://www.csoonline.com/article/552723/turla-cyberespionage-group-exploits-satellite-internet-links-for-anonymity.html

---

### 1.4 Iridium Network Interception (2015)

**What happened:**
Security researchers Sec and Schneider demonstrated interception of Iridium satellite network traffic at the Chaos Communication Camp in August 2015. The finding was that the Iridium network transmitted pager messages and some voice traffic with no encryption.

**The misconfiguration that enabled it:**
The Iridium system transmitted pager messages in cleartext over RF. Anyone with a software-defined radio (SDR) and a directional antenna could receive and decode these messages. The "problem isn't that Iridium has poor security. It's that it has no security" was how researcher Sec described it directly.

**How the interception worked:**
Using a HackRF or similar SDR hardware costing under $300, the researchers tuned to the Iridium frequency band (1616-1626.5 MHz), captured the raw RF signal, and decoded the digital stream. Private text messages, pager notifications, and some positional data were readable in cleartext. The researchers identified and located Department of Defense users with approximately 4 km accuracy using this equipment. German Foreign Office staff communications were intercepted as a live demonstration.

**Why this misconfiguration existed:**
The Iridium system was designed in the 1990s when the threat model for satellite communications focused on jamming and physical interference, not signal interception by cheap consumer hardware. SDR technology that makes interception trivial did not exist when Iridium's RF protocols were designed. Retrofitting encryption into an operational global satellite constellation requires firmware updates to all subscriber devices and changes to ground infrastructure — a massive operational undertaking with significant cost. The decision to not encrypt was made at design time and was very difficult to reverse.

**Lab relevance:**
Document 04 (rf_fundamentals.md) explains Iridium-style cleartext transmission and why it persists operationally. The SpaceVE-1 satellite in the lab has no downlink encryption, modeling this exact design choice. Document 05 (signal_interception.md) demonstrates live telemetry capture from the simulated satellite.

**Sources:**
- Vice overview: https://www.vice.com/en/article/its-surprisingly-simple-to-hack-a-satellite/
- IEEE Spectrum report: https://spectrum.ieee.org/iridium-satellite
- Security Affairs summary: https://securityaffairs.com/39510/hacking/hacking-iridium-network.html

---

### 1.5 ESTCube-1 Telecommand Authentication Bypass (2023, research disclosure)

**What happened:**
This is not an operational incident but a controlled research disclosure. Researchers at CISPA Helmholtz Center for Information Security (Johannes Willbold, Moritz Schloegel, and others) obtained firmware images from real satellites including ESTCube-1, an Estonian educational CubeSat. Analysis revealed that ESTCube-1's communications module had no authentication on its telecommand interface. Anyone who could transmit at the right frequency could send commands the satellite would accept.

**The misconfiguration:**
The flight software accepted telecommands based on checksum validation alone. No authentication mechanism. No source verification. The checksum is a mathematical validity check (did the packet arrive intact?) not an authentication check (is this command from an authorized source?).

**Why this misconfiguration existed:**
ESTCube-1 was an educational CubeSat built by student teams. Resources, time, and expertise were limited. Authentication requires a key management system, ground infrastructure changes, and additional software complexity. For a CubeSat with a finite mission lifetime, designers prioritized getting the satellite working over security hardening that seemed unlikely to be exploited. This is the dominant pattern in the CubeSat space: small teams, small budgets, schedule pressure, and a threat model that did not include targeted attacks.

**Researcher outcome:**
The research team remotely triggered error conditions on the CDHS (Command and Data Handling Subsystem), gaining what they described as full control of two out of three satellites studied. The research was disclosed responsibly.

**Lab relevance:**
This incident directly models the SpaceVE-1 lab satellite. The lab satellite uses checksum-only validation for telecommands. Document 06 (command_injection.md) exploits this directly by crafting valid CCSDS packets with correct checksums but unauthorized commands.

**Sources:**
- Full paper (IEEE S&P 2023): https://jwillbold.com/paper/willbold2023spaceodyssey.pdf
- CISPA publication page: https://cispa.de/en/research/publications/76368-space-odyssey-an-experimental-software-security-analysis-of-satellites
- Summary: https://cispa.de/en/satellite-security

---

## 2. DEF CON and Black Hat Talks

### 2.1 DEF CON 29 Aerospace Village — Satellite Hacking 101 (2021)

**Conference:** DEF CON 29 Aerospace Village, August 2021 (virtual)
**Focus:** Introduction to satellite hacking, recap of Hack-A-Sat 1, preview of Hack-A-Sat 2
**Key content:** Attack techniques against satellite communication protocols, introduction to software-defined radio for satellite signal interception, Flat Sat hardware demo (real satellite hardware components configured as a hacking target), Hack-A-Sat challenge walkthroughs

**Operational weaknesses discussed:**
- Satellite command protocols that lack authentication
- Ground station enumeration techniques
- Signal interception using cheap SDR hardware

**Source:** https://www.welivesecurity.com/2021/08/09/def-con-29-satellite-hacking-101/

---

### 2.2 DEF CON 31 Aerospace Village — Hack-A-Sat 4 / Moonlighter (2023)

**Conference:** DEF CON 31 Aerospace Village, August 2023
**Event:** Hack-A-Sat 4 — world's first Capture The Flag competition hosted on a real satellite in orbit
**Satellite:** Moonlighter CubeSat, developed by The Aerospace Corporation in partnership with Space Systems Command (SSC) and Air Force Research Laboratory (AFRL). Delivered to low Earth orbit June 2023.
**Competition format:** Five finalist teams competed against nine challenges. Two challenges targeted ground station infrastructure. Seven challenges targeted the satellite itself. Ground stations in four locations provided uplink/downlink windows.

**Key technical content:**
- Binary exploitation against satellite flight software
- Reverse engineering of satellite command parsers
- Attitude control system exploitation (reaction wheels, magnetorquers)
- Ground station compromise as a pivot into satellite control
- Cryptographic challenges specific to space operations

**Operational weaknesses exploited:**
- Flight software that did not validate command source
- Ground station software running with default configurations
- Telemetry channels that exposed mission planning data

**Source:** https://www.aerospacevillage.org/defcon-31
**Source:** https://hackasat.com/
**Source:** https://ieeexplore.ieee.org/document/10521107/ (four-year retrospective)

---

### 2.3 DEF CON 32 — "Breaking the Beam: Exploiting VSAT Satellite Modems from the Earth's Surface" (2024)

**Conference:** DEF CON 32 Aerospace Village, August 2024
**Speakers:** Vincent Lenders, Johannes Willbold, Robin Bisping (armasuisse Science and Technology / Ruhr University Bochum)
**Target system:** Newtec MDM2200 VSAT modem (iDirect product family)

**What they did:**
The team reverse-engineered the software stack of a commercially deployed VSAT (Very Small Aperture Terminal) satellite modem. VSAT modems are the hardware used by enterprises, ships, aircraft, and military units to connect to satellite networks. They found vulnerabilities by reverse engineering the firmware. They then devised signal injection attacks: using software-defined radios to inject malicious signals through the antenna dish of a VSAT terminal. This was the first public demonstration of signal injection attacks on VSAT modems.

**Operational weaknesses exploited:**
- VSAT firmware that did not validate the integrity of software updates
- Management interfaces on VSAT modems accessible from the satellite link itself
- No encryption or authentication on the satellite-side management channel

**Why these weaknesses exist operationally:**
VSAT deployments are designed for remote management. A ship or a military forward operating base cannot be physically accessed for maintenance. The satellite link itself is the management channel. Encrypting and authenticating this channel adds complexity, requires key distribution infrastructure, and creates a management burden. Many deployments skip it.

**Full paper:** Published at USENIX Security 2024 — https://www.usenix.org/conference/usenixsecurity24/presentation/bisping
**DEF CON presentation slides:** https://media.defcon.org/DEF%20CON%2032/DEF%20CON%2032%20presentations/DEF%20CON%2032%20-%20Vincent%20Lenders%20Johannes%20Willbold%20Robin%20Bisping%20-%20Breaking%20the%20Beam%20-%20Exploiting%20VSAT%20Satellite%20Modems%20from%20the%20Earths%20Surface.pdf

---

### 2.4 DEF CON 32 — "Small Satellite Modeling and Defender Software" (2024)

**Conference:** DEF CON 32 Aerospace Village, August 2024
**Speaker:** Kyle Murbach, University of Alabama in Huntsville, Center for Cybersecurity Research and Education (CCRE), U.S. Army Space and Missile Defense Command
**Full talk recording:** https://www.classcentral.com/course/youtube-def-con-32-small-satellite-modeling-and-defender-software-kyle-murbach-360311

**What the talk covered:**
Building a working small satellite system model using Raspberry Pi and PyCubed boards. Implementation of satellite subsystems: payload camera, radio communications, positioning, orbital simulation, battery/solar charging. Vulnerability analysis against each subsystem. Attack scenarios modeled: Man-in-the-Middle on satellite commands, denial of service, spoofing, hardware attacks. Introduction of "Small Satellite Defender" (SSD) software to monitor for attack patterns.

**Key operational weaknesses discussed:**
- Consumer-grade microcontrollers used in educational CubeSats with no security hardening
- AX.25 protocol (amateur radio standard) used as command uplink with no authentication
- Camera payload data transmitted in cleartext with no access control on downlink

**Curriculum relevance:** Documents 04, 05, and 07 reference this work for modeling small satellite attack surfaces.

---

### 2.5 DEF CON 34 — "Lowering the Orbit: Exploiting Satellite Protocols and Communications via SDR and GS" (2026)

**Conference:** DEF CON 34, Track 1, August 2026
**Speaker:** Romel "r0r0x" Marin (IBM)
**Talk duration:** 30 minutes

**What the talk covered:**
Introduction to satellite cybersecurity from an attacker's perspective. Detailed walkthrough of the CCSDS Space Packet Protocol: packet structure, header fields, checksum algorithm, command encoding. Tools that can be built for satellite signal work using SDR hardware. Live demonstration of attacks that can be performed using those tools. Explanation of why the checksum-only validation model does not provide security.

**Key content for this curriculum:**
- CCSDS packet structure breakdown (Primary Header, Secondary Header, User Data, Checksum)
- How to craft valid CCSDS packets with arbitrary commands
- SDR hardware setup for satellite frequency ranges
- Ground station enumeration methodology

**Source:** https://it4sec.substack.com/p/hackers-guide-to-satellite-cybersecurity
**DEF CON 34 schedule:** https://defcon.org/html/defcon-34/dc-34-schedule.html

---

### 2.6 Chaos Communication Camp 2015 — "Iridium Hacking: Please Don't Sue Us"

**Conference:** Chaos Communication Camp (CCC), August 2015
**Speakers:** Sec, Schneider

**What they demonstrated:**
Live interception of Iridium satellite pager and voice traffic using a software-defined radio. Equipment cost: under $300. Built and demonstrated an eavesdropping kit (directional Iridium antenna, SDR receiver, Linux laptop) that could identify and locate Department of Defense users with approximately 4 km accuracy. Intercepted and read German Foreign Office staff communications live during the presentation.

**Key finding stated publicly:**
"The problem isn't that Iridium has poor security. It's that it has no security."

**Why it matters for this curriculum:**
This talk established the baseline for understanding how satellite RF protocols designed in the 1990s interact with modern SDR hardware. It demonstrates that the barrier to satellite signal interception is a few hundred dollars and an afternoon of setup, not specialized government-grade equipment. Document 04 (rf_fundamentals.md) and Document 05 (signal_interception.md) both build from this foundation.

**Source:** https://www.vice.com/en/article/its-surprisingly-simple-to-hack-a-satellite/
**Source:** https://spectrum.ieee.org/iridium-satellite

---

## 3. Open-Source Projects

### 3.1 NASA NOS3 (NASA Operational Simulator for Space Systems)

**GitHub:** https://github.com/nasa/nos3
**Maintained by:** NASA Katherine Johnson Independent Verification and Validation (IV&V) Facility
**Status:** Actively maintained. As of January 2026: 536 stars, 138 forks, 80 open issues. Pull requests open as recently as January 16, 2026.
**License:** Apache 2.0

**What it is:**
NOS3 is a software suite for satellite simulation. It provides a full software development environment for CubeSat-class satellites including multi-target build system, an operator interface and ground station, dynamics and environmental simulations, and software-based models of spacecraft hardware components.

**Key capabilities:**
- Simulates satellite hardware: reaction wheels, magnetorquers, GPS, solar panels, power systems, cameras
- Runs NASA cFS (Core Flight System) as the simulated flight software
- Integrates with Ball Aerospace COSMOS as the ground station software
- Provides an isolated internal network for the satellite bus and ground segment

**Docker/containerization status:**
Docker Compose and Kubernetes deployment work is in progress (PR #810 opened November 2025, PR #813 November 2025). Full containerization is not yet stable. The lab setup script in Phase 2 will use the supported VM-based installation on Ubuntu 22.04, with Docker used for isolated service components.

**Lab relevance:**
NOS3 is the core satellite simulator in the lab. The SpaceVE-1 satellite at 192.168.60.100 runs on NOS3. Flight software is NASA cFS running inside NOS3. All command injection, telemetry interception, and flight software attacks target the NOS3 environment.

**Installation prerequisite:** Ubuntu 22.04 LTS, 16 GB RAM recommended.

---

### 3.2 NASA cFS (Core Flight System)

**GitHub:** https://github.com/nasa/cFS
**Maintained by:** NASA
**Status:** Actively maintained, multiple active forks and contributors
**License:** Apache 2.0

**What it is:**
cFS is the actual flight software framework used on real NASA missions including Lunar Reconnaissance Orbiter, LCRD, and multiple CubeSat programs. It is a modular, portable, real-time embedded framework for satellite command and data handling. cFS runs on the spacecraft onboard computer and processes telecommands, manages telemetry, and coordinates subsystem operations.

**Key components:**
- Core Flight Executive (cFE): provides core services including time management, event services, software bus, table services
- cFS Software Bus: publish-subscribe messaging between flight software applications
- Sample applications: command ingest, telemetry output, housekeeping, memory management, file system

**Security-relevant characteristics:**
cFS was designed for reliability and portability, not security. Command validation is application-level and configurable. There is no mandatory authentication layer in the base framework. A cFS installation without explicit authentication applications will accept any correctly formatted command packet it receives. This is documented behavior, not a bug. The framework trusts the command source because it was designed for environments where the communication link itself was assumed to be trusted.

**Build requirements:** Ubuntu 22.04, CMake, GCC, Git. Builds on standard Linux without additional packages.

---

### 3.3 Ball Aerospace COSMOS (Command and Telemetry System)

**GitHub:** https://github.com/BallAerospace/COSMOS
**Maintained by:** Ball Aerospace (now BAE Systems), open-source since December 2014
**License:** GPLv3 (open source) and commercial licenses available
**Status:** Maintained. Active issues and pull requests.

**What it is:**
COSMOS is a complete ground station software suite. It provides everything needed to send commands to and receive telemetry from a satellite or embedded system. It includes a telemetry display, telemetry graphing, command scripting, command sending, data logging, and log playback. COSMOS is used by real CubeSat programs as their mission control software.

**Key capabilities for this curriculum:**
- Command interface: send CCSDS-formatted commands to the satellite by name and parameter
- Telemetry monitor: real-time display of satellite status, sensor data, system health
- Script runner: automate command sequences using Ruby scripts
- Log viewer: replay historical telemetry sessions for analysis

**Default configuration risk:**
COSMOS ships with default credentials. Many CubeSat programs deploy COSMOS in operational environments without changing these credentials. This is the exact misconfiguration exploited in Document 03 (ground_station_attacks.md). The MOC at 192.168.60.11 runs COSMOS with default credentials in the lab.

---

### 3.4 PwnSat / FlatSat (Electronic Cats)

**GitHub (FlatSat):** https://github.com/ElectronicCats/FlatSat
**GitHub (PWNCUBE):** https://github.com/ElectronicCats/PWNCUBE
**Organization:** https://github.com/Pwnsat
**Website:** https://pwnsat.org/
**License:** GPL-2.0-or-later
**Status:** Actively maintained

**What it is:**
PwnSat is an open-source platform for practicing aerospace cybersecurity. It simulates critical real-world satellite subsystems including a flight computer, RF communications subsystem implementing CCSDS and AX.25 protocol stacks, power distribution, and GNSS. The FlatSat repository includes eight pre-built attack scripts (numbered 00 through 07) covering vulnerabilities in the platform, each available in an RF variant (using HackRF or RTL-SDR) and a USB variant.

**PWNCUBE specifically:**
PWNCUBE is a hardware platform that integrates a Dockerized Mission Operations Center running Ball Aerospace COSMOS. It includes scenarios for telemetry forgery (manipulating AX.25 packets), exploiting web-based vulnerabilities in the MOC, pivoting from the MOC to COSMOS C3 instances, and executing unauthorized kill-commands through RF ground stations.

**Key lab relevance:**
PwnSat's attack script structure (00 through 07) maps closely to the curriculum's attack chain. The RF variants demonstrate real SDR-based attacks. The USB variants allow practicing attack logic without RF hardware.

**Note on IBM attribution:** Earlier curriculum drafts incorrectly attributed PwnSat to IBM. PwnSat is maintained by the PwnSat organization and Electronic Cats, not IBM.

---

### 3.5 Hack-A-Sat Library (Department of Defense)

**GitHub:** https://github.com/deptofdefense/hack-a-sat-library
**Maintained by:** U.S. Department of Defense
**Status:** Public, contains challenge writeups and space security documents

**What it contains:**
A public library of space documents, tutorials, and writeups from the Hack-A-Sat competition series. Covers orbital mechanics, satellite subsystem architecture, CCSDS protocol details, ground station operation, and attack techniques demonstrated in past competitions.

**Curriculum relevance:** Research reference. Used in Documents 06 and 07 for command injection and flight software attack methodology.

---

### 3.6 GNU Radio

**Website:** https://www.gnuradio.org/
**Installation:** `sudo apt install gnuradio` on Ubuntu 22.04
**Version (Ubuntu 22.04 package):** 3.10.x
**Status:** Actively maintained, major open-source SDR framework

**What it is:**
GNU Radio is a free and open-source software development toolkit for signal processing. It provides the signal processing blocks needed to implement software-defined radios and receive, decode, and analyze RF signals including satellite communications.

**Key capabilities for this curriculum:**
- Receive and display satellite downlink signals
- Decode BPSK, QPSK, FSK modulated signals (all common in satellite systems)
- Build custom signal processing pipelines in Python or graphical flowgraph editor
- Output decoded bitstreams for further analysis

**Lab use:** Documents 04 and 05 (rf_fundamentals.md and signal_interception.md) use GNU Radio to capture and decode simulated satellite downlink signals from the SpaceVE-1 satellite.

---

## 4. Academic Papers

### 4.1 "Space Odyssey: An Experimental Software Security Analysis of Satellites"

**Authors:** Johannes Willbold, Moritz Schloegel, Manuel Vögele, Maximilian Gerhardt, Thorsten Holz, Ali Abbasi
**Institution:** CISPA Helmholtz Center for Information Security, Ruhr University Bochum
**Published:** IEEE Symposium on Security and Privacy (S&P), May 2023
**Full paper:** https://jwillbold.com/paper/willbold2023spaceodyssey.pdf
**CISPA page:** https://cispa.de/en/research/publications/76368-space-odyssey-an-experimental-software-security-analysis-of-satellites

**What they did:**
Obtained firmware images from three real satellites. Analyzed the firmware using binary analysis techniques. Applied real-world attacker models to determine what an attacker with the ability to transmit at the correct frequency could do. Also surveyed 19 professional satellite developers about security practices in the industry.

**Key findings relevant to this curriculum:**
1. ESTCube-1 (Estonian educational CubeSat): The communications module had no authentication on its telecommand interface. Missing encryption and authentication results in trivial access control bypass. Any attacker who could transmit at the correct frequency could send commands the satellite would execute.
2. All three satellites studied had security-critical vulnerabilities in their firmware.
3. The researchers successfully triggered error conditions on the CDHS (Command and Data Handling Subsystem), achieving what they described as full control of two out of three satellites.
4. Survey of 19 satellite developers found that security practices vary widely and many teams do not consider their satellites likely attack targets.

**Why misconfigurations exist (from survey findings):**
Satellite development teams are small. Security expertise is rarely present on the team. Schedule pressure is intense — launch windows are fixed and cannot slip. The perceived threat model did not include targeted attacks from actors capable of transmitting at the right frequency. Budget for security testing is minimal or absent.

**Curriculum relevance:** Core reference for Documents 06, 07, and 08 (command injection, flight software, persistence). The ESTCube-1 findings are the direct model for the SpaceVE-1 lab satellite's authentication design.

---

### 4.2 "Rethinking Satellite Cybersecurity: A System-Level Taxonomy and Longitudinal Analysis" (SoK)

**arXiv:** https://arxiv.org/abs/2312.01330
**Published:** December 2023
**Alternate title:** "SoK: Evaluating the Security of Satellite Systems"

**Key findings:**
Compiled a dataset of more than 200 publicly reported satellite incidents from 1962 to present. Analyzed each incident across space, ground, communication, and user segments to identify architectural exposures and operational attack surfaces. Found that ground segment attacks are the most common entry point. Found that authentication failures account for the majority of command injection incidents.

**Curriculum relevance:** Documents 02 and 03 reference this taxonomy for ground segment attack classification. The 200-incident dataset is the empirical basis for the claim that ground segment is the primary attack surface.

---

### 4.3 "SpyChain: Multi-Vector Supply Chain Attacks on Small Satellite Systems"

**arXiv:** https://arxiv.org/abs/2510.06535
**Published:** October 2025 (18 pages, 7 figures)
**Key finding:** First end-to-end demonstration of coordinated multi-component malware in the NASA NOS3 environment.

**What it demonstrates:**
Auxiliary COTS (commercial off-the-shelf) components in satellite systems often lack security assurance but have the same access to critical on-board resources as the flight software itself. This includes access to telemetry, system calls, and the software bus. SpyChain shows how trusted-looking components can collude: one component exfiltrates telemetry, another component persists across reboots, and a third disrupts operations — all using legitimate interfaces that do not trigger anomaly detection.

**Why this matters operationally:**
Small satellite programs buy COTS components to reduce cost and schedule. A magnetometer sensor, a GPS receiver, a power monitor — these are bought off the shelf from commercial suppliers. The supply chain for these components is not verified. A compromised COTS component is pre-installed in the satellite at launch and has direct access to the internal bus.

**Curriculum relevance:** Document 08 (persistence.md) and Document 07 (flight_software.md) reference SpyChain for the persistence and supply chain attack models.

---

### 4.4 "Cybersecurity Risk Assessment for CubeSat Missions"

**arXiv:** https://arxiv.org/abs/2604.00303
**Published:** March 2026

**Key findings relevant to this curriculum:**
1. Weak authentication or poorly segmented ground station interfaces directly enable command injection. The paper quantifies the impact range: "configuration drift to mission interruption."
2. AI-driven anomaly detection is technically feasible on CubeSat-class hardware using lightweight TinyML architectures.
3. Many CubeSat programs still use plain AX.25 or legacy CCSDS protocols without encryption or authentication.
4. Ground station software (including COSMOS deployments) is frequently left with default credentials and unpatched firmware.

**Why defaults persist:**
Small mission teams deploy COSMOS and move immediately to mission operations without a security configuration phase. There is no regulatory requirement to harden ground station software in most CubeSat programs. The operational priority is getting telemetry flowing, not auditing access controls.

**Curriculum relevance:** Ground reference for Document 03 (ground_station_attacks.md) and Document 11 (defense_hardening.md).

---

### 4.5 "Towards Resilient Intrusion Detection in CubeSats: Challenges, TinyML Solutions, and Future Directions"

**arXiv:** https://arxiv.org/abs/2604.06411
**Published:** April 2026

**Key findings:**
Traditional intrusion detection systems are impractical on CubeSat hardware due to RAM constraints (typically 256 KB to 4 MB) and power budget limits. The paper proposes TinyML-based anomaly detection as a viable approach and benchmarks lightweight models against simulated attack data.

**Curriculum relevance:** Document 09 (detection_evasion.md) references this work for understanding what detection is realistically deployed on small satellite platforms and how to evade it.

---

### 4.6 "MimicSat: A Reconfigurable Cyber-Physical Testbed For Small Satellite Systems and Cybersecurity Research"

**arXiv:** https://arxiv.org/abs/2609.28228
**Published:** September 2026

**What it is:**
A testbed framework for small satellite cybersecurity research. MimicSat is designed to replicate real satellite subsystem behavior in a controlled lab environment, supporting both attack simulation and defensive control testing.

**Curriculum relevance:** Documents the current state of satellite security testbed design. Validates that the lab architecture used in this curriculum (NOS3 + cFS + COSMOS + isolated network) is consistent with active research methodology.

---

### 4.7 "Silent Subversion: Sensor Spoofing Attacks via Supply Chain Implants in Satellite Systems"

**arXiv:** https://arxiv.org/abs/2603.10388
**Published:** March 2026

**Key finding:**
A compromised sensor component (e.g., a GPS receiver or attitude sensor) can feed false data to the flight software without triggering anomaly detection, because the false data is delivered over trusted internal interfaces. The flight software has no way to distinguish authentic sensor readings from fabricated ones when the sensor itself is compromised.

**Curriculum relevance:** Document 07 (flight_software.md) uses this attack model for the sensor spoofing exploitation path.

---

### 4.8 "SoK: Space Infrastructures Vulnerabilities, Attacks and Defenses"

**Publication:** IEEE Symposium on Security and Privacy 2025
**Authors:** Remy, Ear, Chang, Feffer, Xu
**arXiv/Semantic Scholar:** https://arxiv.org/pdf/2507.17064

**Key finding:**
Comprehensive taxonomy of adversarial tactics, techniques, and procedures targeting LEO satellites. The paper matches every attack technique to a space segment (ground, link, space, user), identifies which defenses exist, and maps the gap between available defenses and deployed defenses. The gap is large: many effective defenses exist but are not deployed because of cost and operational complexity.

**Curriculum relevance:** Core structural reference for the full curriculum architecture. The segment breakdown (ground / link / space / user) directly maps to Documents 02 through 09.

---

## 5. Technical Standards and Design Rationale

### 5.1 CCSDS Space Packet Protocol (SPP)

**Specification:** CCSDS 133.0-B-2 (Blue Book, Recommended Standard)
**Available at:** https://ccsds.org/Pubs/133x0b2e2.pdf
**Free access:** Yes

**What it defines:**
CCSDS SPP defines the format of packets used to carry commands and telemetry in satellite communications. It was designed by the Consultative Committee for Space Data Systems, an international standards body made up of major space agencies (NASA, ESA, JAXA, ISRO, and others).

**Packet structure:**
- Primary Header (6 bytes): Packet Version Number (3 bits), Packet Type (1 bit, command or telemetry), Secondary Header Flag, Application Process Identifier (APID, 11 bits), Sequence Flags, Packet Sequence Count, Packet Data Length
- Secondary Header (variable, optional): Mission-specific fields including timestamps and subsystem identifiers
- User Data Field (variable): The actual command data or telemetry payload
- Checksum (2 bytes, optional): Cyclic redundancy check over the packet

**Security properties:**
SPP has no built-in authentication. No cryptographic integrity check. No source verification. The checksum is a CRC-16 calculated over the packet contents. It detects transmission errors. It does not detect tampering. Any attacker who knows the packet format can calculate a valid checksum for any packet they construct.

**Why no authentication was designed in:**
CCSDS SPP was designed in an era when the RF link itself was considered the security boundary. The assumption was: if you can receive this signal, you are inside the authorized ground station. The protocol was designed for reliability and interoperability across space agency systems, not for adversarial environments. Adding mandatory authentication would have required key management infrastructure that did not exist in the 1980s and 1990s when these standards were developed.

**CCSDS Space Data Link Security (SDLS):**
CCSDS later developed the SDLS protocol (CCSDS 355.0-B-2) to add authentication and encryption at the data link layer. SDLS is not widely deployed on small satellites because it requires additional hardware for key management, adds computational overhead, and requires coordinated key distribution between ground station and spacecraft before launch.

**Curriculum use:** Documents 04 and 06 explain the SPP packet structure and checksum calculation in detail. Document 06 (command_injection.md) uses this to craft unauthorized commands.

---

### 5.2 CubeSat Design Specification (CDS)

**Published by:** California Polytechnic State University (Cal Poly), San Luis Obispo
**Current revision:** Rev 14 (available at cubesat.org)
**Free access:** Yes

**What it defines:**
Physical dimensions, mass limits, deployment interface, and basic operational requirements for CubeSat-class satellites. The 1U standard defines a 10 cm cube with a maximum mass of 1.33 kg. 3U is the most common operational form factor (30 cm x 10 cm x 10 cm, max 4 kg).

**Power budget implications for security:**
A 3U CubeSat in LEO orbit generates between 2 W and 10 W from solar panels depending on attitude and sun angle. A typical 3U power budget allocates approximately:
- Flight computer: 0.5 W - 1 W
- Radio: 0.5 W - 2 W (receive), 1 W - 4 W (transmit)
- Attitude control: 0.2 W - 1 W
- Payload: remainder

AES-256 encryption in software on a low-power ARM Cortex-M4 class processor consumes approximately 10-30 mW sustained. This is technically within budget. However, encryption must be implemented with correct key management, IV handling, and integration with the command parser. This is software work that requires a security engineer. Most CubeSat programs do not have a security engineer on the team.

**Why security is weak — the real operational reason:**
The CubeSat design specification does not require security controls. There is no regulatory body for CubeSat security (compared to, for example, FCC regulations for radio emissions). No customer or launch provider checks for authentication on telecommand interfaces. The first security failure does not typically result in visible mission loss — a satellite that can be commanded by an unauthorized party still functions normally for its authorized users until an attacker actively disrupts it. This means the feedback loop that would drive security improvement does not fire.

---

### 5.3 AX.25 Protocol (Amateur Satellite Standard)

**Standard:** AX.25 Link Access Protocol for Amateur Packet Radio, Version 2.2
**Used by:** Educational CubeSats, amateur radio satellites, some commercial small satellites
**Authentication:** None. No authentication mechanism is defined in the protocol.

**Why it is used in satellites:**
AX.25 is the link-layer protocol for amateur packet radio. Many CubeSat teams, particularly university programs, are also amateur radio operators. Using AX.25 allows the satellite to communicate with a wide network of amateur radio ground stations around the world, providing free additional telemetry reception at no cost. The tradeoff is that AX.25 has zero security.

**Curriculum relevance:** Documents 04 and 05 explain AX.25 in the context of unencrypted downlink protocols. PwnSat/PWNCUBE attack scripts target AX.25 telemetry directly.

---

## 6. Design Weaknesses and Why They Persist

This section documents the specific operational decisions that create exploitable weaknesses in real satellite systems. These are not bugs. They are design choices. Understanding why they were made is required to explain them accurately to students.

### 6.1 No Encryption on Uplink or Downlink

**The weakness:** Commands sent from ground to satellite and telemetry sent from satellite to ground travel in cleartext. Any party with an antenna and an SDR can read the telemetry. Any party who can transmit at the right frequency can attempt to inject commands.

**Why it exists:**

Cost: Encryption requires key management. Before launch, symmetric keys must be generated, securely stored in the satellite's non-volatile memory, and securely stored in the ground station. Asymmetric cryptography (public-key) requires more computational resources than small microcontrollers have available at reasonable power. Key management for satellite missions is a specialized discipline that most small satellite teams do not have expertise in.

Power: Decryption of the incoming command stream requires running a crypto algorithm on every received packet. On a microcontroller drawing 0.5 W total, this is a meaningful overhead. Many CubeSat programs choose not to spend that power on decryption.

Operational complexity: Encrypted satellite links require that the ground station and satellite have synchronized keys. If the key is lost or corrupted, the mission may become unrecoverable. Many teams choose the simpler failure mode (exploitable by attackers) over the catastrophic failure mode (satellite permanently uncontrollable if keys are lost).

Legacy compatibility: The CCSDS standard is widely implemented in ground station software. Adding encryption requires changes to both the satellite and the ground station software, and must be compatible with all existing infrastructure.

**Where this weakness appears in the lab:**
SpaceVE-1 uses CCSDS SPP with checksum-only validation and no encryption on uplink or downlink. This models the dominant operational configuration in LEO small satellite programs. Documents 04, 05, and 06 all exploit this weakness.

---

### 6.2 Weak Authentication on Telecommand Interface

**The weakness:** The satellite accepts telecommands from any source that can transmit a correctly formatted CCSDS packet with a valid checksum. No cryptographic signature. No pre-shared key. No challenge-response handshake.

**Why it exists:**

Threat model: The original threat model for satellite telecommand assumed that the attacker could not transmit at the correct frequency from a ground-based location. The satellite's orbit means it is only visible from a given ground station for approximately 10 minutes per pass. The assumption was: only authorized ground stations have the infrastructure to transmit uplink commands. This assumption was valid in the 1960s. SDR hardware available for $200 today makes it false.

Complexity of authentication: Proper challenge-response authentication requires state management on the satellite side. The satellite must track sequence numbers, prevent replay attacks, and handle the case where authentication fails. This is state that can corrupt. Many teams prefer stateless command acceptance (just check the checksum) because it is simpler and more reliable.

No regulator checks: No launch provider, no CCSDS compliance authority, and no insurance underwriter currently requires command authentication on small satellite missions. There is no external pressure to add it.

---

### 6.3 Ground Station Network Segmentation Failures

**The weakness:** The ground station network that directly controls the satellite is not isolated from the broader corporate or institutional network. An attacker who compromises any system on the institutional network can reach the ground station.

**Why it exists:**
The ground station software needs to pull in orbital data, weather data, mission planning files, and software updates. All of these require network connectivity. The operational reality is that ground station computers are general-purpose workstations that happen to also run COSMOS or equivalent software. Strict network segmentation would require dedicated hardware, separate network infrastructure, and air-gap procedures that most small satellite programs do not budget for.

**How attackers reach it:**
The Viasat attack (Section 1.1) entered through a VPN misconfiguration. The NOAA breach (Section 1.2) entered through unpatched perimeter systems. In the lab, Document 02 demonstrates how an attacker on the same network as the MOC can enumerate and access ground station services directly.

---

### 6.4 Default Credentials on Ground Station Software

**The weakness:** COSMOS, NOS3, and other ground station software ship with default credentials. Operational teams frequently do not change them.

**Why it exists:**
Ground station software is typically installed by the flight operations team, who are satellite engineers, not system administrators. The installation instructions focus on getting the software running, not on hardening it. The default credentials exist to simplify initial setup. There is no automated credential rotation or first-use forced password change in most configurations. The satellite mission is often operational within days of software installation, before security configuration is addressed.

**Lab model:**
The MOC at 192.168.60.11 runs COSMOS with default credentials. Document 03 (ground_station_attacks.md) uses this directly to gain unauthorized command access.

---

### 6.5 Single Points of Failure in Ground Segment Architecture

**The weakness:** Most small satellite programs operate a single ground station. There is no backup ground station. If the ground station is compromised or destroyed, mission control is lost.

**Why it exists:**
Additional ground stations cost money to build and operate. Small satellite programs, particularly university programs, operate on budgets of $1 million to $10 million total. A second ground station might cost $500,000 to build and $100,000 per year to operate. This is not justified for a 12-month educational mission.

**Impact on security posture:**
A single ground station that is compromised gives the attacker complete and exclusive control over the satellite. There is no fallback. There is no secondary ground station that can override the attacker's commands. This makes ground station compromise the highest-impact attack in the entire kill chain.

---

### 6.6 Unverified Firmware and No Code Signing

**The weakness:** Flight software is loaded onto the satellite before launch without cryptographic verification. Once in orbit, software updates can be transmitted and loaded without a code signature check. The satellite will accept and execute any binary that arrives via the telecommand interface, provided the packet is correctly formatted.

**Why it exists:**

No standard for code signing in small satellites: There is no CCSDS standard or CubeSat design specification requirement for firmware code signing. It is technically optional.

Key management complexity: Code signing requires a private key held by the mission team and a public key burned into the satellite's non-volatile memory at manufacturing time. This is a supply chain process that most small satellite programs do not have in place.

Flash memory constraints: Some CubeSat microcontrollers have limited flash memory and limited RAM. Storing a code verification routine, a public key, and the verification overhead competes with mission software.

**SpyChain relevance:** The SpyChain paper (Section 4.3) demonstrates that even if flight software is signed, COTS component firmware often is not. The supply chain attack vector persists even when flight software signing is implemented.

---

*End of research_index.md — Phase 1 complete.*

*Phase 1 sources used: Viasat incident report, DataBreachToday VPN misconfiguration analysis, Washington Post NOAA reporting, Kaspersky Securelist Turla analysis, IEEE Spectrum Iridium reporting, CISPA Space Odyssey paper, arXiv papers 2312.01330 / 2510.06535 / 2604.00303 / 2604.06411 / 2609.28228 / 2603.10388 / 2507.17064, DEF CON 29/31/32/34 Aerospace Village schedules, USENIX Security 2024 VSAT paper, Hack-A-Sat official site and DoD library, NASA NOS3 and cFS GitHub repositories, BallAerospace COSMOS GitHub, PwnSat/PWNCUBE GitHub, CCSDS 133.0-B-2 Space Packet Protocol specification, CubeSat Design Specification.*

*Phase 2 begins when approved: Lab Research and Build — cloning NOS3, cFS, COSMOS, building docker-compose.yml and setup_lab.sh.*
