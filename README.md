UtilityMaestro

Cybersecurity toolkit for network analysis and testing

<img src="https://github.com/user-attachments/assets/2393e7dc-6e5a-4264-8f9e-8f23372bb00a" width="1000">
Status

This project is not actively developed anymore.

Development stopped around October 2025
Parts of it are being split out into separate tools
Network-related tools may still be released publicly
Exploit-related tools are not public

Last note (April 2026): might continue under a different name.

What it is

UtilityMaestro is a collection of tools I built for:

network inspection
basic pentesting
troubleshooting

Everything is bundled into a single GUI app.

It’s not polished, but it works.

Running it
You need one of these first:
https://npcap.com/dist/npcap-1.81.exe
https://www.winpcap.org/install/bin/WinPcap_4_1_3.exe
Steps
Download the build
https://github.com/IndulgeinDotNet/UtilityMaestro/releases/tag/NightDev
Run UtilityMaestro.exe
Use Run as admin for network tools
Unlock:
Code: 1234
Check the ethics box
If Windows blocks it

This happens sometimes.

Go to:

Windows Security
Virus & threat protection
Allow the file

Or add it as an exclusion.

Main tools
Port Scanner

Scans open ports (TCP / SYN / FIN).
Used for finding exposed services.

Vulnerability Scanner

Checks for common web issues:

XSS
SQL injection
Log4Shell
Password Cracker

Brute force / dictionary attacks for:

MD5
SHA1
SHA256
Network Sniffer

Captures live traffic and lets you inspect packets.

SQL Injection Tool

Tests inputs against basic SQL payloads.

Other tools

There’s a bunch more:

DNS resolver
hash generator
base64 encoder
ping tool
packet injector
wifi scanner
brute forcer
csrf tester
xss injector

Some things were removed or never made public.

Use it right

Don’t use this on stuff you don’t own or don’t have permission to test.

That’s it.

License

Not open source.

You can use the build, but you can’t redistribute it.

Full terms:
https://github.com/IndulgeinDotNet/UtilityMaestro/blob/main/EULA

Author

INDDOTNET
