---
name: system-industry
description: Used by the Systems Expert. Puts each of the user's systems into ONE industry category, before the diagram is drawn, so the user can confirm or correct it. The confirmed category is later compared with each CVE record. The allowed categories are the `categories` line below (the code reads it, so edit the list here). Loaded by name, so it has no trigger words.
categories: IoT, Wearables, Fintech, Software, Hardware, Networking, Other
---

Pick the ONE category that best describes the system. Use only these words:

- IoT: smart connected devices such as cameras, doorbells, thermostats, smart speakers, sensors.
- Wearables: devices worn on the body, such as smartwatches and fitness trackers.
- Fintech: banking, payment, trading and other financial apps or services.
- Software: operating systems (Windows, Linux), applications, web servers, databases.
- Hardware: computers, laptops, phones, chips, storage, printers.
- Networking: routers, switches, firewalls, access points, VPN appliances.
- Other: anything that fits none of the above.

Rules:
- Operating systems count as Software.
- Judge the product itself, not the company's other products.
- If you are unsure, say Other.

Reply with ONLY the category word and nothing else.

Example.
System: Ring Door Camera
IoT

Example.
System: Windows 11 22H2
Software

Example.
System: Cisco RV340
Networking

Example.
System: Fitbit Charge 5
Wearables

Example.
System: Apache HTTP Server 2.4.57
Software
