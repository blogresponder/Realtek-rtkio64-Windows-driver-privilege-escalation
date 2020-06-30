# Realtek rtkio64 Windows driver privilege escalation

## What is this?

This is a privilege escalation exploit of the Realtek rtkio64 Windows driver. If the driver is installed on the system, it is possible to escalate privileges to "NT Authority\SYSTEM" from any unprivileged user. 

## Disclamer

This code is a Proof-Of-Concept. It can cause the system to crash. Use at your own risk!
That said, on my setup on Windows 10 version 10.0.17763.973) and with reasonable memory mapping limits, the code worked just fine.

## How does it work

The Realtek rtkio64 driver maps kernel memory in an unsafe manner (using MmMapIoSpace routine) making it possible to map the kernel memory chunk by chunk by anyone who decides to talk to the driver. It is then possible to find and steal privileged tokens stored in the EPROCESS structure of privileged processes. When the current process token is overwritten with the privileged token, the current process gains "NT Authority\SYSTEM" privileges.

## Usage notes

This exploit maps the physical memory to process memory and parses it looking for EPROCESS structures. The start address and end address that should be used for mapping the memory will vary from PC to PC depending on the size of RAM (and other factors). These values can be tweaked (using command line options -startAddr and -endAddr). Choosing start address and end address too far apart will make the scanning process take longer. Setting these values too high can also be risky and cause crashes.

It is also possible to choose which process you want to steal the token from (command line option -privilegedPID) and to which process we want to elevate privileges (command line option -userPID).

Finally, sometimes when we look through the memory, we can miss the searched structure. In such case, we can choose another privileged process to steal the token from.

## Credits

This vulnerability (and many similar ones in numerous other Windows drivers) were discovered and presented at DEFCON 27 by [@JesseMichael](https://twitter.com/jessemichael) and [@HackingThings](https://twitter.com/hackingthings) from the Eclypsium project.
I don't pretend to have found the bug. I just coded a PoC for fun, no profit.

## Driver version and references

The vulnerable driver is part of the "Realtek Ethernet Controller All-In-One Windows Driver".
It can be found in the sp87568.exe driver pack with the following references.

	Title:  Realtek Ethernet RTL8111EPH-CG Controller Drivers
	Version:  10.23.1003.2017
	Description: This package provides the driver for the Realtek Ethernet RTL8111EPH-CG Controller in the supported notebook/laptop models and operating

Following is the hash and name of the vulnerable driver :

	7133a461aeb03b4d69d43f3d26cd1a9e3ee01694e97a0645a3d8aa1a44c39129 rtkio64.sys

## Demo
![Exploitation_PoC](https://github.com/blogresponder/Realtek-rtkio64-Windows-driver-privilege-escalation/blob/master/screenshots/poc_realtek_privesc.gif)

## Moral of the story

During red-teaming or Windows AD pwning scenarios, don't forget to look up drivers. Local admin (or system crash :)), may be closer than you excpect..

## References
	https://github.com/eclypsium/Screwed-Drivers
	http://blog.rewolf.pl/blog/?p=1630
	https://www.fuzzysecurity.com/tutorials/expDev/23.html
	http://www.jackson-t.ca/lg-driver-lpe.html
