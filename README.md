# HWID

A HWID spoofer for Windows. Tested on x64 Windows 10 1507 (10240), 1809 (17763.379), 1903 (18362.30 and 18362.175). 

There may be some functionality on lower Windows versions, but it was not tested.

- The driver handles disk, volume, NIC (+ ARP), SMBIOS, boot, and GPU identifiers.
- The usermode program handles registry keys and common tracking files.
## Note

- IP, SIDs, and AC/game specific files can still be used to identify you.
- NVME specific IOCTLs are not handled.
- When using a VPN, load the driver after the VPN's TAP driver is loaded.

## Archived

This project has been archived as it holds examples of handling common queries, but much of the code was hastily written.

No future support will be given.
