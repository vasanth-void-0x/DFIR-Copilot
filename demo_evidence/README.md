# Safe demo evidence

This directory contains a completely synthetic incident used to verify DFIR
Copilot. The IP address `203.0.113.77` and the `.invalid` domain are reserved
for documentation. There is no malware, live command-and-control endpoint, or
working payload in this package.

Expected sequence:

1. Archive download at 10:15 UTC.
2. PowerShell activity at 10:17 UTC.
3. Outbound connection at 10:18 UTC.
4. Persistence-like service event at 10:22 UTC.
5. Deleted-file records after the connection.

