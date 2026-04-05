Scans a binary file with the format of: 

- DNS header (fixed length)
- Question entries (variable length)
- Answer resource records (variable length)
- Authority resource records (variable length)
- Additional resource records (variable length)

**Note: 
Will only recognise common record types:**
- A Record
- AAAA Record
- CNAME Record
- MX Record
- TXT Record
- NS Record
- SOA Record
- SRV Record
- PTR Record
