# WAFFEL
- DOS - count SYNs from each ip and block it if it exceeds a certain cap
- DDOS -
DDos -> יוצרים מצב שבו אם משתמש בודקים האם משתמש לא שלח הודעה בזמן קצוב מראש לאחר, אם בסיום הזמן הקצוב, המשתמש לא ישלח הודעה, השרת יתנתק מהשיחה ויעביר את המשתמש לשימת אזהרה, ולאחר מספר פעמים שהדבר חוזר על עצמו בזמן נתון, למשל שעה השרת יזהה את המשתמש כתוקף
- SQL INJECTION - Using regex detect SQL inside of certain requests and block them, it should include a whitelist of endpoints that would be ignored for the detection.
- XSS INJECTION - Replace html symbols with the special thingies (for example replace > with &gt)
- DIRECTORY TRAVERSAL - search for symbols that show directory traversal such as .. inside of link
- SSRF - make server request local URL with high previliges (for example https://127.0.0.1/admin) - Filter local URLs + blacklist of certain url endings
- HTTP Request Smuggling - A way to "smuggle" parts of a request through a front end proxy - check if a request has both of the problematic headers (content-length and transfer-encoding).
- Malicous file upload - Upload each file sent to virustotal.
- XXE - regex to check for xml

Ideas:
- connecting many servers to the same reverse proxy
- creating the server to protect