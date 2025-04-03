<h2>Flask honeypot idea server</h2>
<p>
No actualy honeypot is yet made. But a simple DDOS protection service is made in <b>security.py</b> file.
</p>
<p>
Current filters for blacklist are:
- Over 20 get/post request / second
- IP is then added to blacklist.txt file and flask checks the ip before serving a website
</p>