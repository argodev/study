# Web Site Exploitation

## BurpSuite

## OWASP Zed Attack Proxy (ZAP)
https://owasp.org/www-project-zap/

https://www.zaproxy.org/getting-started/ 

Helpful:

> Software security testing is the process of assessing and testing a system to discover security risks and vulnerabilities of the system and its data. There is no universal terminology but for our purposes, we define assessments as the analysis and discovery of vulnerabilities without attempting to actually exploit those vulnerabilities. We define testing as the discovery and attempted exploitation of vulnerabilities.
https://www.zaproxy.org/getting-started/


this looks helpful

https://www.zaproxy.org/zap-deep-dive/

a tool for finding vulnerabilities in web application projects

Dynamic application security testing tool (DAST)... *not* a static analyzer



``` sh
# automatically listening on port 8080
./zap.sh -daemon

# scan via the cmdline
./zap.sh -cmd -quickurl http://localhost:8080/bodgeit -quickprogress



```
