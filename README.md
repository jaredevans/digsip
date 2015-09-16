<h2>Resolving the SIP Proxy&nbsp;for a SIP phone number</h2>
<p><strong>Target audience:</strong> Engineers in the FCC VRS industry</p>
<p><strong>Purpose:</strong>&nbsp;Querying FCC iTRS to look up&nbsp;NAPTR and SRV records for&nbsp;"SIP phone number to IP address"&nbsp;resolution</p>
<p>This script automates the process of resolving a SIP phone number to the IP address of a SIP proxy server, where the SIP INVITE should be sent.</p>
<p>Requires installing python module: dnspython</p>
<p>To run it:</p>
<p>digsip.py -d yourdnsserver -p phonenumber</p>
