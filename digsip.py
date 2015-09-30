__author__ = 'Jared Evans'

import argparse
import re
import dns.e164
import dns.query
import dns.message

def digsip(dns_server, phone_number):

   n = dns.e164.from_e164(phone_number, None).to_text()
   e164 = n + ".1.itrs.us"

   print "\nSending queries to DNS server: ", dns_server 
   print "\n ---Looking up NATPR record for ====>> ", e164
   print "=======================================================================\n"
   q = dns.message.make_query(e164, "NAPTR")
   naptr_results = dns.query.udp(q, dns_server)
   results = naptr_results.answer

   print "======================================================================="
   for res in results :
	print res;
   print "=======================================================================\n"

   for res in results :
       sipdomainres = re.search( r'!sip:\\\\1@(.*)!',res.to_text(), re.M|re.I)

   if (sipdomainres) :
     sipdomain = sipdomainres.group(1)
     print "SIP domain: ", sipdomain
   else :
     print "There is no SIP iTRS entry... exiting!\n\n"
     exit(0)

   q = dns.message.make_query(sipdomain, "NAPTR")
   naptr_results = dns.query.udp(q, dns_server)
   for res in naptr_results.answer :
       siptcpres = re.search( r'(_sip._tcp.*).',res.to_text(), re.M|re.I)

   siptcpserver = siptcpres.group(1)
   print "Found NAPTR record for SIP TCP: ", siptcpserver
   print "=======================================================================\n"
   print " ---Looking up SRV record now."

   q = dns.message.make_query(siptcpserver, "SRV")
   srv_results = dns.query.udp(q, dns_server)
   for res in srv_results.answer :
       port = res.to_text().split(" ")[6]
       sipserverres = re.search( r' ([a-z0-9.]*)$',res.to_text(), re.M|re.I)

   sipserver = sipserverres.group(1)
   print "Found SIP server: ", sipserver , " on port ", port

   q = dns.message.make_query(sipserver, "A")
   a_results = dns.query.udp(q, dns_server)
   for res in a_results.answer :
       asipserverres = re.search( r' ([a-z0-9.]*)$',res.to_text(), re.M|re.I)

   asipserver = asipserverres.group(1)
   print "SIP Invite should be sent to IP address: ", asipserver

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Look up SIP phone number")
    parser.add_argument("-d" , "--dnsserver", default=["replace this with your default DNS server"], nargs=1, help="DNS server to contact")
    parser.add_argument("-p" , "--phonenumber", default=["replace this with default phone number"], nargs=1, help="Phone number to look up")
    args = parser.parse_args()
    digsip(args.dnsserver[0], args.phonenumber[0])
