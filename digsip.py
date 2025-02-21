#!/usr/bin/env python3
import argparse
import re
import logging
import dns.e164
import dns.query
import dns.message

# Configure logging for debug and info output
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

def lookup_dns_record(query_name, record_type, dns_server):
    """
    Perform a DNS query for a given record type.
    Returns the answer section (list of rrsets) or None if not found.
    """
    try:
        query = dns.message.make_query(query_name, record_type)
        response = dns.query.udp(query, dns_server)
        if not response.answer:
            logging.warning(f"No {record_type} record found for {query_name}")
            return None
        return response.answer
    except Exception as e:
        logging.error(f"DNS query for {query_name} ({record_type}) failed: {e}")
        return None

def extract_sip_domain_from_naptr(naptr_answers):
    """
    Extract the SIP domain from NAPTR records.
    This function looks for a regexp field matching a pattern like: !sip:\1@<domain>!
    """
    pattern = re.compile(r'!sip:\\\\1@(.*)!', re.IGNORECASE)
    for rrset in naptr_answers:
        for record in rrset:
            if record.regexp:
                match = pattern.search(record.regexp)
                if match:
                    return match.group(1)
    return None

def extract_sip_tcp_record_from_naptr(naptr_answers):
    """
    Extract the SIP TCP server record from NAPTR records.
    First, try to match a regexp pattern; if not available, fall back on the replacement field.
    """
    # Look for a pattern like _sip._tcp.domain.tld
    pattern = re.compile(r'(_sip\._tcp\.[^.]+\.[^\s]+)', re.IGNORECASE)
    for rrset in naptr_answers:
        for record in rrset:
            if record.regexp:
                match = pattern.search(record.regexp)
                if match:
                    return match.group(1)
            # Alternatively, check if the replacement field is set and valid.
            if record.replacement and record.replacement != b'.':
                repl = record.replacement.to_text().rstrip('.')
                if '_sip._tcp' in repl:
                    return repl
    return None

def lookup_srv_record(srv_name, dns_server):
    """
    Lookup SRV record and return a tuple (target, port) or (None, None) if not found.
    """
    srv_answers = lookup_dns_record(srv_name, "SRV", dns_server)
    if not srv_answers:
        return None, None
    # Return the first SRV record's target and port
    for rrset in srv_answers:
        for srv in rrset:
            target = str(srv.target).rstrip('.')
            return target, srv.port
    return None, None

def lookup_a_record(domain, dns_server):
    """
    Lookup A record and return the IP address as a string.
    """
    a_answers = lookup_dns_record(domain, "A", dns_server)
    if not a_answers:
        return None
    for rrset in a_answers:
        for a in rrset:
            return a.address
    return None

def digsip(dns_server, phone_number, domain_suffix="1.itrs.us"):
    """
    Resolve a SIP phone number to the IP address of a SIP proxy server.
    
    Steps:
      1. Convert the phone number to E.164 text and append a configurable domain suffix.
      2. Look up the NAPTR record for this E.164 name.
      3. Extract the SIP domain from the NAPTR record.
      4. Query the SIP domain for another NAPTR record to extract the SIP TCP record.
      5. Lookup the corresponding SRV record to find the SIP server target and port.
      6. Finally, resolve the SIP server's A record to get its IP address.
    """
    try:
        e164_text = dns.e164.from_e164(phone_number, None).to_text()
    except Exception as e:
        logging.error(f"Error converting phone number to E.164 format: {e}")
        return

    query_name = f"{e164_text}.{domain_suffix}"
    logging.info(f"Querying DNS server {dns_server} for NAPTR records for {query_name}")

    naptr_answers = lookup_dns_record(query_name, "NAPTR", dns_server)
    if not naptr_answers:
        logging.error("No NAPTR records found for the initial query.")
        return

    sip_domain = extract_sip_domain_from_naptr(naptr_answers)
    if not sip_domain:
        logging.error("No SIP domain found in the NAPTR records. Exiting.")
        return
    logging.info(f"Extracted SIP domain: {sip_domain}")

    # Lookup NAPTR records for the SIP domain to get the SIP TCP record.
    naptr_sip_tcp = lookup_dns_record(sip_domain, "NAPTR", dns_server)
    if not naptr_sip_tcp:
        logging.error(f"No NAPTR records found for SIP domain: {sip_domain}")
        return
    sip_tcp_record = extract_sip_tcp_record_from_naptr(naptr_sip_tcp)
    if not sip_tcp_record:
        logging.error("No SIP TCP record found in the NAPTR records.")
        return
    logging.info(f"Extracted SIP TCP record: {sip_tcp_record}")

    # Lookup SRV record for the SIP TCP record.
    logging.info(f"Querying SRV record for {sip_tcp_record}")
    sip_server, port = lookup_srv_record(sip_tcp_record, dns_server)
    if not sip_server or not port:
        logging.error("Failed to retrieve SRV record for the SIP server.")
        return
    logging.info(f"Found SIP server {sip_server} on port {port}")

    # Lookup A record for the SIP server to get the IP address.
    ip_address = lookup_a_record(sip_server, dns_server)
    if not ip_address:
        logging.error("Failed to retrieve A record for the SIP server.")
        return
    logging.info(f"SIP Invite should be sent to IP address: {ip_address}")

def main():
    parser = argparse.ArgumentParser(description="Look up SIP phone number")
    parser.add_argument("-d", "--dnsserver", required=True, help="DNS server to contact")
    parser.add_argument("-p", "--phonenumber", required=True, help="Phone number to look up")
    parser.add_argument("--domainsuffix", default="1.itrs.us", help="Domain suffix for E164 conversion")
    args = parser.parse_args()
    digsip(args.dnsserver, args.phonenumber, args.domainsuffix)

if __name__ == "__main__":
    main()

