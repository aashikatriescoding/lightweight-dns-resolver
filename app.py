import socket #low level networking interfaces
import time  #cache expiration
from flask import Flask, render_template, request, jsonify  # render html
import dns.message
import dns.rdatatype  #record type
import dns.flags
import dns.query
import dns.resolver

app = Flask(__name__)#initializes web app

class DNSCache:  

    def __init__(self):
        self.cache = {} #stores cached dns record  in a dictionary
        self.max_cache_size = 1000 #max items in cachee
        self.default_ttl = 300   #ttl def in secs
    

    #uses fifo for cache clesarin
    def _clean_cache(self):  #removes expired entries from cachee
        current_time = time.time()
        expired_keys = [k for k, v in self.cache.items() if v['expires'] <= current_time] 
        for key in expired_keys:
            del self.cache[key] #deletes expired keys

        #if cache is too full remove least rececntly exp entries
        if len(self.cache) > self.max_cache_size:
            #sorts by expiration time 
            sorted_items = sorted(self.cache.items(), key=lambda x: x[1]['expires'])
            # Calculate how many to remove
            for key, _ in sorted_items[:len(self.cache) - self.max_cache_size]: # _ is for ignoring the dns records; values since we only need expiration
                del self.cache[key]

    #if found in cache, get from cached result
    def get(self, domain, record_type):
        self._clean_cache() #clean expired
        key = f"{domain.lower()}_{record_type}" #eg: google.com_A
        return self.cache.get(key, None)
    
    #saves the latest entry to cache
    def set(self, domain, record_type, records, ttl=None):
        self._clean_cache()
        key = f"{domain.lower()}_{record_type}"
        ttl = ttl if ttl is not None else self.default_ttl
        self.cache[key] = {
            'records': records,
            'expires': time.time() + ttl,
            'timestamp': time.time()
        }

#creates an instance of the cache
dns_cache = DNSCache()

RECORD_TYPES = {
    'A': dns.rdatatype.A,
    'AAAA': dns.rdatatype.AAAA,
    'CNAME': dns.rdatatype.CNAME,
    'MX': dns.rdatatype.MX, 
    'NS': dns.rdatatype.NS
}

#dns resolutionn
def resolve_dns(domain, record_type='A', dns_server='8.8.8.8'):
    
    record_type = record_type.upper()
    
    # Check cache first, if present, return it.
    cached = dns_cache.get(domain, record_type)
    if cached:
        return {'results': cached['records'], 'cached': True, 'ttl': int(cached['expires'] - time.time())}
    
    try:
        # For MX/NS records, try both the exact domain and the base domain
        if record_type in ['MX', 'NS']:
            base_domain = extract_base_domain(domain)
            domains_to_try = [domain, base_domain] if domain != base_domain else [domain]
        else:
            domains_to_try = [domain]
        
        results = [] #collects dns resultrd
        ttl = None 
        
        for current_domain in domains_to_try:
            try:
                # Create DNS query
                query = dns.message.make_query(current_domain, RECORD_TYPES[record_type])
                query.use_edns(0, 0, 4096)  # Removed DNSSEC flag , for lesser use of tcp (512 bytes)
                
                # Try UDP first, then TCP if needed
                try:
                    response = dns.query.udp(query, dns_server, timeout=2)
                    if response.flags & dns.flags.TC: # response too big for udp, timeout
                        response = dns.query.tcp(query, dns_server, timeout=5)
                except dns.exception.Timeout:
                    response = dns.query.tcp(query, dns_server, timeout=5)
                
                # Process response
                for rrset in response.answer: #resource record set
                    for record in rrset:
                        if record.rdtype == RECORD_TYPES[record_type]:
                            if record_type == 'A':
                                results.append(f"A Record: {record.address}")
                                ttl = rrset.ttl
                            elif record_type == 'AAAA':
                                results.append(f"AAAA Record: {record.address}")
                                ttl = rrset.ttl
                            elif record_type == 'CNAME':
                                results.append(f"CNAME Record: {record.target.to_text()}")
                                ttl = rrset.ttl
                            elif record_type == 'MX':
                                results.append(f"MX Record: {record.exchange.to_text()} (Preference: {record.preference})")
                                ttl = rrset.ttl
                            elif record_type == 'NS':
                                results.append(f"NS Record: {record.target.to_text()}")
                                ttl = rrset.ttl
            
            except dns.resolver.NoAnswer:
                continue   # No records found
            except dns.exception.DNSException as e:
                continue     #dns specfic error
        
        if not results:
            return {'error': f'No {record_type} records found for {domain}'}
        
        # Cache the results
        if ttl is not None:
            dns_cache.set(domain, record_type, results, ttl)
        
        return {
            'results': results,
            'cached': False,
            'ttl': ttl
        }
    
    except dns.exception.DNSException as e:
        return {'error': f'DNS error: {str(e)}'}
    except Exception as e:
        return {'error': f'Unexpected error: {str(e)}'}

def extract_base_domain(domain):
    """Extract base domain by removing subdomains"""
    parts = domain.split('.')
    if len(parts) > 2:
        return '.'.join(parts[-2:])   # Returns last two parts (e.g., 'google.com')
    return domain

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/resolve', methods=['POST'])
def resolve():
    data = request.json
    domain = data.get('domain', '').strip()
    record_type = data.get('type', 'A').upper()
    
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    # Validate record type
    if record_type not in RECORD_TYPES:
        return jsonify({'error': f'Unsupported record type: {record_type}'}), 400
    
    result = resolve_dns(domain, record_type)
    
    if 'error' in result:
        return jsonify({'error': result['error']}), 400
    
    return jsonify({
        'domain': domain,
        'type': record_type,
        'results': result['results'],
        'cached': result.get('cached', False),
        'ttl': result.get('ttl', 0)
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
