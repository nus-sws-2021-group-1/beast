from scapy.layers.tls.automaton_srv import *
# runs an echo service with TLSv1 support and prefers a CBC cipher suite
t = TLSServerAutomaton(server='10.9.0.3', mycert='server_cert.pem', mykey='server_key.pem', sport=443, preferred_ciphersuite=49171)
t.run()