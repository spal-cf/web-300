#!/usr/bin/env python3

import argparse
import requests
 
parser = argparse.ArgumentParser()
parser.add_argument('-a','--actionlist', help='actionlist to use')
parser.add_argument('-t','--target', help='host/ip to target', required=True)
parser.add_argument('-w','--wordlist', help='wordlist to use')
args = parser.parse_args()
 
actions = []
 
with open(args.actionlist, "r") as a :
    for line in a:
        try:
            actions.append(line.strip())
        except:
            print("Exception occurred")
 
print("Path             - \tGet\tPost")
 
with open(args.wordlist, "r") as f:
    for word in f:
        for action in actions:
            print('\r/{word}/{action}'.format(word=word.strip(), action=action), end='')
            url = "FIX ME".format(target=args.target, word=word.strip(), action=action)
            r_get = requests.get(url=url).status_code
            r_post = requests.post(url = url).status_code
 
            if(r_get not in ['FIX ME'] or r_post not in ['FIX ME']):
                print(' \r', end='')
                print("/{word}/{action:10} - \t{get}\t{post}".format(word=word.strip(), action=action, get=r_get, post=r_post))
 
print('\r', end='')
print("Wordlist complete. Goodbye.")