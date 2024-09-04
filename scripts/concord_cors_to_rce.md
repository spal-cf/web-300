Concord Authentication Bypass to RCE
=======

## Commands

**Fetch cfg.js**

```
fetch("http://concord:8001/cfg.js")
    .then(function (response) {
        return response.text();
    })
    .then(function (text) {
        console.log(text);
    })
```

**Fetch example.com**

```
fetch("http://example.com")
   .then(function (response) {
       return response.text();
   })
   .then(function (text) {
       console.log(text);
   })
```

**Fetch example.com - POST - Standard**

```
fetch("http://example.com",
   {
       method: 'post',
       headers: {
           "Content-type": "application/x-www-form-urlencoded;"
       }
   })
```

**Fetch example.com - POST - JSON**

```
fetch("http://example.com",
   {
       method: 'post',
       headers: {
           "Content-type": "application/json;"
       }
   })
```

**Fetch CORS-test - POST - JSON**

```
fetch("http://cors-test.appspot.com/test",
   {
       method: 'post',
       headers: {
           "Content-type": "application/json;"
       }
   })
```

**Rsync New Version**

```
rsync -az student@concord:/home/student/concord-1.83.0/ concord/
```


## Downloads
[index.html - CORS to RCE - Groovy](index-rce_html.txt)
[index.html - CORS to RCE - Python](index-rce-python_html.txt)
[index.html - CORS to RCE - Ruby](index-rce-ruby_html.txt)

## Exercises

### 12.3 Exercise #5

Below we have provide an encrypted value. This value was encrypted using the OffSec org and the AWAE project in Concord 1.43.0. Using a Concord process, decrypt this value.

Encrypted Value:

```
vyblrnt+hP8GNVOfSl9WXgGcQZceBhOmcyhQ0alyX6Rs5ozQbEvChU9K7FWSe7cf
```