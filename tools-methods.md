#### Interacting with Web Listeners using Python


#### Managed .NET Code

##### Source Code Recovery

xfreerdp +nego +sec-rdp +sec-tls +sec-nla /d: /u: /p: /v:dnn /u:administrator /p:studentlab /size:1180x708


Note: Depending on our version of FreeRDP, we might receive an ERRCONNECT_TLS_CONNECT_FAILED message when attempting to connect to the DNN machine. If so, we need to append /tls-seclevel:0 to the end of our command to allow for any TLS level on our connection.

Test.cs
```
using System;
namespace dotnetapp
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("What is your favourite Web Application Language?");
            String answer = Console.ReadLine();
            Console.WriteLine("Your answer was: " + answer + "\r\n");
        }
    }
}
```

Compile:
c:\Users\Administrator\Desktop>C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe test.cs

csc.exe test.cs

dnSpy tool for decompiling C# code

```
1
(DNN Corp., 2020),  https://www.dnnsoftware.com/ ↩︎
2
(0xd4d, 2020),  https://github.com/0xd4d/dnSpy ↩︎
3
(ICSharpCode , 2020),  https://github.com/icsharpcode/ILSpy ↩︎
4
(MicroSoft, 2021),  https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/compiler-options/command-line-building-with-csc-exe ↩︎
5
(Wikipedia, 2021),  https://en.wikipedia.org/wiki/Cross-reference ↩︎
6
(Wikipedia, 2019),  https://en.wikipedia.org/wiki/Breakpoint ↩︎
```

#### Decompiling Java Classes

JD-GUI

Mkdir JAR; cd JAR;

Test.java
```
import java.util.*;
public class test{
	public static void main(String[] args){
		Scanner scanner = new Scanner(System.in);
		System.out.println("What is your favorite Web Application Language?");
		String answer = scanner.nextLine();
		System.out.println("Your answer was: " + answer);
	}
}
```

Note:
For this section, we will need a Java Development Kit (JDK) to compile the Java source. If it is not already installed, we can install it in Kali with "sudo apt install default-jdk".

```
javac -source 1.8 -target 1.8 test.java

mkdir META-INF
echo "Main-Class: test" > META-INF/MANIFEST.MF


jar cmvf META-INF/MANIFEST.MF test.jar test.class

java -jar test.jar
Java
```

One easy way to transfer files is via SMB with an Impacket script. In our JAR directory, we will issue the following command:
```
/JAR$ sudo impacket-smbserver test .

Or

/JAR$ sudo impacket-smbserver -smb2support test .
```
RDP to windows box:
```
xfreerdp +nego +sec-rdp +sec-tls +sec-nla /d: /u: /p: /v:manageengine /u:administrator /p:studentlab /size:1180x708 /tls-seclevel:0 
```

we'll use Windows Explorer to navigate to our Kali SMB server using the \\your-kali-machine-ip\test path. We'll then copy test.jar to the desktop of the ManageEngine virtual machine. Finally, we can open JD-GUI using the taskbar shortcut and drag our JAR file on its window.


#### Using an IDE

Visual Studio Code

```
1
(Wikipedia, 2021), https://en.wikipedia.org/wiki/Integrated_development_environment ↩︎

2
(Microsoft, 2022), https://code.visualstudio.com/ ↩︎

3
(Wikipedia, 2021), https://en.wikipedia.org/wiki/False_positives_and_false_negatives ↩︎
```
##### HTTP Routing Patterns

File System Routing maps the URL of a request to a file on the server's filesystem.
if we request http://example.com/funnyCats.html, the server would serve the file located at /var/www/html/funnyCats.html.

Some Java applications use Servlet Mappings to control how the application handles HTTP requests. 
A web.xml file stores the HTTP routing configuration. While there can be multiple entries in a web.xml file, each route is made up of two entries: one entry to define a servlet and a second entry to map a URL to a servlet.

```
<!-- SubscriptionHandler-->
<servlet id="SubscriptionHandler">
  <servlet-name>SubscriptionHandler</servlet-name>
  <servlet-class>org.opencrx.kernel.workflow.servlet.SubscriptionHandlerServlet</servlet-class>
	</servlet>
...
<servlet-mapping>
  <servlet-name>SubscriptionHandler</servlet-name>
	<url-pattern>/SubscriptionHandler/*</url-pattern>
</servlet-mapping>

```



Some programming languages and frameworks include routing information directly in the source code. For example, ExpressJS uses this method of routing:
```
var express = require('express');
var router = express.Router();
...

router.get('/login', function(req, res, next) {
  res.render('login', { title: 'Login' });
});
```
Listing 16 - Example Express.js routing From DocEdit

A variant of this approach is routing by annotation or attribute. The Spring MVC2 framework for Java and the Flask3 framework for Python, among others, use this approach. The source code declares an annotation or attribute next to the method or function that handles the HTTP request.

```
@GetMapping({"/admin/users"})
public String getUsersPage(HttpServletRequest req, Model model, HttpServletResponse res) {
...
```
Listing 17 - Example Spring MVC annotation

```
1
(Apache Software Foundation, 2020), https://httpd.apache.org/docs/2.4/urlmapping.html ↩︎

2
(Spring, 2016), https://docs.spring.io/spring-framework/docs/3.2.x/spring-framework-reference/html/mvc.html#mvc-controller ↩︎

3
(Pallets, 2010), https://flask.palletsprojects.com/en/1.1.x/quickstart/#routing ↩︎
```

##### Debugging

We will need to install two plugins: the RedHat Language Support for Java1 and the Microsoft Debugger for Java.2

We will create a new directory named debug and create DebuggerTest.java

```
import java.util.Random;
import java.util.Scanner;

public class DebuggerTest {

  private static Random random = new Random();
  public static void main(String[] args){
    int num = generateRandomNumber();
		Scanner scanner = new Scanner(System.in);
		System.out.println("Guess a number between 1 and 100.");
		try{
      int answer = scanner.nextInt();
      scanner.close();
      System.out.println("Your guess was: " + answer);
      if(answer == num) {
        System.out.println("You are correct!");
      } else {
        System.out.println("Incorrect. The answer was " + num);
      }
    } catch(Exception e) {
      System.out.println("That's not a number.");
    } finally {
      scanner.close();
    }
    System.exit(0);
  }

  public static int generateRandomNumber() {
    return random.nextInt(100)+1;
  }
}
```

```
1
(Microsoft, 2022), https://marketplace.visualstudio.com/items?itemName=redhat.java ↩︎

2
(Microsoft, 2022), https://marketplace.visualstudio.com/items?itemName=vscjava.vscode-java-debug ↩︎
```


Let's add the dependencies to VS Code. We can extract them from the JAR file. The @SpringBootApplication annotation in NumberGameApplication.java indicates this is a Spring Boot application. We can find the dependencies in /BOOT-INF/lib/ inside the JAR file. VS Code should automatically import the dependencies if we place them in a lib directory inside the NumberGame directory.

```
unzip -j NumberGame.jar "BOOT-INF/lib/*" -d NumberGame/lib/
```
After a few moments, launch.json should open in an Editor window. If the Editor window does not open, we can find the new file in the .vscode directory. We can ignore the default configurations. We will create a new configuration for remote debugging by clicking Add Configuration... and then Java: Attach to Remote Program on the pop-up menu.

We need to update the "hostName" value to "127.0.0.1" and the "port" value to 9898. We'll then save the changes.

java -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=9898 -jar NumberGame.jar

```
1
(Oracle, 2021), https://docs.oracle.com/javase/8/docs/technotes/guides/jpda/conninv.html#Invocation ↩︎


```


