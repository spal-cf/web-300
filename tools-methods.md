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
xfreerdp +nego +sec-rdp +sec-tls +sec-nla /d: /u: /p: /v:manageengine /u:administrator /p:studentlab /size:1180x708
```

we'll use Windows Explorer to navigate to our Kali SMB server using the \\your-kali-machine-ip\test path. We'll then copy test.jar to the desktop of the ManageEngine virtual machine. Finally, we can open JD-GUI using the taskbar shortcut and drag our JAR file on its window.


