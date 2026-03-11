---
title: "DVWA - XSS (DOM)"
date: 2026-03-05 10:00:00 +0800
categories: [Labs, DVWA]
tags: [RedTeam, WebSecurity]
image:
  path: /assets/images/posts/dvwa/dvwa.png
  alt: DVWA
---



### **Introduction**

Damn Vulnerable Web Application (DVWA) is a PHP/MySQL web application designed for security professionals and students to test their skills in a legal environment. This writeup documents the DOM-Based Cross-Site Scripting (XSS) challenge, exploring how security protections evolve across three difficulty levels—and how client-side vulnerabilities can persist even when server-side defenses appear robust.

### **About the Vulnerability**
DOM-Based XSS differs from reflected or stored XSS in a critical way: the payload never reaches the server. Instead, the attack occurs entirely in the browser, where client-side JavaScript reads data from the URL (or other browser-accessible sources) and injects it into the page without proper sanitization.

In this challenge, the application accepts a language preference through a default URL parameter. A client-side script reads this value and dynamically builds a dropdown menu using document.write(). As we'll see, how the server handles this parameter—and how the client trusts it—creates opportunities for exploitation.



### **Security: Low**

> Low level will not check the requested input, before including it to be used in the output text.

``` php
<?php

# No protections, anything goes

?>
```

1) Examining the URL reveals a parameter named ``default``:
![image.png](/assets/images/posts/dvwa/xss-dom/2.png)


2) To identify potential XSS vulnerabilities, we can inject a basic proof-of-concept payload such as:

``` js
 <script>alert('XSS')</script>
```

![image.png](/assets/images/posts/dvwa/xss-dom/1.png)




### **Security: Medium**

> "The developer implemented a filter that checks for the string <script (case-insensitive) using stripos(). If detected, the page redirects to a safe default value:"


``` js

<?php

// Is there any input?
if ( array_key_exists( "default", $_GET ) && !is_null ($_GET[ 'default' ]) ) {
    $default = $_GET['default'];
    
    # Do not allow script tags
    if (stripos ($default, "<script") !== false) {
        header ("location: ?default=English");
        exit;
    }
}

?>
```

1) The developer upgraded from simple detection to active replacement. However, we can adapt with an SVG payload that doesn't contain <script:

List Payload 


``` js
<svg/onload=alert`INJECTX`>
```

![image.png](/assets/images/posts/dvwa/xss-dom/3.png)







### **Security: High**

> The developer implemented a whitelist that only allows specific languages

``` js
<?php

// Is there any input?
if ( array_key_exists( "default", $_GET ) && !is_null ($_GET[ 'default' ]) ) {

    # White list the allowable languages
    switch ($_GET['default']) {
        case "French":
        case "English":
        case "German":
        case "Spanish":
            # ok
            break;
        default:
            header ("location: ?default=English");
            exit;
    }
}

?>
```

> The app uses strict input handling with advanced filtering and a whitelist of allowed languages, forcing attackers to attempt client‑side execution without sending malicious input to the server

``` js
#default=<script>alert(document.cookie)</script>
```

![image.png](/assets/images/posts/dvwa/xss-dom/4.png)



**Why this works:**

- The # symbol is key - Everything after # (the fragment) stays in the browser and never goes to the server. This completely bypasses the whitelist!

- The JavaScript is blind to the difference - When the client-side code reads document.location.href, it sees the entire URL including the fragment. It extracts our malicious script.

- No validation on the client - The extracted value is directly inserted into the page using document.write() without any sanitization.

- The browser does its job - Seeing <script> tags in the HTML, the browser executes them.

Result: Alert box fires, proving the application is still vulnerable to XSS through client-side code, even with perfect server-side validation."