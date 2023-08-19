# Lab

## Tool : Burp Suite

## Retrieving hidden data

### Lab: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

#### source : <https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data>

* To solve the lab, perform a SQL injection attack that causes the application to display one or more unreleased products.

Solution:

We have a url like this "filter?category=Clothing,+shoes+and+accessories"

The query is **SELECT * FROM products WHERE category = 'Clothing, shoes and accessories' AND released = 1** to retrieve hidden data, you need to change **released** to 0 or remove it as a comment.

We have a payload `?category=Clothing,+shoes+and+accessories'+OR+1=1--`. ***Since 1=1 is always true, the query will return all items.*** Firstly, I try with payload **?category=Clothing,+shoes+and+accessories'--**, it only displays a unreleased data, not all of it, so I fail.

## Subverting application logic

### Lab: SQL injection vulnerability allowing login bypass

#### source : <https://portswigger.net/web-security/sql-injection/lab-login-bypass>

* To solve the lab, perform a SQL injection attack that logs in to the application as the administrator user.

Solution:

Login with the username **administrator'--** and with anything as a password.
We have a payload as `username=administrator'--&password=123**.`
Because of the SQL comment **--**. It removes the query password from the original query.

## Retrieving data from other database tables

 **Requirements** : For a UNION query to work, two key requirements must be met:

* The individual queries must return the same number of columns.
* The data types in each column must be compatible between the individual queries.

**Determination**:

* How many columns are being returned from the original query?
* Which columns returned from the original query are of a suitable data type to hold the results from the injected query?

### Determining the number of columns required in a SQL injection UNION attack

#### Lab: SQL injection UNION attack, determining the number of columns returned by the query

##### source : <https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns>

* To solve the lab, determine the number of columns returned by the query by performing a SQL injection UNION attack that returns an additional row containing null values.

Solution:

The required topic returns an additional row containing null values, so we need to use **a series of UNION SELECT payloads**.

By default, we have three columns returned. We have a payload as `?category=Accessories+UNION+SELECT+NULL,NULL,NULL--`, and the result is returned as **Accessories' UNION SELECT NULL,NULL,NULL--**. Ok, we have completed it.

### Finding columns with a useful data type in a SQL injection UNION attack

#### Lab: SQL injection UNION attack, finding a column containing text

##### source: <https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text>

* To solve the lab, perform a SQL injection UNION attack that returns an additional row containing the value provided.

Require:

* The lab will provide a random value that you need to make appear within the query results.

Solution:

The first, as seen in the lab above, returns three columns.
We have a payload `'+UNION+SELECT+NULL,'*random value*',NULL--` to test which column contains available string data. And we have completed it.

### Using a SQL injection UNION attack to retrieve interesting data

#### Lab: SQL injection UNION attack, retrieving data from other tables

##### souce: <https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables>

* To solve the lab, perform a SQL injection UNION attack that retrieves all usernames and passwords, and use the information to log in as the administrator user.

Solution:

As to the above mention, we try to retrieve all usernames and passwords in a table called users, so we have a payload as `'+UNION+SELECT+username,+password+FROM+users--`. After that, we have the username and password as *administrator* and *54zidtfu6c3sxubn2wq3*.
Login again and complete the lab.

### Retrieving multiple values within a single column

#### Lab: SQL injection UNION attack, retrieving multiple values in a single column

##### source: <https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-multiple-values-in-single-column>

* To solve the lab, perform a SQL injection UNION attack that retrieves all usernames and passwords, and use the information to log in as the administrator user.

Solution:

As a solution above, we have to retrieve all usernames and passwords in a table called users.
Firstly, I test with payload as `+UNION+SELECT+username,+password+FROM+users--` but it is an error. And I think this is the final lab, so it isn't easy. I started to determine the number of columns in table **users** by payload as `+UNION+SELECT+NULL,NULL+FROM+users--`. It returned two columns—okay, two columns; each column is username and password. Hmm, it isn't true after testing the payload as `+UNION+SELECT+NULL,'a'+FROM+users--`. Only the second column is a string. That is an issue. Because of the first comlunm, I don't know about the data type of it, so my payload is to take NULL in this position, and the second comlunm is to be used to take username and password. Finally, payload as `'+UNION+SELECT+NULL,username+||+'~'+||+password+FROM+users--`. Login again and complete it.
> || or concatenation operator is use to link columns or character strings.

## Examining the database

### Querying the database type and version

#### Lab: SQL injection attack, querying the database type and version on Oracle

##### source: <https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-oracle>

* To solve the lab, display the database version string.

Solution:

As mentioned above, the database is Oracle, so we have the payload as `'+UNION+SELECT+*+FROM+v$version`. And I haven't realized that my payload has been issued. I modified it as `"+UNION+SELECT+*+FROM+v$version`. I started stuck with it **'** and **"**. When I use **"**, no errors are displayed, so after trying so much different with **"** payload, I can't find the cause. I try to check the solution and realize that columns have to be checked and problems with quotes. Let's start again.

Check columns and data type in each column in table **v$version** with payload as `'+UNION+SELECT+NULL,NULL+FROM+v$version--`. It has two columns, and all is string data, so we have two payloads: `'+UNION+SELECT+NULL,+banner+FROM+v$version--` or `'+UNION+SELECT+banner,+NULL+FROM+v$version--`. Outputs were slightly different, but all completed the task.

#### Lab: SQL injection attack, querying the database type and version on MySQL and Microsoft

##### source: <https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft>

* To solve the lab, display the database version string.

Solution:

As mentioned above, the database is MySQL and Microsoft, and we have experience from the above lab, so we have the payload as `'+UNION+SELECT+NULL,NULL--`. Again, I am stuck. I try trying so much as `'+UNION+SELECT+NULL,NULL,NULL--`, `'+UNION+SELECT+NULL,NULL--` *with the space after the double dash*, but it still fails. I realized that double dashes are blocked, but I still tried with them. Simply, it is changed from **--** to **#**. Finally, payload is `'+UNION+SELECT+@@version,+NULL#`. I still saw a solution to realize that. Fu**!!!

### Listing the contents of the database

#### Lab: SQL injection attack, listing the database contents on non-Oracle databases

##### source: <https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle>

* To solve the lab, log in as the administrator user.

Solution:

First, I tested with payload as `'+UNION+SELECT+*+FROM+information_schema.tables`, it failed. After relaxing, I realized that the requirements for **Retrieving data from other database tables** are so important. It said that **The individual queries must return the same number of columns.**. That is why we always check the columns returned. Okay, continues. After checking colunms, which returned two colunms with string data. I have accepted that the lab is difficult; I lost so much time trying to solve it. I have a payload to retrieve the name of the table as `'+UNION+SELECT+TABLE_NAME,NULL+FROM+information_schema.tables--`. Because we have two columns, we can't use \*. F!!!, so many tables are there. I lost about an hour and can't find it. I saw the solution to find the table name, and oh wow, it said *Find the name of the table containing user credentials.*. They didn't disclose the table name. After I searched Google to find the table name, their names were slightly different, but I could save my time. As time continues, we need to notice **The data types in each column must be compatible between the individual queries.**. So I have payload as `'+UNION+SELECT+COLUMN_NAME,+DATA_TYPE+FROM+information_schema.columns+WHERE+table_name+=+'users_zfmbzy'--` and `'+UNION+SELECT+username_qwfbhp,+password_jqavlf+FROM+users_zfmbzy--`. Finally, I found it *administrator* and *asmohymintc55i28bkf6*. Nice lab, but also so difficult.

### Equivalent to information schema on Oracle

#### Lab: SQL injection attack, listing the database contents on Oracle

##### source: <https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-oracle>

* To solve the lab, log in as the administrator user.

Solution:

Reusing the experience above, we have a payload to list table names as `'+UNION+SELECT+TABLE_NAME,NULL+FROM+all_tables--`. After we have payload as `'+UNION+SELECT+COLUMN_NAME,DATA_TYPE+FROM+all_tab_columns+WHERE+TABLE_NAME+=+'USERS_TTAZON'--` and `'+UNION+SELECT+PASSWORD_DACSDY,USERNAME_XICVMM+FROM+USERS_TTAZON--`. Finally, we get *administrator* and *vbp1uh0zrpdgrquanuih*

## Blind SQL injection

### Exploiting blind SQL injection by triggering conditional responses

#### Lab: Blind SQL injection with conditional responses

##### source: <https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses>

* To solve the lab, log in as the administrator user.

Solution:

Firstly, I tried to inject SQL in *category* but it failed. It always displays *Welcome back* but fails to meet the conditions. I glance at the solution and realize that, oh, it has two queries in here. One in *category* and two in *TrackingId*. And check again with fail conditions in *TrackingId*. Nice, *Welcome back* is disappeared. I saw the hint and knew that all characters are lower case. That is good for me because it saves time when using brute force because I can only check each character for each payload. I have to brute force about twenty times for *sniper mode*. FU!!, try again with *cluster bomb mode* I have the payload as `'+AND+SUBSTRING((SELECT+password+FROM+users+WHERE+username+=+'administrator'),+§§,+1)+=+'§§;`.
> SUBSTRING(string, start, length)  
> The AND operator displays a record if all the conditions separated by AND are TRUE.

The payload is checked in each position will be equal to what character in the payload list.

> Payload 1: The position of each character is compared. Here, the length of the password is twenty, so *1-20*. Payload 2: The compared character *0-9, a-z*

And we have password as *x75h9fj4j5kd0thrgnpb*.

> In addition, after seeing some write-up, I see that the step to check the length of the password is so nice. The payload is `'+AND+(SELECT+username+FROM+users+WHERE+username+=+'administrator'+AND+LENGTH(password)=§§)+=+'administrator`.

### Error-based SQL injection

#### Exploiting blind SQL injection by triggering conditional errors

##### Lab: Blind SQL injection with conditional errors

##### souce: <https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors>

* To solve the lab, log in as the administrator user.

> Important: The most important part of exploiting blind SQL injection by triggering conditional errors is using conditions to check whether the injected query is true or false. If the condition was true, the query returned false as *Internal Server Error*; otherwise, it returned true with no error display.

Solution:

This lab is so *hard*. I can't solve it by myself for the first time. This is my solution after referring to some write-up.
> The CASE expression goes through conditions and returns a value when the first condition is met (like an if-then-else statement). So, once a condition is true, it will stop reading and return the result. If no conditions are true, it returns the value in the ELSE clause.
> If there is no ELSE part and no conditions are true, it returns NULL.  
>  
>CASE  
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;WHEN condition1 THEN result1  
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;WHEN condition2 THEN result2  
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;WHEN conditionN THEN resultN  
    ELSE result  
END;

From the hint, we know that *This lab uses an Oracle database*. We need to check the length of the password by using brute force, so the payload is `' AND (SELECT CASE WHEN LENGTH(password)=§§ THEN TO_CHAR(1/0) ELSE NULL END FROM users WHERE username='administrator')='NULL'--`. Now, we knew the length was twenty characters. Continues, we only need to check each character as above lab with the same payloads to use brute force, the payload as `' AND (SELECT CASE WHEN (SUBSTR((password), §§, 1)='§§')THEN TO_CHAR(1/0) ELSE NULL END FROM users WHERE username='administrator')='NULL'--`

We have password as *zypjctpkaux6b3igrrm6*

##### Lab: Visible error-based SQL injection

###### souce: <https://portswigger.net/web-security/sql-injection/blind/lab-sql-injection-visible-error-based>

* To solve the lab, find a way to leak the password for the administrator user, then log in to their account.

Solution:

> The CAST() function converts a value (of any type) into a specified datatype.  CAST(expression AS datatype(length))

To solve this lab, we need to observe the new error messages, which appear to be generated by the database. My solution is collabed with some write-up to explain some errors I get.

First, I test with payloads as `' AND CAST((SELECT password FROM users WHERE username='administrator') AS int)--`, and a new error appears as *Unterminated string literal started at position 95 in SQL SELECT \* FROM tracking WHERE id = '73iTx7DtmmtfiuBz' AND CAST((SELECT password FROM users WHERE'. Expected  char*. As you can see, the error only displays to *Where* and does not have the rest of the query, so we can infer that it had the limit character here. As it continues, we drop a cookie of *TrackingID* to free up some additional characters. After the payload is `' AND CAST((SELECT password FROM users WHERE username='administrator') AS int)--` and a new error as *ERROR: syntax error at end of input. Position: 97*, I think that *Where* is blocked in here. After removing *Where*, I have payload as `' AND CAST((SELECT password FROM users) AS int)--`, a new error as *ERROR: argument of AND must be type boolean, not type integer Position: 42*. It said we need a boolean statement after *AND*, so we have payload as `1>CAST((SELECT password FROM users) AS int)--`, and a new error is *ERROR: more than one row returned by a subquery used as an expression* means more than one row in table user. We only need to get one row, so we have payload as *' AND 1>CAST((SELECT password FROM users LIMIT 1) AS int)--*, and we get a password from a new error: *ERROR: invalid input syntax for type integer: "f43nlf4ci637noq11s2b"*.

> To determine the *administrator* in the first row, we can check it through payload as *' AND 1>CAST((SELECT username FROM users LIMIT 1) AS int)--*,
the error is *ERROR: invalid input syntax for type integer: "administrator"*.

### Exploiting blind SQL injection by triggering time delays

> Note: The same as between *Exploiting blind SQL injection by triggering time delays* and *Exploiting blind SQL injection by triggering conditional errors* is using conditions to observe the result returned by the database. The difference is *Exploiting blind SQL injection by triggering time delays* using condition to check time delays if it is a true condition. Otherwise,  *Exploiting blind SQL injection by triggering conditional errors* using condition to check whether the condition is true or false; if true, no result is returned.

#### Lab: Blind SQL injection with time delays

##### source: <https://portswigger.net/web-security/sql-injection/blind/lab-time-delays>

* To solve the lab, exploit the SQL injection vulnerability to cause a 10 second delay.

Solution:

we have payload as `'||(SELECT pg_sleep(10))--` because database is *PostgreSQL*

#### Lab: Blind SQL injection with time delays and information retrieval

##### source: <https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval>

* To solve the lab, log in as the administrator user.

Solution:
> %3b equals *;*

We have the payload as `'%3b+SELECT+CASE+WHEN(1=1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--` to check whether the injected query is true or false.

> We can check the length of the password with the payload as `'%3b+SELECT+CASE+WHEN+LENGTH(password)=§§+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END FROM users WHERE username='administrator'--`.

Continues, we have payload as `'%3b+SELECT+CASE+WHEN+SUBSTRING(password,§§,1)='§§'+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END FROM users WHERE username='administrator'--`. The payload for each position is as shown in the above lab. Now we only use brute force and wait for the result.

> I think we can't use *AND* because pg_sleep(10) is more like a command than a clause.

The result is *3pu6u5vh21uyekk44eib*

### Exploiting blind SQL injection using out-of-band (OAST) techniques

## SQL injection in different contexts

### Lab: SQL injection with filter bypass via XML encoding

#### source: <https://portswigger.net/web-security/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding>

* To solve the lab, perform a SQL injection attack to retrieve the admin user's credentials, then log in to their account.

Solution:

> Hint recommend using the Hackvertor extension to do this lab.

First, before using *UNION*, we need to know how much of the column is returned, so we have the payload as `<@html_entities>UNION SELECT NULL FROM information_schema.tables--<@/html_entities>`.

> <@html_entities> is encoding of Hackvertor extension using HTML encode.

Now, after knowing that one column is returned, we need to know about the table and its columns. So, we have payload as `<@html_entities>UNION SELECT TABLE_NAME FROM information_schema.tables--<@/html_entities>` and `<@html_entities>UNION SELECT COLUMN_NAME FROM information_schema.columns WHERE TABLE_NAME='users'--<@/html_entities>`

> From my experience in the above labs, I can easily find table names that include *username* and *password*

After knowing about its columns, we will extract data from them. Because only one column is returned, we have the payload as `<@html_entities>UNION SELECT username||'~'||password FROM users--<@/html_entities>`.

