# Lab

## Tool : Burp Suite

## Retrieving hidden data

### Lab: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

#### source : <https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data>

* To solve the lab, perform a SQL injection attack that causes the application to display one or more unreleased products.

Solution:

We have a url like this "filter?category=Clothing%2c+shoes+and+accessories"

The query is **SELECT * FROM products WHERE category = 'Clothing, shoes and accessories' AND released = 1** to retrieve hidden data, you need to change **released** to 0 or remove it as a comment.

We have a payload **?category=Clothing%2c+shoes+and+accessories'+OR+1=1--**. ***Since 1=1 is always true, the query will return all items.*** Firstly, I try with payload **?category=Clothing%2c+shoes+and+accessories'--**, it only displays a unreleased data, not all of it, so I fail.

## Subverting application logic

### Lab: SQL injection vulnerability allowing login bypass

#### source : <https://portswigger.net/web-security/sql-injection/lab-login-bypass>

* To solve the lab, perform a SQL injection attack that logs in to the application as the administrator user.

Solution:

Login with the username **administrator'--** and with anything as a password.
We have a payload as **username=administrator%27--&password=123**.
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

By default, we have three columns returned. We have a payload as **?category=Accessories+UNION+SELECT+NULL,NULL,NULL--**, and the result is **Accessories' UNION SELECT NULL,NULL,NULL--**. Ok, we have completed it.

### Finding columns with a useful data type in a SQL injection UNION attack

#### Lab: SQL injection UNION attack, finding a column containing text

##### source: <https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text>

* To solve the lab, perform a SQL injection UNION attack that returns an additional row containing the value provided.

Require:

* The lab will provide a random value that you need to make appear within the query results.

Solution:

The first, as seen in the lab above, returns three columns.
We have a payload **'+UNION+SELECT+NULL,'*random value*',NULL--** to test which column contains available string data. And we have completed it.

### Using a SQL injection UNION attack to retrieve interesting data

#### Lab: SQL injection UNION attack, retrieving data from other tables

##### souce: <https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables>

* To solve the lab, perform a SQL injection UNION attack that retrieves all usernames and passwords, and use the information to log in as the administrator user.

Solution:

As to the above mention, we try to retrieve all usernames and passwords in a table called users, so we have a payload as **'+UNION+SELECT+username,+password+FROM+users--**. After that, we have the username and password as *administrator* and *54zidtfu6c3sxubn2wq3*.
Login again and complete the lab.

### Retrieving multiple values within a single column

#### Lab: SQL injection UNION attack, retrieving multiple values in a single column

##### source: <https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-multiple-values-in-single-column>

* To solve the lab, perform a SQL injection UNION attack that retrieves all usernames and passwords, and use the information to log in as the administrator user.

Solution:

As a solution above, we have to retrieve all usernames and passwords in a table called users.
Firstly, I test with payload as **+UNION+SELECT+username,+password+FROM+users--** but it is an error. And I think this is the final lab, so it isn't easy. I started to determine the number of columns in table **users** by payload as **+UNION+SELECT+NULL,NULL+FROM+users--** . It returned two columns—okay, two columns; each column is username and password. Hmm, it isn't true after testing the payload as **+UNION+SELECT+NULL,'a'+FROM+users--**. Only the second column is a string. That is an issue. Because of the first comlunm, I don't know about the data type of it, so my payload is to take NULL in this position, and the second comlunm is to be used to take username and password. Finally, payload as **'+UNION+SELECT+NULL,username+||+'~'+||+password+FROM+users--**. Login again and complete it.

## Examining the database

### Querying the database type and version

#### Lab: SQL injection attack, querying the database type and version on Oracle

##### source: <https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-oracle>

* To solve the lab, display the database version string.

Solution:

As mentioned above, the database is Oracle, so we have the payload as **'+UNION+SELECT+*+FROM+v$version**. And I haven't realized that my payload has been issued. I modified it as **"+UNION+SELECT+*+FROM+v$version**. I started stuck with it **'** and **"**. When I use **"**, no errors are displayed, so after trying so much different with **"** payload, I can't find the cause. I try to check the solution and realize that columns have to be checked and problems with quotes. Let's start again.

Check columns and data type in each column in table **v$version** with payload as **'+UNION+SELECT+NULL,NULL+FROM+v$version--**. It has two columns, and all is string data, so we have two payloads: **'+UNION+SELECT+NULL,+banner+FROM+v$version--** and **'+UNION+SELECT+banner,+NULL+FROM+v$version--**. Outputs were slightly different, but all completed the task.

#### Lab: SQL injection attack, querying the database type and version on MySQL and Microsoft

##### source: <https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft>

* To solve the lab, display the database version string.

Solution:

As mentioned above, the database is MySQL and Microsoft, and we have experience from the above lab, so we have the payload as **'+UNION+SELECT+NULL,NULL--**. Again, I am stuck. I try trying so much as **'+UNION+SELECT+NULL,NULL,NULL--**, **'+UNION+SELECT+NULL,NULL--** *with the space after the double dash*, but it still fails. I realized that double dashes are blocked, but I still tried with them. Simply, it is changed from **--** to **#**. Finally, payload is **'+UNION+SELECT+@@version,+NULL#**. I still saw a solution to realize that. Fu**!!!

### Listing the contents of the database

#### Lab: SQL injection attack, listing the database contents on non-Oracle databases

##### source: <https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle>

* To solve the lab, log in as the administrator user.

Solution:

First, I tested with payload as **'+UNION+SELECT+*+FROM+information_schema.tables**, it failed. After relaxing, I  realized that the requirements for **Retrieving data from other database tables** are so important. It said that **The individual queries must return the same number of columns.**. That is why we always check the columns returned. Okay, continues. After checking colunms, which returned two colunms with string data. I have accepted that the lab is difficult; I lost so much time trying to solve it. I have a payload to retrieve the name of the table as **'+UNION+SELECT+TABLE_NAME,NULL+FROM+information_schema.tables--**. Because we have two columns, we can't use \*. Fu**, so many tables are there. I lost about an hour and can't find it. I saw the solution to find the table name, and oh wow, it said *Find the name of the table containing user credentials.*. They didn't disclose the table name. After I searched Google to find the table name, their names were slightly different, but I could save my time. As time continues, we need to notice **The data types in each column must be compatible between the individual queries.**. So I have payload as **'+UNION+SELECT+COLUMN_NAME,+DATA_TYPE+FROM+information_schema.columns+WHERE+table_name+=+'users_zfmbzy'--** and **'+UNION+SELECT+username_qwfbhp,+password_jqavlf+FROM+users_zfmbzy--**. Finally, I found it *administrator* and *asmohymintc55i28bkf6*. Nice lab, but also so difficult.

### Equivalent to information schema on Oracle

#### Lab: SQL injection attack, listing the database contents on Oracle

##### source: <https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-oracle>

* To solve the lab, log in as the administrator user.

Solution:

Reused experience above, we have payload to list table name as **'+UNION+SELECT+TABLE_NAME,NULL+FROM+all_tables--**. After we have payload as **'+UNION+SELECT+COLUMN_NAME,DATA_TYPE+FROM+all_tab_columns+WHERE+TABLE_NAME+=+'USERS_TTAZON'--** and **'+UNION+SELECT+PASSWORD_DACSDY,USERNAME_XICVMM+FROM+USERS_TTAZON--**. Finally, we get *administrator* and *vbp1uh0zrpdgrquanuih*
