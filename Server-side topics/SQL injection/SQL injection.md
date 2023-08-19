# SQL injection

## Source: <https://portswigger.net/web-security/sql-injection>

## General

SQL injection (SQLi) is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. It generally allows an attacker to view data that they are not normally able to retrieve. This might include data belonging to other users, or any other data that the application itself is able to access. In many cases, an attacker can modify or delete this data, causing persistent changes to the application's content or behavior.

In some situations, an attacker can escalate a SQL injection attack to compromise the underlying server or other back-end infrastructure, or perform a denial-of-service attack.

## How to prevent SQL injection

Most instances of SQL injection can be prevented by using parameterized queries (also known as prepared statements) instead of string concatenation within the query

## SQL injection cheat sheet

*Link*: <https://portswigger.net/web-security/sql-injection/cheat-sheet>

## View all SQL injection labs

*Link*: <https://portswigger.net/web-security/all-labs#sql-injection>
