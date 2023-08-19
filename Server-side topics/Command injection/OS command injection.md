# OS command injection

## SourceL <https://portswigger.net/web-security/os-command-injection>

## General

OS command injection (also known as shell injection) is a web security vulnerability that allows an attacker to execute arbitrary operating system (OS) commands on the server that is running an application, and typically fully compromise the application and all its data. Very often, an attacker can leverage an OS command injection vulnerability to compromise other parts of the hosting infrastructure, exploiting trust relationships to pivot the attack to other systems within the organization.

## Useful command

When you have identified an OS command injection vulnerability, it is generally useful to execute some initial commands to obtain information about the system that you have compromised. Below is a summary of some commands that are useful on Linux and Windows platforms:

| Purpose of command | Linux | Windows |
| ---                | ---   | ---     |
| Name of current user | whoami | whoami |
| Operating system | uname -a | ver
| Network configuration | ifconfig | ipconfig /all
| Network connections | netstat -an | netstat -an
| Running processes | ps -ef | tasklist

## How to prevent OS command injection attacks

By far the most effective way to prevent OS command injection vulnerabilities is to never call out to OS commands from application-layer code. In virtually every case, there are alternate ways of implementing the required functionality using safer platform APIs.

If it is considered unavoidable to call out to OS commands with user-supplied input, then strong input validation must be performed. Some examples of effective validation include:

* Validating against a whitelist of permitted values.
* Validating that the input is a number.
* Validating that the input contains only alphanumeric characters, no other syntax or whitespace.

Never attempt to sanitize input by escaping shell metacharacters. In practice, this is just too error-prone and vulnerable to being bypassed by a skilled attacker.

## View all OS command injection labs

*Link*: <https://portswigger.net/web-security/all-labs#os-command-injection>