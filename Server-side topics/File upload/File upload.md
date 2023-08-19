# File upload

## Source: <https://portswigger.net/web-security/file-upload>

## General

File upload vulnerabilities are when a web server allows users to upload files to its filesystem without sufficiently validating things like their name, type, contents, or size. Failing to properly enforce restrictions on these could mean that even a basic image upload function can be used to upload arbitrary and potentially dangerous files instead. This could even include server-side script files that enable remote code execution.

In some cases, the act of uploading the file is in itself enough to cause damage. Other attacks may involve a follow-up HTTP request for the file, typically to trigger its execution by the server.

## How to prevent file upload vulnerabilities

Allowing users to upload files is commonplace and doesn't have to be dangerous as long as you take the right precautions. In general, the most effective way to protect your own websites from these vulnerabilities is to implement all of the following practices:

* Check the file extension against a whitelist of permitted extensions rather than a blacklist of prohibited ones. It's much easier to guess which extensions you might want to allow than it is to guess which ones an attacker might try to upload.
* Make sure the filename doesn't contain any substrings that may be interpreted as a directory or a traversal sequence (../).
* Rename uploaded files to avoid collisions that may cause existing files to be overwritten.
* Do not upload files to the server's permanent filesystem until they have been fully validated.
* As much as possible, use an established framework for preprocessing file uploads rather than attempting to write your own validation mechanisms.

## View all file upload labs

*Link*: <https://portswigger.net/web-security/all-labs#file-upload-vulnerabilities>
