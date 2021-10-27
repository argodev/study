# Ring Zero CTF

I stumbled on [this site](https://ringzer0ctf.com) and thought it might be helpful in testing some basic CTF-style activities and serve as an gentle entryway into the sport.  This page contains some of my notes collected while working through some of their challenges.

## Coding Challenges

### Hash Me Please

In this challenge, you are presented with a "message" on a web page that you need to encode using `sha512` and post to a URL _within 2 seconds_. Obviously, the primary task (encoding using `sha512`) isn't hard, but doing it within 2 seconds is designed to require that you write some code/script the operation rather than trying to copy/paste it into some online tool, generate the hash, and then post.

I spent some time writing up a little python script that I hope will serve me well over a handful of challenges. Essentially, it does the following:

- requests the challenge page (https://ringzer0ctf.com/challenges/13)
- parses the results and extracts the message text
- encodes the text using sha512
- issues a `get` request to `https://ringzer0ctf.com/challenges/13/<generated_hash>`
- parse the results of that `get()` and extracts the flag

I then manually submit the flag and collect my points.

!!! note
    I assumed I needed to do this all while logged in, so I first browsed to the site using FireFox with the developer tools enabled. I collected the `PHPSESSID` cookie and sent it along with all of my `get()` requests.

### Hash Me Reloaded

I initially thought that this challenge was simply a longer variant of _Hash me Please_ designed to *ensure* that you couldn't do it manually. However, that wasn't the case. Further, I take a _little_ issue with the instructions, because following them is __not sufficient__. Besides hashing the message, you need to first figure out (e.g. guess) that you need to convert the binary-string-looking message into ascii characters and *then* calculate the hash. Once you do that, the solution is very similar to the prior variant. 

My solution for this challenge was to modify the script I created for _Hash Me Please_ alter it as follows:

- Once the message had been extracted and stripped (no extraneous whitespace chars), split the string into blocks of 8 digits
- convert each digit into an int
- map that each int to the ASCII table (`chr()` in python)
- assemble the resulting characters into a string
- calculate and submit the hash of the resulting string

I then manually submit the flag and collect my points.

### I Hate Mathematics

This problem is fairly straight-forward, especially if you have your script developed for grabbing messages from the server and posting your answers.

The math problem is presented in a consistent format and looks something like the following:

```
292 + 0x2408 - 1111000011011 = ?
```

Where you have a decimal value plus a hex value and then subtract a binary. All you need to do is split the string into its compoent parts, convert the three "numbers" into ints using the proper base (10, 16, 2), perform the math, and submit the answer. This will provide you the flag value which you can then submit for points.


## Cryptography

## Exotic Data Storage

### File recovery

For this challenge, you were presented with a zip archive containing two files: `flag.enc` and `private.pem`. This immediately looked like a simple decryption problem. Looking up my command-line reference, I ran the following commands:

```bash
$ openssl rsautl -decrypt -in flag.enc -out flag.txt -inkey private.pem
$ cat flag.txt
```

I then submitted the contents of flag.txt and was awarded my one point.

## Forensics

## Jail Escaping

### Bash Jail 1

First of this type of challenge. SSH into a machine with given credentials, and you are entered into a limited shell. In this case, you are provided a basic example of what is going on, so you have some idea of how to get out. You see something like the following:

```bash
RingZer0 Team Online CTF

BASH Jail Level 1:
Current user is uid=1000(level1) gid=1000(level1) groups=1000(level1)

Flag is located at /home/level1/flag.txt

Challenge bash code:
-----------------------------

while :
do
        echo "Your input:"
        read input
        output=`$input`
done 

-----------------------------
Your input:
```

There are better ways to solve this, but all I did was the following:

```bash
// provide /bin/bash as my "input" :)
/bin/bash
bash: FLAG-U96l4k6m72a051GgE5EN0rA85499172K: command not found
level1@lxc17-bash-jail:~$ 
```

And you have the flag which you can then submit and collect your points.


!!! note
    I knew I was missing something here, so I read a writeup or two after I submitted mine. The key was the supression of stdout. One example I saw had you simply submitting `bash`, and then using `ls 1>&2` followed by `cat flag.txt 1>&2` to get the goods. This was the "niceness" that I was hoping for.


### Bash Jail 2

This one was a little harder, but not too bad. This is what the "jail" looked like:

```bash
function check_space {
    if [[ $1 == *[bdks';''&'' ']* ]]
    then 
            return 0
    fi

    return 1
}

while :
do
    echo "Your input:"
    read input
    if check_space "$input" 
    then
            echo -e '\033[0;31mRestricted characters has been used\033[0m'
    else
            output="echo Your command is: $input"
            eval $output
    fi
done 
```

I did some testing/experimentation, and finally settled on the following input:

```bash
$(<flag.txt)
Your command is: FLAG-a78i8TFD60z3825292rJ9JK12gIyVI5P
```

Which seems both simple and elegant at the same time. With this, you can submit the flag and claim your points.



## JavaScript

### Client Side Validation Is Bad!

This is an easy challenge that I actually worked through while sitting on a conference call. The premise is that (unfortunately) many websites embed too much logic on the client that gives away information that shouldn't be.

You are presented with a password login form that takes a username/password. Utilizing the in-built browser developer tools, you can see a block of JavaScript code that looks like the following:

```javascript
// Look's like weak JavaScript auth script :)
$(".c_submit").click(function(event) {
    event.preventDefault()
    var u = $("#cuser").val();
    var p = $("#cpass").val();
    if(u == "admin" && p == String.fromCharCode(74,97,118,97,83,99,114,105,112,116,73,115,83,101,99,117,114,101)) {
        if(document.location.href.indexOf("?p=") == -1) {   
            document.location = document.location.href + "?p=" + p;
        }
    } else {
        $("#cresponse").html("<div class='alert alert-danger'>Wrong password sorry.</div>");
    }
});	
```

And yes, the comment about weak JavaScript auth __is part of the page__ (I didn't add it).  A little bit of reading shows that the expected username is `admin` and they attempt to be clever by encoding the password. Lots of ways to decode this, but if you copy that string and drop it into [JSFiddle](https://jsfiddle.net), you can drop the results into a variable, display them, and see that the expected password is `JavaScriptIsSecure`. Entering these values causes the page to present the flag which can then be entered to collect your points.

### Hashing Is More Secure

This is quite similar to the prior JavaScript challenge, but only has a password field. If you inspect the code on this page, you'll see that rather than encoded as the int variant of ASCII chars, the password against which the checks are performed is hashed via `sha1`. 

```javascript
if(Sha1.hash(p) == "b89356ff6151527e89c4f3e3d30c8e6586c63962") {
    if(document.location.href.indexOf("?p=") == -1) {   
        document.location = document.location.href + "?p=" + p;
    }
} 
```

Again, there are many ways to unroll this, but I used `John` as it was easy.

```bash
# store the hash in a file called hash.txt
$ echo "b89356ff6151527e89c4f3e3d30c8e6586c63962" >> hash.txt

# attempt to crack
$ john hash.txt
...
adminz
...
```

Submit the form with that password and you'll be presented with the flag which you can then submit to collect your points.


### Then Obfuscation Is More Secure

In a continuing theme from the password forms, we have another client-side password validation routine but this time the code is "obfuscated".

```javascript
// Look's like weak JavaScript auth script :)
var _0xc360=["\x76\x61\x6C","\x23\x63\x70\x61\x73\x73","\x61\x6C\x6B\x33","\x30\x32\x6C\x31","\x3F\x70\x3D","\x69\x6E\x64\x65\x78\x4F\x66","\x68\x72\x65\x66","\x6C\x6F\x63\x61\x74\x69\x6F\x6E","\x3C\x64\x69\x76\x20\x63\x6C\x61\x73\x73\x3D\x27\x65\x72\x72\x6F\x72\x27\x3E\x57\x72\x6F\x6E\x67\x20\x70\x61\x73\x73\x77\x6F\x72\x64\x20\x73\x6F\x72\x72\x79\x2E\x3C\x2F\x64\x69\x76\x3E","\x68\x74\x6D\x6C","\x23\x63\x72\x65\x73\x70\x6F\x6E\x73\x65","\x63\x6C\x69\x63\x6B","\x2E\x63\x5F\x73\x75\x62\x6D\x69\x74"];$(_0xc360[12])[_0xc360[11]](function (){var _0xf382x1=$(_0xc360[1])[_0xc360[0]]();var _0xf382x2=_0xc360[2];if(_0xf382x1==_0xc360[3]+_0xf382x2){if(document[_0xc360[7]][_0xc360[6]][_0xc360[5]](_0xc360[4])==-1){document[_0xc360[7]]=document[_0xc360[7]][_0xc360[6]]+_0xc360[4]+_0xf382x1;} ;} else {$(_0xc360[10])[_0xc360[9]](_0xc360[8]);} ;} );
```

We could write our own little script to unwrap this, but if we hop over to [lelinhtinh's](https://github.com/lelinhtinh) little [JavaScript Deobfuscator and Unpacker](https://lelinhtinh.github.io/de4js/), we see the following:

```javascript
var _0xc360 = ["val", "#cpass", "alk3", "02l1", "?p=", "indexOf", "href", "location", "<div class=\'error\'>Wrong password sorry.</div>", "html", "#cresponse", "click", ".c_submit"];
$(_0xc360[12])[_0xc360[11]](function () {
    var _0xf382x1 = $(_0xc360[1])[_0xc360[0]]();
    var _0xf382x2 = _0xc360[2];
    if (_0xf382x1 == _0xc360[3] + _0xf382x2) {
        if (document[_0xc360[7]][_0xc360[6]][_0xc360[5]](_0xc360[4]) == -1) {
            document[_0xc360[7]] = document[_0xc360[7]][_0xc360[6]] + _0xc360[4] + _0xf382x1;
        };
    } else {
        $(_0xc360[10])[_0xc360[9]](_0xc360[8]);
    };
});
```

```javascript
// excerpt
var _0xf382x2 = _0xc360[2];
if (_0xf382x1 == _0xc360[3] + _0xf382x2) {

// translate based on the array above
if (_0xf382x1 == "02l1" + "alk3") {

// or, more nicely
if (_0xf382x1 == "02l1alk3") {
```

That conditional looks an awful lot like the password comparison we've seen before. Sure enough, if you submit the password of `02l1alk3` you will be presented with the flag that you can then submit and collect your points.


## Malware Analysis

## Pwnage Linux

## Reverse Engineering

## Shellcoding

## Software Defined Radio

## SQL Injection

## Steganography

## SysAdmin Linux

## The NC8 Reverse Engineering Track

## Web Warning

