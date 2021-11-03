# picoCTF

picoCTF is .....

!!! note
    Any time a sample command/output is listed on this page, the actual flag value will be replaced with `redacted_value`. This is done to ensure the "keys" aren't given away entirely should someone find these notes.

## Web Exploitation

### GET aHEAD

This probably goes down as one of those "boy, did you make it harder than it should have been" activities.

You are asked to find the flag hidden at http://mercury.picoctf.net:47967.

After a bit of benign poking around, I assumed that you need to use burp (or similar) to modify the requests, so I fired it up and started looking around. I had expected to find something in the headers taht would give the answer, but no joy. After fighting with this for too long, I broke down and looked at the first hint, which said something like _"maybe you have more than two choices"_. Score one for my lack of creativity. Looking at the page code again, I noticed that one option submitted a `GET` request and the other did a `POST` request.

Great! All I need to do is loop through the valid HTTP verbs, and I'll be set. So, I captured a request in burp, sent it to the Repeater tool, modified the verb, and sent it... did it again for each verb (`GET`, `PUT`, `POST`, `PATCH`, `DELETE`) and, as you might guess... no joy. My creative thinking fails again. Finally, I tried `HEAD` (a guess, based on the title of the challenge) and, wouldn't you guess... bingo.

I then stepped back to `curl` to see if I could have done it there, and ended up with this one-liner:

```bash
# -I (or --head) fetches the HTTP headers only. --> this is the same as sending a HEAD verb
$ curl http://mercury.picoctf.net:47967 -I     
HTTP/1.1 200 OK
flag: picoCTF{redacted_value}
Content-type: text/html; charset=UTF-8
```

### Cookies

Need to try to figure out the "best" cookie from http://mercury.picoctf.net:27177

So, the purpose of this challenge is really to ensure you know how to use Burp Suite's Intruder tool, or something similar. After poking around a bit with valid cookie names, you will notice that upon finding a valid cookie, the user is directed to http://mercury.picoctf.net:27177/check with a cookie value of `name=,some_int>`. The value of `<some_int>` changes based on the cookie name, and appears to be a lookup value of some sort. 

If you configure Intruder to use a sequential numerical payload that goes from say, `1` to `50` in steps of `1` and then run the attack, you'll see that the length property of the response for `18` is different than the rest. Inspecting the returned html will show you the key.

!!! hint
    A helpful link found while working on this challenge is https://github.com/swisskyrepo/PayloadsAllTheThings which provides word lists and various payloads for different situations

### Insp3ct0r

We are encouraged to inspect the following URL: https://jupiter.challenges.picoctf.org/problem/9670/ 

Upon viewing the source, we quickly see 1/3rd of the key in the comment string at the bottom: `picoCTF{tru3_d3` ... now to find the remaining 2/3rds.  Poking around at the downloaded JS file `myjs.js`, we see the end of the flag: `_lucky?2e7b23e3}`. All we are missing now is the middle part... Thinking ever so little, we assume that we can go to the only other referenced file (`mycss.css`) and find the middle part of the key, which we do: `t3ct1ve_0r_ju5t`

!!! note
    for what it is worth, I found this to be a very easy "challenge", and more on the lines of a 10 point challenge than the two prior ones...

### Scavenger Hunt

We are asked to find the interesting information hidden here: http://mercury.picoctf.net:39491/

* looking at the page source, we find `picoCTF{t`
* looking at the css source we find `h4ts_4_l0`
* looking at the JS source, we find a hint... `/* How can I keep Google from indexing my website? */` which points us to `robots.txt`
* looking at `robots.txt`, we find `t_0f_pl4c` as well as a hint that this is an apache server
* looking at `.htaccess` (clearly a mis-configured apache server), we find `3s_2_lO0k`. We also see that this was built on a mac and that we can store alot of info there.
* looking at `.DS_Store`, we find the last portion: `_f7ce8828}`


### Some Assembly Required 1

No description provided, no hints provided, just this url: `http://mercury.picoctf.net:26318/index.html`. Once you get there, you have a form that says "enter flag" with a submit button.

After noodling around a little, this challenge looks like an introduction to [Web Assembly](https://webassembly.org)

As I normally do, I spent way too much time trying to unravel the JS code here (mild obfuscation) only to realize that I was missing the really obvious piece... the following is the magic line:

```javascript
let _0x5f0229 = await fetch(_0x48c3be(489)),
```

In order to understand what is going on (and get the flag), you need to know the following:
* `_0x48c3be` is a function pointer, declared two lines prior, that points to the function defined on line 28 of the de-mangled javascript (`const _0x4e0e = function (_0x553839, _0x53c021) {`).
* you then need to know how the `_0x4e0e()` function works.
* It essentially takes in a number, subtracts `470` from it, and then uses the result as an index into the `_0x402c` array defined at the top of the file.
* Before you get too excited, however, you need to understand that the immediately-executing function defined prior to the current code block (line `33` for me, which starts liek `(function (_0x76dd13, _0x3dfcae) {`) modifies/sorts the array into a different order. Without this knowledge, your indicies will point to the wrong place.
* Having done all of that, you can determine that `fetch()` call referenced above is grabbing a pre-compiled blob of web assembly code. If you download that file (`http://mercury.picoctf.net:26318/JIFxzHyW8W`) and run strings on it, you will see the flag you can submit.


!!! tip:
    A few things that were helpful for me as I worked through this one:
    * Using [jsbin](https://jsbin.com) to execute random JavaScript was quite helpful
    * Figuring out that when FireFox's dev tools "demangled" the javascript, it left the two words `await fetch()` slammed together as `awaitfetch()`. The latter is _not_ a function that you will find, and searching for it will leave you disappointed. Adding the space in between them and _then_ trying to understand the code will place you in a much better position.



### More Cookies

### where are the robots

### logon

### dont-use-client-side

### It is my Birthday

### Who are you?

### login

### Some Assembly Required 2

### Super Serial

### Most Cookies

### caas

### Some Assembly Required 3

### Web Gauntlet 2

### picobrowser

### Client-side-again

### Web Gauntlet

### Some Assembly Required 4

### X marks the spot

### notepad

### Irish-Name-Repo 1

### Web Gauntlet 3

### JAuth

### Irish-Name-Repo 2

### Irish-Name-Repo 3

### JaWT Scratchpad

### Java Script Kiddie

### Java Script Kiddie 2

### Bithug






## Cryptography

### Mod 26

This is a test to see if you know what `ROT13` is, and how to encode/deocde from it. You are provided a value (`cvpbPGS{arkg_gvzr_V'yy_gel_2_ebhaqf_bs_ebg13_GYpXOHqX}`) that looks a bit like a flag and that is all.

[ROT13](https://en.wikipedia.org/wiki/ROT13) is a substitution cipher where you take one letter in plain text, increase the index by 13, and use the corresponding letter in the "enciphered" text. This is a special case of a [Caesar cipher](https://en.wikipedia.org/wiki/Caesar_cipher) because there are 26 letters in the Roman alphabet, the encoder is its own decoder.

There are a couple of easy ways to go about solving this. I've listed a few here because I thought they were informative for future challenges:

* [Cyber Chef](https://gchq.github.io/CyberChef/) with a `ROT13` recipe gives you the results straight away. This is how I solved it myself (kinda lazy, but effective).

* I saw some examples using the Linux `tr` command that I thought were pretty neat. The following example shows how:

```bash
# simple and straight-forward
$ echo "cvpbPGS{arkg_gvzr_V'yy_gel_2_ebhaqf_bs_ebg13_GYpXOHqX}" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
picoCTF{redacted_value}

# or, let's get a little fancy...
# we could/should put this first line in our .bashrc
$ alias rot13="tr 'A-Za-z' 'N-ZA-Mn-za-m'"

# then, you can call it directly
$ echo "cvpbPGS{arkg_gvzr_V'yy_gel_2_ebhaqf_bs_ebg13_GYpXOHqX}" | rot13
picoCTF{redacted_value}
```

* I also saw a python one-liner that I thought was nice:

```bash
$ echo "cvpbPGS{arkg_gvzr_V'yy_gel_2_ebhaqf_bs_ebg13_GYpXOHqX}" | python3 -c 'import sys; import codecs; print(codecs.encode(sys.stdin.read(), "rot13"))'
picoCTF{redacted_value}
```

## Reverse Engineering

### Transformation

This one takes a little more work than some of the other starter challenges. You are given a file `enc` and a little bit of code: `''.join([chr((ord(flag[i]) << 8) + ord(flag[i + 1])) for i in range(0, len(flag), 2)])` and asked to figure out what it is. To solve this you likely need to understand what the "code" is doing and what each command is. This appears to be a python one-liner that takes a variable `flag`, loops through it, manipulates it a bit, and spits it out. To get the flag back in 'plain text', we simply need to reverse the process.

What appears to be happening in the provided python script is this:

* loop through the characters in `flag`, starting with the "0th", and skipping every other
* take the ordinal value of the current character (int that maps to the ASCII code, e.g. 'a' becomes 97) and shift that value up by 8.
* then take the next character in the flag and add it to the shifted value
* output the resulting number as a string character.

To "undo" the above, we need to:

* loop through the characters in enc _one at a time_
* take the ordinal value of the current character
* take the right-most 8 bits and convert that to a character (becomes the second letter)
* shift the remaining number down 8, convert that to a character
* output the results

A "verbose" version of the reversing is shown in the following python function:

```python
def decode(enc):
    result=''
    for i in range(0, len(enc)):
        result += chr(ord(enc[i]) >> 8)
        result += chr(ord(enc[i]) & 0xff)
    return result
```

A "one liner" is as follows:

```python
''.join([chr(ord(enc[i]) >> 8) + chr(ord(enc[i]) & 0xff) for i in range(0, len(enc))])
```

So, you can tie it all together if you like as follows:

```bash
$ cat enc | python3 -c "import sys; enc=sys.stdin.read(); plain=''.join([chr(ord(enc[i]) >> 8) + chr(ord(enc[i]) & 0xff) for i in range(0, len(enc))]); print(plain)"
picoCTF{redacted_value}
```

### keygenme-py

For this challenge, you are given the file `keygenme-trial.py` and no further instructions.

If we run the script, we see that there is some functionality that is protected by a license key. It doesn't take much guessing to assume we need to figure out the key, the result of which will either be the flag itself, or will unlock functionality that will render it. Looking into the code we see the function `check_key(user_key, bUsername_trial)` that looks quite promising. Digging into it and the surrounding code, we learn the following things:

* Must be 32 chars long
* Starts with `picoCTF{1n_7h3_|<3y_of_`
* Ends with `}`
* Has 8 unknown chars in the middle `xxxxxxxx`
* username_trial is `GOUGH`

Additionally, the main logic of the `check_key()` function is as follows:

1. Confirm provided key is 32 chars long
1. Ensure the first part of the key matches `picoCTF{1n_7h3_|<3y_of_`
1. Loops through the next 8 characters to ensure they match particular indicies of a hash based on the trial username
1. If everything else has passed, we are good to go.

All of the hash-based checks look at the same hash, simply compare against different indicies. So, let's do a one-liner to generate our own copy of the hash so we can work against it.

```bash
$ python3 -c "import hashlib; x=hashlib.sha256(b'GOUGH').hexdigest(); print(x)"
e8a1f9146d32473b9605568ca66f7b5c2db9f271f57a8c8e9e121e48accddf2f
```

Simple enough, we then build our 8-digit key using the proper values from the string above (remember the indicies in the code are zero-based).

`f911a486`

We then assemble the entire key and submit it to the app to decrypt the "full" version of the program.


### crackme-py

This one is pretty easy. Downloading/running the file didn't seem to do much, so we view it in an editor and notice an uncalled-function `decode_secret()` as well as an interesting constant `bezos_cc_secret`. We add a line at the bottom of the script `decode_secret(bezos_cc_secret)` and then run the script, providing some dummy values, and then being presented with a key.


### ARMssembly 0

Here we are presented a file (`chall.S`) which is an ARM-based assembly program. We then are asked "What integer does this program print with arguments `182476535` and `3742084308`? Flag format: picoCTF{XXXXXXXX} -> (hex, lowercase, no 0x, and 32 bits. ex. 5614267 would be picoCTF{0055aabb})"



## Forensics

### information

Here you are presented with an image and asked nothing else. We download the file `cat.jpg` and inspect it. I immediately assumed there was either a string embedded in the file that was or contained the key. Running `strings` on the file and then grepping for `picoCTF` didn't yield anything, but that probably would have been too easy. Opening it with `eog` and then viewing the metadata, however, showed a weird-looking license.

Experimenting with this a little rendered the key:

```bash
$ strings cat.jpg | grep license | cut -d"'" -f 2 | base64 -d
picoCTF{redacted_value}
```

### Matryoska doll

As we are told in the instructions, "Matryoshka dolls are a set of wooden dolls of decreasing size placed one inside another." We download `dolls.jpg` and immediately learn that the file does not render properly with `eog`. Running `file` shows it as a `PNG` file rather than jpg. 

What followed was a cycle of running `binwalk` on the file, followed by extracting the contents (e.g. `binwalk -e <file_name>`) and a repeat. I did this 3 or 4 times, and the final "inner" file was `flag.txt`. this file contains the flag to be submitted.

### tunn3l v1s10n

We are provided a file, `tunn3l_v1s10n` and asked to recover the flag.




## General Skills

### Obedient Cat

This is basically a "test challenge" to ensure you know how things work. You download the file, read it in a text editor (or just via `cat`), and you can recover the flag for submission.

```bash
$ cat flag
picoCTF{redacted_value}
```

### Python Wrangling

This is a "can you run python and follow instructions" challenge. You start with a script `ende.py` that can encrypt/decrypt a file (`flag.txt.en`) using the password in `pw.txt`. You can do this in two steps, or in a one-liner as follows:

```bash
python3 ende.py -d flag.txt.en < pw.txt
Please enter the password:picoCTF{redacted_value}
```

### Wave a flag

This is a simple test to see if you know how to interact with command-line tools by asking for arguments. Additionally, you need to know a little about execute permissions.

```bash
# make it executable
$ chmod +x warm

# run it to see what it does
$ ./warm 
Hello user! Pass me a -h to learn what I can do!

# follow the instructions
$ ./warm -h
Oh, help? I actually don't do much, but I do have this flag here: picoCTF{redacted_value}
```

### Nice netcat...

We are pointed to `$ nc mercury.picoctf.net 22902` but told that the program doesn't speak English.

Looking at the response, it looks like ascii, so let's dump the data and see if we can do something

```bash
# get the data and store it in a file called data
$ nc mercury.picoctf.net 22902 > data

# loop through the file, convert each line to ascii and print it out
$ while read ln; do printf "\x$(printf %x $ln)"; done < data
picoCTF{redacted_value}
```

### Static ain't always noise

For this challenge you are provided two files, `static` and a potentially helpful bash script, `ltdis.sh`

The `ltdis.sh` script seems like a bit of a sledge hammer... I simply ran strings, grepped for 'pico' and found the flag.

```bash
$ strings static | grep pico
picoCTF{redacted_value}
```

### Tab, Tab, Attack

The description for this challenge suggests something about tabcomplete and rambling directory structures and filenames. Provided is a zip file, `Addadshashanammu.zip`. Finding the key is pretty easy:

```bash
# unzip the file
$ unzip Addadshashanammu.zip 

# cat the deepest-extracted file (looked interesting)
$ cat Addadshashanammu/Almurbalarammi/Ashalmimilkala/Assurnabitashpi/Maelkashishi/Onnissiralis/Ularradallaku/fang-of-haynekhtnamet

# clear that it is a binary but there is a string version of the flag
# let's get it
$ strings Addadshashanammu/Almurbalarammi/Ashalmimilkala/Assurnabitashpi/Maelkashishi/Onnissiralis/Ularradallaku/fang-of-haynekhtnamet | grep pico
*ZAP!* picoCTF{redacted_value}
```

### Magikarp Ground Mission

This is just a simple challenge to confirm you know how to ssh, how to navigate around and read files.

Once in, cat `1of3.flag.txt`, read the instructions file and cat `/2of3.flag.txt`. Read the instructions file and then cat `~/3of3.flag.txt`. Assemble the results and go. 

### Lets Warm Up

A simple test to see if you can convert between hex and ASCII characters.

```bash
# simple lookup table
$ man ascii
```

!!! warning
    I don't like the instructions for this challenge, because you are expected to calculate the result (easy enough), but then you have to assume how to format the flag (normal format, `picoCTF{<value>}`). It's not hard, but the ambiguity isn't helpful.

### Warmed Up

Just need to convert a hex value to decimal

```bash
$ python -c print(int(0x3D))
61
```

### 2Warm

Here we convert a decimal number to a binary string

```bash
$ python -c 'print(format(42, "b"))'
101010
```

### what's a net cat?

This is another introduction to netcat.

```bash
$ nc jupiter.challenges.picoctf.org 41120
You're on your way to becoming the net cat master
picoCTF{redacted_value}
```

### strings it

This is getting old now... donwload the file, run strings, submit flag.

```bash
$ strings strings | grep pico
picoCTF{redacted_value}
```

### Bases

This looks like a base64 conversion question.

```bash
$ echo "bDNhcm5fdGgzX3IwcDM1" | base64 -d
redacted_value
```

### First Grep

Another simple test to see if you can grep

```bash
# option 1
$ cat file| grep pico
picoCTF{redacted_value}

# option 2
$ grep "pico" file 
picoCTF{redacted_value}
```

### Based

This is another data encoding challenge. You are given a string of bits (binary) that you need to translate quickly, in this case, within 45 seconds. There are probably a handful of ways to solve this, including a script. Instead, I ended up using the online CyberChef tool to help out.

I was presented a binary string that I translated using the `From Binary`, followed by an octal string for which I used thed `from Octal` tool, and finally a hexadecimal string where I used the `from Hex` tool. The easiest way to set up CyberChef for this would be to have three different input tabs, have the appropriate recipies enabled/disabled for each tab, so it is just a matter of copy/paste.

### plumbing

This one was a bit too easy for 200 points. You connect via `nc` to a server and are given a bunch of text. Based on what we've seen earlier, it is pretty easy to script/find the flag.

```bash
$ nc jupiter.challenges.picoctf.org 4427 | grep pico
picoCTF{redacted_value}
```

### mus1c

This one was a bit strange, and as I comment below, a bit of a disapointment. The "trick" you need to figure out is that it is actually a program, written in a esoteric programming language called [RockStar](https://codewithrockstar.com/). If you take the lyrics provided and dump them into the [online interpreter](https://codewithrockstar.com/online), you get a series of values that look quite like ASCII. If you convert those values into ASCII characters (either via a script or online tool such as CyberChef), you'll get the value you can then plug into the flag format for submission.

!!! tip
    For some dumb reason, I was having trouble figuring out how to convince CyberChef to give me characters from ASCII codes. Come to find out, I was using the wrong recipie. Using the `From Decimal` tool is all that is needed, and you can change the delimiter to various things such as `Line feed` which was helpful in this case.

!!! failure
    I *really* do not like this type of challenge and am a bit disappointed that it is included in picoCTF. For all of the other challenges, there is a clear pedagogical rationale that maps to building strong cyber security skills. This is simply searching the Internet for a weird phrase from some provided text, assuming you will guess the linking, and plugging some things together. 

### flag_shop

This is a simple test to see if you can read source code and if you understand the issues with int roll-overs. You are provided the source code `store.c` and told to connect to a server via netcat. 

The keys to this challenge are as follows:

* Understand the starting balance of `1100`
* Notice that buying the "real" flag costs `100000`
* Notice that you can buy a number of "fake" flags at `900` each. 
* Somehow, we need to get our balance up from `1100` to over `100000`
* This process of buying fake flags is the only place (other than purchings the real flags) that your account balance is updated.
* If you try to purchase a stupidly-large number of flags (e.g. 2,500,000), the calculated `cost` will actually be negative (due to integer rollover). 
* This then subtracts a large _negative_ value from your current balance, effectively _adding_ to it, making you a rich person
* you can then purchase the flag with ease

!!! hint
    The key take-away here is that multiplying two `int` values (_signed_), can easily result in a value larger than `INT_MAX`. If this is unchecked, it will overflow, resulting in a negative number as the result.

I initially did the math to get my purchase number with a calculator, but I then went back and wrote a little program to calculate the _optimal_ value just for learning purposes:

```c
#include <stdio.h>
#include <stdlib.h>
int main()
{
    // these both are signed!
    int account_balance = 0;
    int number_flags = 0;
    int total_cost = 0;
    
    do {
        account_balance = 1100;
        number_flags++;
        total_cost = 900*number_flags;
        if (total_cost <= account_balance) {
            account_balance = account_balance - total_cost;
        }
    } while (account_balance < 10000);

    printf("\nWhen the number of fake flags ordered is %d\n", number_flags);
    printf("The resulting cost is %d\n", total_cost);
    printf("And your account balance will be %d\n", account_balance);
}
```

And if we build/run it...

```bash
$ gcc -g -o mytest mytest.c
$ ./mytest                 

When the number of fake flags ordered is 2386095
The resulting cost is -2147481796
And your account balance will be 2147482896
```

### 1_wanna_b3_a_r0ck5star

Again with the waste-of-time challenges.

If you want to waste your time trying to solve it, go ahead. Otherwise, consider checking out an online write-up.[^1]

  [^1]:
    A decent writeup of `1_wanna_b3_a_r0ck5star` can be found here: https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/1_wanna_b3_a_r0ck5tar.md

## Binary Exploitation

### Stonks

Here you are given a file `vuln.c` and told that there is a bot to trade "stonks" using AI and ML. It looks to be  service listening on `mercury.picoctf.net 16439` that you can interact with via netcat (`nc`). Probably need to spend some time looking at `vuln.c` to see what is going on...

Well, I somewhat quickly assertained what was going on (format string vulnerability), but I then proved to myself that __I had abosolutely no idea how to actually exploit__ or take advantage of it. I spent *way* too much time trying to figure things out. 

What I ended up doing was creating a file called `inputs` that looks like the following:

```text
1
%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x
```

This represents the two inputs I wanted to provide to the program. I then called the program as you would normally expect:

```bash
$ nc mercury.picoctf.net 16439 < inputs
Welcome back to the trading app!

What would you like to do?
1) Buy some stonks!
2) View my portfolio
Using patented AI algorithms to buy stonks
Stonks chosen
What is your API token?
Buying stonks with token:
9aa0390804b00080489c3f7eecd80ffffffff19a9e160f7efa110f7eecdc709a9f18029aa03709aa03906f6369707b465443306c5f49345f74356d5f6c6c306d5f795f79336e6263376365616336ff8a007d
Portfolio as of Thu Oct 28 20:20:27 UTC 2021


2 shares of I
6 shares of WJ
22 shares of W
55 shares of ZCVR
1903 shares of Z
Goodbye!
```

I assumed that the flag would start with `picoCTF{` as most of them had, so I confirmed that I knew that the little-endian hex version of the start of that string was `6f636970`. I identified that portion in the byte string above, took from there to the end and dumped it into cyberchef. I then used a `swap endianness` tool complete with `from hex` and I had the flag.

I made that *__way__* too difficult.

One helpful line of code that I don't want to loose:

```bash
$ python3 -c "print('%x'*30)"
```



## Uncategorized


## picoMini by redpwn

## picoCTF 2021

## picoCTF 2020 Mini-Competition

## picoCTF 2019

### Glory of the Garden

Given an image (`garden.jpg`), can you find the flag.

Looking at the image didn't show much, and there was nothing immediately obvious in the metadata. Knowing that it is a 50 pt problem, it has to be pretty easy, so I ran strings against it and the last line includes: `Here is a flag "picoCTF{redacted_value}"`

### So Meta

Asked to find the flag in the provided picture: `pico_img.png`.

Probably could have used some image-processing tool to inspect the metadata, but I ran it through strings and immediately found what I was looking for (e.e. `$ strings pico_img.png | grep pico`)

### shark on wire 1

Given a capture file (`capture.pcap`), you are asked to recover the flag.

After noodling around a bit, I found the flag, but I wish I had a better way.

I searched for `pico` and found nothing.

I then went to `Statistics --> Conversations`. From there, I started looking around at ones that looked interesting, and started clicking on UDP converstions where there was data being sent back (e.g. `B --> A`). After clicking a few and pressing `Follow Stream...` I found the flag.

While this works for the problem, there *must* be a better way. I read a handful of write-ups, and many people "just searched" like I had and seemed to have stumbled upon it. I still don't like that as a sustainable approach, because it feels too much like luck.

I then found [this writeup](https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/shark_on_wire_1.md) which used a bash script with `tshark` (command-line version of wireshark) to find it. This is a much better approach in my mind.

Therefore, in order to ensure I learned from this, I pulled apart the script so I could understand what is going on.  I include it below with my comments for clarity, but credit for the script goes to [dvd848](https://github.com/Dvd848)

```bash
#!/bin/bash

# this is the file we are interrogating
PCAP=shark_on_wire.pcap; 

# determine how many UDP streams exist in the file
# this number increments so we just grab the last one.
END=$(tshark -r $PCAP -T fields -e udp.stream | sort -n | tail -1); 

# loop through the UDP streams...
for ((i=0;i<=END;i++));
do
    # for the given stream:
    #   show the data as text, ignoring any errors
    #   remove any line returns via the translate (`tr`) tool
    #   grep/search for "picoCTF"
    tshark -r $PCAP -Y "udp.stream eq $i" -T fields -e data.text -o data.show_as_text:TRUE 2>/dev/null | tr -d '\n' | grep "picoCTF"; 

    # if the result of the prior command was "0" (successful), indicate which stream it was in.
    if [ $? -eq 0 ]; then
        echo "(Stream #$i)";
    fi; 
done
```

### extensions

By the name, you can guess that the file extension is wrong. If you run `file` against it, you see that it believes it to be a `png`.

Running `strings` shows you nothing, but if you open it in an image viewer you see the flag to submit

### What Lies Within

File is definitely an image. Neither `identify` or `exiftool` showed anything interesting. Running `strings` didn't make anything immediately obvious either.

### m00nwalk

### WhitePages

### c0rrupt

### like1000

### m00nwalk2

### Investigative Reversing 0

### shark on wire 2

### Investigative Reversing 1

### Investigative Reversing 2

### WebNet0

### Investigative Reversing 3

### Investigative Reversing 4

### WebNet1

### investigation_encoded_1

### investigation_encoded_2

### B1g_Mac
