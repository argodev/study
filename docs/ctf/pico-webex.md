# Web Exploitation

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

!!! tip
    A few things that were helpful for me as I worked through this one:
    * Using [jsbin](https://jsbin.com) to execute random JavaScript was quite helpful
    * Figuring out that when FireFox's dev tools "demangled" the javascript, it left the two words `await fetch()` slammed together as `awaitfetch()`. The latter is _not_ a function that you will find, and searching for it will leave you disappointed. Adding the space in between them and _then_ trying to understand the code will place you in a much better position.


### More Cookies

Instructions suggest that there exists "encrypted" cookies that must be modified client-side in order to solve the challenge. Pointer to url: `http://mercury.picoctf.net:15614/`. Visiting the page shows nothing other than a "reset" link and a comment that only the admin can use the cookie search page.

After poking around a little in Firefox and seeing the cookie (text below), I decided to open up Burp and start there.

``` text
Cookie: name=7; auth_name=dEJSZTVtTlZOajVGSWc0WFBRckZzWmtiMi8vNWJkUzQ2MURNLzYySUlXS1BlZXFUK1BqaHk3MGlwTm96ampFTU1qUitXT2s1cXZUWUUrbS9GeXJHZzN0bTltdDBjL21YNXJWSy83YjF6SFR0ektWNWVWVmpwSnErMDFQYW9mVW4=
```

After decoding the base64 version of `auth_name`, we were left with this:

``` text
tBRe5mNVNj5FIg4XPQrFsZkb2//5bdS461DM/62IIWKPeeqT+Pjhy70ipNozjjEMMjR+WOk5qvTYE+m/FyrGg3tm9mt0c/mX5rVK/7b1zHTtzKV5eVVjpJq+01PaofUn
FSly8XvmFjLPdS83KXonEoEDE4cmhz8QwWCiNnsmdS0FrZmIouQghyQcnmOayk2fJ9LNM25QxcQF69MuYoAdXJWd206be16+q39R76T3GOmW7CxUBCl7wtm7W1HmZtPA
```

Which wasn't too helpful. I decided to click on the first hint, and was pointed to a wikipedia page on [homomorphic encryption](https://en.wikipedia.org/wiki/Homomorphic_encryption)

After reading this article and deciding that it was unhelpful, I clicked on the second hint that basically said, even if you *were* to crack it, you likely won't be helped out. (__I missed the point here__).

I noodled around with the challenge for a bit longer, and eventually decided that this was one of those "I need to learn" so I started googling for a write-up. I quickly found one that confirmed that I likely would not have found the solution because I wasn't thinking creatively enough and also wasn't noticing sufficient details.

The hint about homomorphic encryption should be pointing me to the fact that I might have been able to make some changes to the encrypted text (cipher text) and cause some effect. The second hint in this direction was *completely* lost on me, in that the challenge description said the following: _I forgot ==Cookies== can ==Be== modified ==Client-side,== so now I decided to encrypt them!_ You'll note that I highlighted the three oddly-capitalized letters, forming `CBC` which (after reading a bit) should have triggered me into considering a bit-flipping attack (e.g. `admin=0` vs `admin=1`) due to the way cipher-block chaining works.

I learned a bit about how to do this in Python3 and developed a script, only to have it *not* work. I did some additional reading and found that in the most recent version of the challenge (at least as of 2021), the cookie value was *double* base64 encoded. I needed to double-decode, bit flip, and then double-encode. With this in place, it "sovled" the problem on the 10th byte in, flipping the 0th bit.

Helpful Writeups:

* https://docs.abbasmj.com/ctf-writeups/picoctf2021#more-cookies (don't take this verbatim)
* https://github.com/HHousen/PicoCTF-2021/blob/master/Web%20Exploitation/More%20Cookies/script.py


### where are the robots

After the last one that took me quite a long time to solve, this one was nearly a joke. The title suggests that mabye it is a robots.txt problem. Visiting the URL and then adjusting it for `robots.txt` renders a page that is prohibited (`1bb4c.html`). If you point your browser there, you will be presented  the flag.

### logon

This one was, once again, pretty easy. You follow the instructions given and log in as `jason` (no password). Nothing is obvious other than no flag being shown. If, however, you inspect the cookies, you'll see a parameter that says `admin=False`. If you alter this to say `admin=True` and resend the request, you'll be rewarded with the flag to submit.

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

