# Coding Challenges

## Hash Me Please

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
