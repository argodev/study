# General Skills

## Resources

- :material-web: [Challenge Website](https://play.picoctf.org/practice?category=5&page=1){:target="_blank"}
- :material-github: [Generated Artifacts](https://github.com/argodev/study/tree/main/assets/picoctf/general){:target="_blank"}

## Obedient Cat

This is basically a "test challenge" to ensure you know how things work. You download the file, read it in a text editor (or just via `cat`), and you can recover the flag for submission.

```bash
$ cat flag
picoCTF{redacted_value}
```

## Python Wrangling

This is a *"can you run python and follow instructions"* challenge. You start with a script `ende.py` that can encrypt/decrypt a file (`flag.txt.en`) using the password in `pw.txt`. You can do this in two steps, or in a one-liner as follows:

```bash
python3 ende.py -d flag.txt.en < pw.txt
Please enter the password:picoCTF{redacted_value}
```

## Wave a flag

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

## Nice netcat...

We are pointed to `$ nc mercury.picoctf.net 22902` but told that the program doesn't speak English.

Looking at the response, it looks like ascii, so let's dump the data and see if we can do something

```bash
# get the data and store it in a file called data
$ nc mercury.picoctf.net 22902 > data

# loop through the file, convert each line to ascii and print it out
$ while read ln; do printf "\x$(printf %x $ln)"; done < data
picoCTF{redacted_value}
```

## Static ain't always noise

For this challenge you are provided two files, `static` and a potentially helpful bash script, `ltdis.sh`

The `ltdis.sh` script seems like a bit of a sledge hammer... I simply ran strings, grepped for 'pico' and found the flag.

```bash
$ strings static | grep pico
picoCTF{redacted_value}
```

## Tab, Tab, Attack

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

## Magikarp Ground Mission

This is just a simple challenge to confirm you know how to ssh, how to navigate around and read files.

Once in, cat `1of3.flag.txt`, read the instructions file and cat `/2of3.flag.txt`. Read the instructions file and then cat `~/3of3.flag.txt`. Assemble the results and go. 

## Lets Warm Up

A simple test to see if you can convert between hex and ASCII characters.

```bash
# simple lookup table
$ man ascii
```

!!! warning
    I don't like the instructions for this challenge, because you are expected to calculate the result (easy enough), but then you have to assume how to format the flag (normal format, `picoCTF{<value>}`). It's not hard, but the ambiguity isn't helpful.

## Warmed Up

Just need to convert a hex value to decimal

```bash
$ python -c print(int(0x3D))
61
```

## 2Warm

Here we convert a decimal number to a binary string

```bash
$ python -c 'print(format(42, "b"))'
101010
```

## what's a net cat?

This is another introduction to netcat.

```bash
$ nc jupiter.challenges.picoctf.org 41120
You're on your way to becoming the net cat master
picoCTF{redacted_value}
```

## strings it

This is getting old now... donwload the file, run strings, submit flag.

```bash
$ strings strings | grep pico
picoCTF{redacted_value}
```

## Bases

This looks like a base64 conversion question.

```bash
$ echo "bDNhcm5fdGgzX3IwcDM1" | base64 -d
redacted_value
```

## First Grep

Another simple test to see if you can grep

```bash
# option 1
$ cat file| grep pico
picoCTF{redacted_value}

# option 2
$ grep "pico" file 
picoCTF{redacted_value}
```

## Codebook

Asked to run a python script in the same directory as a text file.

This really wasn't even a challenge... simply run `$ python3 code.py` and you are presented with the flag.

## convertme.py

In this challenge, you are given a python script that presents you a randomly-generated int in decimal that you are to convert to binary. The challenge is easy enough (use your head, a calculator, cyberchef, etc.). I quickly solved the challenge, but stumbled onto a tool chain called `expect` that is designed to automate console program interactions. I got to thinking it might be worth digging into a bit.

I spent *way* more time on it than I should have, but I eventually got something working. I need to get better (and *much faster*) at this kind of scripting, but I think it might add some value.

## fixme1.py

In this one you needed to download a Python script and figure out what was wrong with it/was preventing it from running. This one was easy as there was an indentation problem... likely trying to highlight the importance of whitespace in the Python language.

## fixme2.py

Similar to the last one, we had a broken python script we needed to fix. In this one, we had an assignment (`=`) operator being used in the place of equality (`==`). A simple fix and the flag was printed.

## Glitch Cat

This was another simple case. When you connect to the service you get a string back, but it is a malformed code. It looks something like this:

```text
'picoCTF{gl17ch_m3_n07_' + chr(0x39) + chr(0x63) + chr(0x34) + chr(0x32) + chr(0x61) + chr(0x34) + chr(0x35) + chr(0x64) + '}'
```

The obvious task is to convert the encoded values to their actual values. I did this one step at a time, using some python one-liners such as `python3 -c "print(char(0x39))"`

## HashingJobApp

This service gives you 3 strings (one at a time) that you need to calculate the md5 sum for and submit. I solved it manually, using a separate tab and an open python window. I then went back, of course, and figured that this wasn't quite the best plan givne I would likely need to automate this sort of thing moving forward.

I learned a bit more about how `expect` scripts work, and ended up solving the challenge in a nicely automated fashion.

## PW Crack 1

In this challenge, you simply need to read the python code to determine the hard-coded password. You then provide this password when running the script, and you are presented with the flag.

## PW Crack 2

Quite similar to the last one... this time you needed to convert some hex codes to ascii and then enter the password. Felt like a repeat of things we've already done.

## PW Crack 3

There is probably a "right" way to solve this, but I'm sure I didn't do it. I read enough of the code to determine it would be quite easy to write a brute-force script to match the hash. I did this, figured out which value worked, and then submitted it to earn the flag.

## PW Crack 4

The point of this challenge seems to be to encourage you to script or do what I did for the prior challenge. With just some updates to a few things, the scripts/tools from pw 3 worked perfectly on pw 4.

## PW Crack 5

This challenge was similar to the last few, but you needed to adjust your brute-forcing script to read the candidate passwords in from a file. A minor key with this is to ensure that you aren't including the line return (`\n`) in your hash attempt.

## runme.py

I don't understand the purpose of this challenge. You simply downladed a python script, ran it, and were given the flag.

## Serpentine

The goal of this challenge appears to be to ensure that you know how to read a python script, understand what functions are, and to ensure that a function is called correctly. All you need to do is add a line in the switch stmt to print the flag, run it, and you are good.

## First Find

This challenge wants to confirm you know how to use the `find` command. You unzip the source file, search for the file in question, and then display the output.

## Big Zip

Presented with a large zip file, you need to find the flag. None of the files have particularly interesting names, so you need to recursively-grep through the files... something like `grep -r "pico" .`

## Based

This is another data encoding challenge. You are given a string of bits (binary) that you need to translate quickly, in this case, within 45 seconds. There are probably a handful of ways to solve this, including a script. Instead, I ended up using the online CyberChef tool to help out.

I was presented a binary string that I translated using the `From Binary`, followed by an octal string for which I used thed `from Octal` tool, and finally a hexadecimal string where I used the `from Hex` tool. The easiest way to set up CyberChef for this would be to have three different input tabs, have the appropriate recipies enabled/disabled for each tab, so it is just a matter of copy/paste.

*__Actually__*, my first solution bothered me as I didn't think it was scalable and wouldn't really help me in the long term. I went back and re-solved it using a Python-based interactive netcat client. The script is available in the assets section.

## plumbing

This one was a bit too easy for 200 points. You connect via `nc` to a server and are given a bunch of text. Based on what we've seen earlier, it is pretty easy to script/find the flag.

```bash
$ nc jupiter.challenges.picoctf.org 4427 | grep pico
picoCTF{redacted_value}
```

## mus1c

This one was a bit strange, and as I comment below, a bit of a disapointment. The "trick" you need to figure out is that it is actually a program, written in a esoteric programming language called [RockStar](https://codewithrockstar.com/). If you take the lyrics provided and dump them into the [online interpreter](https://codewithrockstar.com/online), you get a series of values that look quite like ASCII. If you convert those values into ASCII characters (either via a script or online tool such as CyberChef), you'll get the value you can then plug into the flag format for submission.

!!! tip
    For some dumb reason, I was having trouble figuring out how to convince CyberChef to give me characters from ASCII codes. Come to find out, I was using the wrong recipie. Using the `From Decimal` tool is all that is needed, and you can change the delimiter to various things such as `Line feed` which was helpful in this case.

!!! failure
    I *really* do not like this type of challenge and am a bit disappointed that it is included in picoCTF. For all of the other challenges, there is a clear pedagogical rationale that maps to building strong cyber security skills. This is simply searching the Internet for a weird phrase from some provided text, assuming you will guess the linking, and plugging some things together. 

## flag_shop

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

int main() {

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
    } while (account_balance < 100000);

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

## 1_wanna_b3_a_r0ck5star

Again with the waste-of-time challenges.

If you want to waste your time trying to solve it, go ahead. Otherwise, consider checking out an online write-up.[^1]

  [^1]:
    A decent writeup of `1_wanna_b3_a_r0ck5star` can be found here: https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/1_wanna_b3_a_r0ck5tar.md
