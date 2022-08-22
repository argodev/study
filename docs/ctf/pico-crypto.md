# Cryptography

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