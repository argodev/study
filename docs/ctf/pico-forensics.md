# Forensics

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
