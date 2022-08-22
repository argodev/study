# Exotic Data Storage

## File recovery

For this challenge, you were presented with a zip archive containing two files: `flag.enc` and `private.pem`. This immediately looked like a simple decryption problem. Looking up my command-line reference, I ran the following commands:

```bash
$ openssl rsautl -decrypt -in flag.enc -out flag.txt -inkey private.pem
$ cat flag.txt
```

I then submitted the contents of flag.txt and was awarded my one point.
