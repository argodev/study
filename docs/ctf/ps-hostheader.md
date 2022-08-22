# HTTP Host Header Attacks

## Basic Password Reset Poisoning

We are told that `carlos` will click any link in any email he receives. The goal is to log in to Carlos's account.

We are given a valid set of credentials.

Given the title of the challenge, I'm assuming that in the `POST` request to reset my password, there will be a header that can be manipulated or maybe in the password reset link.