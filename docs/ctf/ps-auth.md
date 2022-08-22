# Authentication

### :material-gauge-empty: Username enumeration via different responses

!!! question
    This lab is vulnerable to username enumeration and password brute-force attacks. It has an account with a predictable username and password, which can be found in the following wordlists:

    Candidate usernames
    Candidate passwords

    To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.


Goal: Enumerate a valid username, brute-force the user's password, and then access the user's account page.

You are provided a wordlist of candidate usernames as well as a list of candidate passwords.

Here are the steps I took to solve this challenge:

1. Load up Burp and start the embedded browser
1. Connect to the URL provided and visit the `/login` page
1. Attempt to log in with a random username/password
1. View the `POST` request in Burp and send it to the intruder
1. On the Positions tab, I cleared the `§` from the session cookie, leaving just the username and password positions
1. Pasted the values from the list of candidate usernames (100 of them) into the Payload Options (simple list) and started the attack, paying attention to the response payload size.
1. After the list ran through, I sorted by response length and noticed that one of them (username: `agenda`) had a different payload length. Looking at the response text, I noticed that it said _"Incorrect password"_. 
1. Returning to the positions page, I changed the username to a static value of `agenda`
1. I cleared the payload list and pasted in the values from the candidate password list and then ran the attack
1. Watching the response lengths, I again noticed taht one of them (password: `robert`) had a different length. Inspecting the response showed that user had logged in. 
1. With this information, I then returned to the browser, manually logged in with this information, and completed the challenge

### :material-gauge: Username enumeration via subtly different responses

!!! question
    This lab is subtly vulnerable to username enumeration and password brute-force attacks. It has an account with a predictable username and password, which can be found in the following wordlists:

    Candidate usernames
    Candidate passwords

    To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.

Working on this challenge made me sharpen my understanding of the _intruder_ tool. I had two lists, and I wanted to run all permutations of them (combined). The mistake I had been making was that I had been failing to change the attack type from the default `Sniper` to the `Cluster Bomb` option. This let me define my two lists, each assigned to one of the two fields/positions, and then start.

After just over 10,000 attempts, we found one request that returned a `302` rather than a `200`. Logging in as `at` with a password of `7777777` solved the challenge.


### :material-gauge: Username enumeration via response timing

!!! question
    This lab is vulnerable to username enumeration using its response times. To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.

    Your credentials: wiener:peter
    Candidate usernames
    Candidate passwords


This was an unwelcome response:

!!! error 
    You have made too many incorrect login attempts. Please try again in 30 minute(s).

The more accurate statement... I should have read the instructions. You are supposed to do this in two steps: 1. enumerate the username and then 2. brute force that user's password. I tried to just do the cluster bomb approach and that was foolish.





### :material-gauge-empty: 2FA simple bypass

!!! question
    This lab's two-factor authentication can be bypassed. You have already obtained a valid username and password, but do not have access to the user's 2FA verification code. To solve the lab, access Carlos's account page.

    Your credentials: `wiener:peter`
    Victim's credentials `carlos:montoya`

Given a valid username/password and access to that account's email, as well as a victim username/password, you are asked to bypass the 2FA for the victim's account (you do not have access to their email) and get to their profile page.

Walking through the auth flow with a valid user is pretty straight foward. You log in at `/login` and then are directed to `/login2` to enter the 2FA code. Once you get that from your email, you are redirected to `/my-account`.

The "attack" is as simple as completing the first stage with the victim's credentials and then changing the URL to `/my-account`. This succeeds as there is no session logic to confirm that the 2FA code was entered (only redirection logic).

### :material-gauge-empty: Password reset broken logic

!!! question
    This lab's password reset functionality is vulnerable. To solve the lab, reset Carlos's password then log in and access his "My account" page.

    Your credentials: `wiener:peter`
    Victim's username: `carlos`

Given a valid set of credentials as well as a victim username, you are asked to reset the victim's password and then log in to view the "my account" page.

Using the valid credentials, I pretended to have forgotton my password and requested a password reset link. I then completed that process and reviewed the `POST` request to `/forgot-password`. I noticed the payload had not only the reset token and the new password, but also the username. I sent the request to the repeater, changed the `username` to the victim username and re-submitted it. The request completed, so I went to the browser, logged in with the victim username and my newly-set password and was able to view the account page.
