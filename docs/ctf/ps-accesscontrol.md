# Access Control Vulnerabilities

## :material-gauge-empty: Unprotected admin functionality

!!! question
    This lab has an unprotected admin panel.

    Solve the lab by deleting the user `carlos`.

This was pretty simple, though it took me a bit to remember that `/robots.txt` can be your friend when looking for "hidden" directory paths. Once I remembered this, I navigated to `/administrator-panel` (which was unprotected) and successfully deleted the user.

## :material-gauge-empty: Unprotected admin functionality with unpredictable URL

!!! question
    This lab has an unprotected admin panel. It's located at an unpredictable location, but the location is disclosed somewhere in the application.

    Solve the lab by accessing the admin panel, and using it to delete the user `carlos`.

The normal guesses didn't work, so I started looking through the raw HTML within burpsuite. Eventually, I stumbled across this bit of JavaScript:

```javascript
var isAdmin = false;
if (isAdmin) {
   var topLinksTag = document.getElementsByClassName("top-links")[0];
   var adminPanelTag = document.createElement('a');
   adminPanelTag.setAttribute('href', '/admin-gw0pr8');
   adminPanelTag.innerText = 'Admin panel';
   topLinksTag.append(adminPanelTag);
   var pTag = document.createElement('p');
   pTag.innerText = '|';
   topLinksTag.appendChild(pTag);
}
```

This made it clear that simply going to `/admin-gw0pr8` was the key and I was able to delete the user.

## :material-gauge-empty: User role controlled by request parameter

!!! question
    This lab has an admin panel at `/admin`, which identifies administrators using a forgeable cookie.

    Solve the lab by accessing the admin panel and using it to delete the user `carlos`.

    You can log in to your own account using the following credentials: `wiener:peter`

I first visited the site and logged in with "my" credentials and then attempted to visit the `/admin` page. After receiving an error, I looked at the response data in burpsuite. I immediately saw a cookie that looked like the following: `Cookie: Admin=false; session=D8CRqtEqMaPm0lhHMAVEcW452XcJq0Cd`. I sent the request to the "Repeater" tool and edited the cookie to say `Admin=true;`. I then used the "request in browser/original session" tool, and the page rendered properly and I deleted the user. 

__UPDATE__ Actually, the above *didn't* solve it. I did successfully get to the admin page, but the request to delete the user was denied because the cookie had been re-written. I probaby could have solved this via a re-write rule, but ended up just editing the `GET` request to `/admin/delete?username=carlos` and submitting it via the repeater tool.


## :material-gauge-empty: User role can be modified in user profile

!!! question
    This lab has an admin panel at `/admin`. It's only accessible to logged-in users with a `roleid` of `2`.

    Solve the lab by accessing the admin panel and using it to delete the user `carlos`.

    You can log in to your own account using the following credentials: `wiener:peter`

I logged in, visited the `/admin` page and received the "access denied" error.

Went back to the profile page, updated the account email and noticed that the `roleid` param is shown in the response to the `/my-account/change-email` request. I sent this request to the Repeater tool and added my own `roleid` param in the post and re-sent. As expected, it was processed and accepted fine. I was then able to visit `/admin` and delete `carlos`.

## :material-gauge-empty: User ID controlled by request parameter

!!! question
    This lab has a horizontal privilege escalation vulnerability on the user account page.

    To solve the lab, obtain the API key for the user `carlos` and submit it as the solution.

    You can log in to your own account using the following credentials: `wiener:peter`

I logged in to the application and on the `/my-account` page, my API key was shown. I noodled around a bit and failed to see anything like what I expected. Eventually, I navigated back to the home page, and then returned to the `/my-account` page. This time, however, I noticed the URL was a little different... `/my-account?id=wiener`. Of course, the solution looks obvious. I changed it to `/my-account?id=carlos` and was presented with that account's page/key. I submitted that answer and solved the challenge.



## :material-gauge-empty: User ID controlled by request parameter, with unpredictable user IDs

!!! question
    This lab has a horizontal privilege escalation vulnerability on the user account page, but identifies users with GUIDs.

    To solve the lab, find the GUID for carlos, then submit his API key as the solution.

    You can log in to your own account using the following credentials: `wiener:peter`

The key to this challenge is actually reading the entire block of instructions in the training material. Here it is suggested that user ids may be disclosed in other parts of the application (this I was guessing), such as user reviews and comments (I hadn't thought about this). I noodled around a little and found a post written by carlos. This page contained the following HTML: 

```html
<span id=blog-author><a href='/blogs?userId=091f297d-6894-4e29-97a6-21647b180a44'>carlos</a></span>
```

From here, the solution was easy.

