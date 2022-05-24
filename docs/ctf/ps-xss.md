# Cross-Site Scripting

## :material-gauge-empty: Reflected XSS into HTML conext with Nothing Encoded

!!! question
    This lab contains a simple reflected cross-site scripting vulnerability in the search functionality.

    To solve the lab, perform a cross-site scripting attack that calls the `alert` function.

Visiting the site, there is a search form. I searched for `test` and was redirected to `t/?search=test`. I then searched for `test <script>alert();</script>` and, not surprisingly, I receieved an alert and completed the lab.

## :material-gauge-empty: Stored XSS into HTML context with nothing encoded

!!! question
    This lab contains a stored cross-site scripting vulnerability in the comment functionality.

    To solve this lab, submit a comment that calls the `alert` function when the blog post is viewed.

Found an comment form on the website and submitted the following: `This is awesome!<script>alert('you stink');</script>`. Once I submitted and then visited the post again, the alert was triggered and the lab was solved.

## :material-gauge-empty: DOM XSS in document.write sink using source location.search

!!! question
    This lab contains a DOM-based cross-site scripting vulnerability in the search query tracking functionality. It uses the JavaScript `document.write` function, which writes data out to the page. The `document.write` function is called with data from `location.search`, which you can control using the website URL.

I started out by attempting to search for `test <script>alert();</script>` which displayed the exact same contents out on the page (no alert box). I then reviewed the source code for the page and found this bit of Javascript:

```javascript
document.write('<img src="/resources/images/tracker.gif?searchTerms='+query+'">');
```

With this knowledge, I re-structured my query to close out the end of the `img` tag and render my javascript. Submitting this: `test'"><script>alert();</script>` allowed me to solve the challenge.


## :material-gauge-empty: DOM XSS in innerHTML sink using source location.search

!!! question
    This lab contains a DOM-based cross-site scripting vulnerability in the search blog functionality. It uses an `innerHTML` assignment, which changes the HTML contents of a `div` element, using data from `location.search`.

The Javascript on the page looks like the following:

```javascript
document.getElementById('searchMessage').innerHTML = query;
```

Doing an ill-informed attempt results in DOM that looks like the following (and is unsuccessful): 

```html
<h1>
    <span>0 search results for '</span>
    <span id="searchMessage">
        <script>alert();</script>
    </span>
    <span>'</span>
</h1>
```

I went down a failed rathole here a bit before I read https://portswigger.net/web-security/cross-site-scripting/dom-based and noticed that the `innerHTML` sink doesn't accept `script` elements and, as such, you need to use other elements usch as `img` or `iframe`. I used the example directly from the page (`<img src=1 onerror=alert(document.domain)>`) and it worked successfully.



## :material-gauge-empty: DOM XSS in jQuery anchor href attribute sink using location.search source

!!! question
    This lab contains a DOM-based cross-site scripting vulnerability in the submit feedback page. It uses the jQuery library's `$` selector function to find an anchor element, and changes its `href` attribute using data from `location.search`.

    To solve this lab, make the "back" link alert `document.cookie`.

I noticed the "submit feedback" link on the page, and if you click on it, you are directed to a feedback form that has a "back" link at the bottom of it (this is what we need to mess with). Additionally, the URL looks like this: `/feedback?returnPath=/`. After a little experimentation, I simply changed the URL to `/feedback?returnPath=javascript:alert(document.cookie);` and hit enter. This caused the page to render, and looking at the DOM, we now see the following:

```html
<div class="is-linkback">
    <a id="backLink" href="javascript:alert(document.cookie);">Back</a>
</div>
```

Of course, clicking the link completes the challenge.

## :material-gauge-empty: DOM XSS in jQuery selector sink using a hashchange event

!!! question
    This lab contains a DOM-based cross-site scripting vulnerability on the home page. It uses jQuery's `$()` selector function to auto-scroll to a given post, whose title is passed via the `location.hash` property.

    To solve the lab, deliver an exploit to the victim that calls the `print()` function in their browser.

Ok, this one was a little weird, only because it took me a bit to a.) understand what they wanted me to do and b.) wrap my head around the who-sends-what-to-whom part of things. Once I figured out what the code on the vulnerable site was doing, I then headed over to the exploit server and, leaving the first few fields with their default values, set the body to:

```html
<iframe src="https://ac1d1fef1e4a1f89c02b0709003e00de.web-security-academy.net/#" onload="this.src+='<img src=1 onerror=print()>'">
```

Pressing the `View Exploit` button made it clear that it was working (couldn't get it to stop trying to print). Coming back and clicking the `Deliver exploit to victim` button confirmed that I had solved the lab.
