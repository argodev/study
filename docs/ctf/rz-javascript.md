# JavaScript

## Client Side Validation Is Bad!

This is an easy challenge that I actually worked through while sitting on a conference call. The premise is that (unfortunately) many websites embed too much logic on the client that gives away information that shouldn't be.

You are presented with a password login form that takes a username/password. Utilizing the in-built browser developer tools, you can see a block of JavaScript code that looks like the following:

```javascript
// Look's like weak JavaScript auth script :)
$(".c_submit").click(function(event) {
    event.preventDefault()
    var u = $("#cuser").val();
    var p = $("#cpass").val();
    if(u == "admin" && p == String.fromCharCode(74,97,118,97,83,99,114,105,112,116,73,115,83,101,99,117,114,101)) {
        if(document.location.href.indexOf("?p=") == -1) {   
            document.location = document.location.href + "?p=" + p;
        }
    } else {
        $("#cresponse").html("<div class='alert alert-danger'>Wrong password sorry.</div>");
    }
});	
```

And yes, the comment about weak JavaScript auth __is part of the page__ (I didn't add it).  A little bit of reading shows that the expected username is `admin` and they attempt to be clever by encoding the password. Lots of ways to decode this, but if you copy that string and drop it into [JSFiddle](https://jsfiddle.net), you can drop the results into a variable, display them, and see that the expected password is `JavaScriptIsSecure`. Entering these values causes the page to present the flag which can then be entered to collect your points.

## Hashing Is More Secure

This is quite similar to the prior JavaScript challenge, but only has a password field. If you inspect the code on this page, you'll see that rather than encoded as the int variant of ASCII chars, the password against which the checks are performed is hashed via `sha1`. 

```javascript
if(Sha1.hash(p) == "b89356ff6151527e89c4f3e3d30c8e6586c63962") {
    if(document.location.href.indexOf("?p=") == -1) {   
        document.location = document.location.href + "?p=" + p;
    }
} 
```

Again, there are many ways to unroll this, but I used `John` as it was easy.

```bash
# store the hash in a file called hash.txt
$ echo "b89356ff6151527e89c4f3e3d30c8e6586c63962" >> hash.txt

# attempt to crack
$ john hash.txt
...
adminz
...
```

Submit the form with that password and you'll be presented with the flag which you can then submit to collect your points.


## Then Obfuscation Is More Secure

In a continuing theme from the password forms, we have another client-side password validation routine but this time the code is "obfuscated".

```javascript
// Look's like weak JavaScript auth script :)
var _0xc360=["\x76\x61\x6C","\x23\x63\x70\x61\x73\x73","\x61\x6C\x6B\x33","\x30\x32\x6C\x31","\x3F\x70\x3D","\x69\x6E\x64\x65\x78\x4F\x66","\x68\x72\x65\x66","\x6C\x6F\x63\x61\x74\x69\x6F\x6E","\x3C\x64\x69\x76\x20\x63\x6C\x61\x73\x73\x3D\x27\x65\x72\x72\x6F\x72\x27\x3E\x57\x72\x6F\x6E\x67\x20\x70\x61\x73\x73\x77\x6F\x72\x64\x20\x73\x6F\x72\x72\x79\x2E\x3C\x2F\x64\x69\x76\x3E","\x68\x74\x6D\x6C","\x23\x63\x72\x65\x73\x70\x6F\x6E\x73\x65","\x63\x6C\x69\x63\x6B","\x2E\x63\x5F\x73\x75\x62\x6D\x69\x74"];$(_0xc360[12])[_0xc360[11]](function (){var _0xf382x1=$(_0xc360[1])[_0xc360[0]]();var _0xf382x2=_0xc360[2];if(_0xf382x1==_0xc360[3]+_0xf382x2){if(document[_0xc360[7]][_0xc360[6]][_0xc360[5]](_0xc360[4])==-1){document[_0xc360[7]]=document[_0xc360[7]][_0xc360[6]]+_0xc360[4]+_0xf382x1;} ;} else {$(_0xc360[10])[_0xc360[9]](_0xc360[8]);} ;} );
```

We could write our own little script to unwrap this, but if we hop over to [lelinhtinh's](https://github.com/lelinhtinh) little [JavaScript Deobfuscator and Unpacker](https://lelinhtinh.github.io/de4js/), we see the following:

```javascript
var _0xc360 = ["val", "#cpass", "alk3", "02l1", "?p=", "indexOf", "href", "location", "<div class=\'error\'>Wrong password sorry.</div>", "html", "#cresponse", "click", ".c_submit"];
$(_0xc360[12])[_0xc360[11]](function () {
    var _0xf382x1 = $(_0xc360[1])[_0xc360[0]]();
    var _0xf382x2 = _0xc360[2];
    if (_0xf382x1 == _0xc360[3] + _0xf382x2) {
        if (document[_0xc360[7]][_0xc360[6]][_0xc360[5]](_0xc360[4]) == -1) {
            document[_0xc360[7]] = document[_0xc360[7]][_0xc360[6]] + _0xc360[4] + _0xf382x1;
        };
    } else {
        $(_0xc360[10])[_0xc360[9]](_0xc360[8]);
    };
});
```

```javascript
// excerpt
var _0xf382x2 = _0xc360[2];
if (_0xf382x1 == _0xc360[3] + _0xf382x2) {

// translate based on the array above
if (_0xf382x1 == "02l1" + "alk3") {

// or, more nicely
if (_0xf382x1 == "02l1alk3") {
```

That conditional looks an awful lot like the password comparison we've seen before. Sure enough, if you submit the password of `02l1alk3` you will be presented with the flag that you can then submit and collect your points.

