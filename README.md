Useless Authorization Server
============================

Overview
--------

This is an implementation of authorization server just for education purposes
only. This implementation is not proper for commercial use because the following
reasons and unwritten ones.

- PKCE (RFC 7636), a must security feature, is not supported.
- Other flows than the authorization code flow are not supported.
- Confidential clients are not supported. Note that this implies that this implementation does not have any code related to client authentication.
- The 'redirect_uri' request parameter must always be given although RFC 6749 allows omission of the parameter in some cases.
- RFC 6749 allows redirect URIs to include a query part, but this implementation fails to build a proper value for the `Location` header in the case.
- It is not checked whether the same request parameters are not given although RFC 6749 requires that _"Request and response parameters MUST NOT be included more than once."_
- This implementation does not strictly follow the requirement in RFC 6749: _"Parameters sent without a value MUST be treated as if they were omitted from the request."_
- The authorization endpoint does not use `302 Found` in error cases even after the redirect URI it should use has been determined.
- The value of the `state` request parameter is not checked although RFC 6749 requires that characters of `state` be in the range of `%x20-7E`.
- The token endpoint requires `client_id` as a mandatory parameter because it knows that all clients are 'public'.
- The token endpoint requires `redirect_uri` as a mandatory parameter because (1) it knows that the authorization endpoint always requires `redirect_uri` and (2) it does not support other flows than the authorization code flow.
- No mechanism to clean up expired authorization codes and access tokens periodically.
- Entropy of authorization codes and access tokens is too low.
- The feature of sinatra's session is used without any security consideration.
- No protection for CSRF.
- The following are hard-coded: One client application, one end-user account, access token duration.

Set up
------

    $ gem install sinatra webrick
    $ git clone https://github.com/authlete/useless-oauth-server
    $ cd useless-oauth-server

Run
---

    $ ruby server.rb

Test
----

### Authorization Request and Response

Input the following URL to your web browser's address bar.

  <code>http://localhost:4567/authorization?response_type=code&client_id=1&redirect_uri=http://example.com/&scope=read+write</code>

An authorization page will be displayed. Input `john` and `john` to the Login
ID field and the Password field. Then, press the "Approve" button.

The top page of example.com will be displayed. Copy the value of the `code`
parameter of the URL which is in the address bar of the web browser. The value
is the issued authorization code.

### Token Request and Response

Type the following commands.

    $ CODE={The-Issued-Authorization-Code}
    $ curl http://localhost:4567/token \
      -d grant_type=authorization_code \
      -d code=$CODE \
      -d client_id=1 \
      -d redirect_uri=http://example.com/

A successful response will look like the following.

```json
{
  "access_token":"mvL_sRy3",
  "token_type":"Bearer",
  "expires_in":86400,
  "scope":"read write"
}
```
