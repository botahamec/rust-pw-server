I was thinking about a project that I could use to demonstrate my proficiency in a given programming language. I decided on a password server, and decided to try writing it in Rust to see if I can write it at all. Then I got carried away.

At this time, I was working on KeyCloak. It is the most hopelessly object-oriented codebase I have ever worked with. It's filled with files that do nothing except call one function. You can look through seven files and not find any logic. So I thought about trying to implement the rest of what KeyCloak does. My co-workerers were correct in telling me that this would be a hopeless endeavor, but I at least got a fully compliant implementation of OAuth2. I ended up learning a lot through this. At least, I learned enough to teach my co-workers a couple things about OAuth.

Future work:
- Better scopes
- Better rate limiting
- Better documentation
- TLS support
- OpenID Connect
- Token introspection
- Token revocation
- PKCE
- Device Authorization
- Token Exchange
- Server Metadata
- Client Registration
- Token binding over HTTP
