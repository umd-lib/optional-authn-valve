# optional-authn-valve

Optional Authentication Valves for Apache Tomcat

## Building

```
git clone https://github.com/umd-lib/optional-authn-valve.git
cd optional-authn-valve
mvn clean package
```

Place the resulting JAR file into the Tomcat lib directory
(`$CATALINA_BASE/lib`).

## Usage

The valves are configured in the webapp's `context.xml` file (typically found
either in the `$CATALINA_BASE/webapps/{webapp}/META-INF` directory of the
deployed webapp, or in the `$CATALINA_BASE/conf/Catalina/localhost/{webapp}`
directory for an externally specified context).

To enable optional HTTP Basic authentication, add the following to the `<Context>`
element:

```
<Valve className="edu.umd.lib.tomcat.valves.OptionalBasicAuthenticator"/>
```

If you wish to use the optional SSL authenticator, add the following instead:

```
<Valve className="edu.umd.lib.tomcat.valves.OptionalSSLAuthenticator"/>
```

Finally, you should ensure that there is no authentication configured in the
webapp's `web.xml` file. If there is, that will defeat the whole purpose of
these valves!

## Description

This library provides two valves for Apache Tomcat for performing optional
authentication on incoming requests. Webapps configured to use these valves will
never challenge for authentication. However, for any request with preemptive
authentication, those credentials are checked and, if successful, the valve adds
a user principal to the request. Thus web applications with either of these
valves set up in their context will be able to retrieve that user principal to
do authorization.

### edu.umd.lib.tomcat.valves.OptionalBasicAuthenticator

This valve checks an incoming request for a HTTP Basic Authorization header. If
one is present, it attempts to authenticate the provided credentials against the
context's realm. If authentication is successful, the returned user principal is
added to the request.

### edu.umd.lib.tomcat.valves.OptionalSSLAuthenticator

Uses client certificates instead of HTTP Basic authentication. The user
principal name will be the DN on the certificate.

## License

See the [LICENSE](LICENSE.md) file for license rights and limitations (Apache 2.0).

