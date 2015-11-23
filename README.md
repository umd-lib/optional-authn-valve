# optional-authn-valve
[Proof-of-Concept] Optional Basic Authentication Filter for Apache Tomcat

## Usage

* `mvn clean package` and place the JAR file in `/var/lib/tomcat7/lib`
* Add a `<Valve className="edu.umd.lib.tomcat.valves.OptionalBasicAuthenticator"/>`
  element to the `<Context>` element in the webapp's `context.xml` file 
  (`/var/lib/tomcat7/webapps/{webapp}/META-INF/context.xml`)
* Ensure that there is no authentication configured in the webapp's `web.xml`

## Description

This valve checks an incoming request for a HTTP Basic Authorization header. If
one is present, it attempts to authenticate the provided credentials against the
context's realm. If authentication is successful, the returned user principal is
added to the request. Thus web applications with this valve set up in their
context will be able to retrieve that user principal to do authorization.
