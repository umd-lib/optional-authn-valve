# optional-authn-valve
[Proof-of-Concept] Optional Basic Authentication Filter for Apache Tomcat

## Usage

* `mvn clean package` and place the JAR file in `/var/lib/tomcat7/lib`
* Add a `<Valve className="edu.umd.lib.tomcat.valves.OptionalBasicAuthenticator"/>` element to the `/var/lib/tomcat7/conf/context.xml`
* Disable the `<login-config>` section of the webapp's `web.xml`
