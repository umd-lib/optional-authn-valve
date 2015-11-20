package edu.umd.lib.tomcat.valves;

import java.io.IOException;
import java.security.Principal;

import javax.servlet.ServletException;

import org.apache.catalina.Context;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.buf.B2CConverter;
import org.apache.tomcat.util.buf.ByteChunk;
import org.apache.tomcat.util.buf.MessageBytes;
import org.apache.tomcat.util.codec.binary.Base64;

/**
 * 
 * @author peichman
 */
public class OptionalBasicAuthenticator extends ValveBase {

  private static final Log log = LogFactory.getLog(OptionalBasicAuthenticator.class);

  protected static final String info = "edu.umd.lib.tomcat.valves.OptionalBasicAuthenticator/0.0.1";

  @Override
  public String getInfo() {
    return (info);
  }

  @Override
  public void invoke(Request request, Response response) throws IOException, ServletException {
    // check for an HTTP Authorization request header
    MessageBytes authorization = request.getCoyoteRequest().getMimeHeaders().getValue("authorization");

    // if there is an Authorization header, then check the provided credentials
    if (authorization != null) {
      String username = null;
      String password = null;

      authorization.toBytes();
      log.debug("Authorization header found: " + authorization.toString());
      ByteChunk authorizationBC = authorization.getByteChunk();
      if (authorizationBC.startsWithIgnoreCase("basic ", 0)) {
        authorizationBC.setOffset(authorizationBC.getOffset() + 6);

        byte[] decoded = Base64.decodeBase64(authorizationBC.getBuffer(), authorizationBC.getOffset(),
            authorizationBC.getLength());

        // Get username and password
        int colon = -1;
        for (int i = 0; i < decoded.length; i++) {
          if (decoded[i] == ':') {
            colon = i;
            break;
          }
        }

        if (colon < 0) {
          username = new String(decoded, B2CConverter.ISO_8859_1);
        } else {
          username = new String(decoded, 0, colon, B2CConverter.ISO_8859_1);
          password = new String(decoded, colon + 1, decoded.length - colon - 1, B2CConverter.ISO_8859_1);
        }

        authorizationBC.setOffset(authorizationBC.getOffset() - 6);
      }

      Context context = request.getContext();
      Principal principal = context.getRealm().authenticate(username, password);
      if (principal != null) {
        log.debug("User principal " + principal.getName() + " has been authenticated");
        request.setUserPrincipal(principal);
      } else {
        log.debug("Authentication failed with the provided credentials");

        // TODO: we could issue an HTTP Basic authentication challenge at this point;
        // the problem is we need to get the proper realm name; need to have a parameter on the valve?

        // log.debug("Sending 401 Unauthorized header");
        // StringBuilder value = new StringBuilder(16);
        // value.append("Basic realm=\"");
        // if (config.getRealmName() == null) {
        // value.append(REALM_NAME);
        // } else {
        // value.append(config.getRealmName());
        // }
        // value.append('\"');
        // response.setHeader(AUTH_HEADER_NAME, value.toString());
        // response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
      }
    } else {
      log.debug("No authorization header in the request, doing no authentication");
    }

    getNext().invoke(request, response);
  }

}
