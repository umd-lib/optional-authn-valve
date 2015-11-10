package edu.umd.lib.tomcat.valves;

import java.io.IOException;
import java.security.Principal;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.authenticator.AuthenticatorBase;
import org.apache.catalina.authenticator.Constants;
import org.apache.catalina.connector.Request;
import org.apache.catalina.deploy.LoginConfig;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.buf.B2CConverter;
import org.apache.tomcat.util.buf.ByteChunk;
import org.apache.tomcat.util.buf.MessageBytes;
import org.apache.tomcat.util.codec.binary.Base64;

/**
 * 
 * @author peichman
 * @todo Is there a better way to implement this apart from copying the BasicAuthenticator and adding the code to return
 *       true on a request without credentials?
 */
public class OptionalBasicAuthenticator extends AuthenticatorBase {

  private static final Log log = LogFactory.getLog(OptionalBasicAuthenticator.class);

  protected static final String info = "edu.umd.lib.tomcat.valves.OptionalBasicAuthenticator/0.1";

  @Override
  public String getInfo() {
    return (info);
  }

  @Override
  public boolean authenticate(Request request, HttpServletResponse response, LoginConfig config) throws IOException {

    // Have we already authenticated someone?
    Principal principal = request.getUserPrincipal();
    String ssoId = (String) request.getNote(Constants.REQ_SSOID_NOTE);
    if (principal != null) {
      if (log.isDebugEnabled()) {
        log.debug("Already authenticated '" + principal.getName() + "'");
      }
      // Associate the session with any existing SSO session
      if (ssoId != null) {
        associate(ssoId, request.getSessionInternal(true));
      }
      return (true);
    }

    // Is there an SSO session against which we can try to reauthenticate?
    if (ssoId != null) {
      if (log.isDebugEnabled()) {
        log.debug("SSO Id " + ssoId + " set; attempting " + "reauthentication");
      }
      /*
       * Try to reauthenticate using data cached by SSO. If this fails, either the original SSO logon was of DIGEST or
       * SSL (which we can't reauthenticate ourselves because there is no cached username and password), or the realm
       * denied the user's reauthentication for some reason. In either case we have to prompt the user for a logon
       */
      if (reauthenticateFromSSO(ssoId, request)) {
        return true;
      }
    }

    // Validate any credentials already included with this request
    String username = null;
    String password = null;

    MessageBytes authorization = request.getCoyoteRequest().getMimeHeaders().getValue("authorization");

    // when there is no Authorization header, then
    // pass this through as an unauthenticated request
    // TODO: can we implement just this code somehow instead of copying all of the BasicAuthenticator?
    if (authorization == null) {
      return true;
    }

    if (authorization != null) {
      authorization.toBytes();
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

      principal = context.getRealm().authenticate(username, password);
      if (principal != null) {
        register(request, response, principal, HttpServletRequest.BASIC_AUTH, username, password);
        return (true);
      }
    }

    StringBuilder value = new StringBuilder(16);
    value.append("Basic realm=\"");
    if (config.getRealmName() == null) {
      value.append(REALM_NAME);
    } else {
      value.append(config.getRealmName());
    }
    value.append('\"');
    response.setHeader(AUTH_HEADER_NAME, value.toString());
    response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    return (false);

  }

  @Override
  protected String getAuthMethod() {
    return HttpServletRequest.BASIC_AUTH;
  }

}
