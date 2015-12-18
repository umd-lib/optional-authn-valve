package edu.umd.lib.tomcat.valves;

import java.io.IOException;
import java.security.Principal;
import java.security.cert.X509Certificate;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.Globals;
import org.apache.catalina.authenticator.Constants;
import org.apache.catalina.authenticator.SSLAuthenticator;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.LoginConfig;
import org.apache.coyote.ActionCode;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

public class OptionalSSLAuthenticator extends SSLAuthenticator {

  private static final Log log = LogFactory.getLog(OptionalSSLAuthenticator.class);

  protected static final String info = "edu.umd.lib.tomcat.valves.OptionalSSLAuthenticator/0.0.1";

  @Override
  public String getInfo() {
    return (info);
  }

  @Override
  public void invoke(Request request, Response response) throws IOException, ServletException {
    try {
      authenticate(request, response, request.getContext().getLoginConfig());

    } catch (Exception e) {
      log.debug(e);
    }
    getNext().invoke(request, response);
  }

  /**
   * The only change from SSLAuthenticator.authenticate method is that the response.sendError is not invoked when the
   * authentication fails.
   * 
   * @see org.apache.catalina.authenticator.SSLAuthenticator#authenticate(org.apache.catalina.connector.Request,
   *      javax.servlet.http.HttpServletResponse, org.apache.catalina.deploy.LoginConfig)
   */
  @Override
  public boolean authenticate(Request request,
      HttpServletResponse response,
      LoginConfig config)
      throws IOException {

    // Have we already authenticated someone?
    Principal principal = request.getUserPrincipal();
    // String ssoId = (String) request.getNote(Constants.REQ_SSOID_NOTE);
    if (principal != null) {
      if (containerLog.isDebugEnabled())
        containerLog.debug("Already authenticated '" + principal.getName() + "'");
      // Associate the session with any existing SSO session in order
      // to get coordinated session invalidation at logout
      String ssoId = (String) request.getNote(Constants.REQ_SSOID_NOTE);
      if (ssoId != null)
        associate(ssoId, request.getSessionInternal(true));
      return (true);
    }

    // Retrieve the certificate chain for this client
    if (containerLog.isDebugEnabled())
      containerLog.debug(" Looking up certificates");

    X509Certificate certs[] = (X509Certificate[])
        request.getAttribute(Globals.CERTIFICATES_ATTR);
    if ((certs == null) || (certs.length < 1)) {
      try {
        request.getCoyoteRequest().action
            (ActionCode.REQ_SSL_CERTIFICATE, null);
      } catch (IllegalStateException ise) {
        // Request body was too large for save buffer
        // DISABLE SEND ERROR ON FAILED AUTHENTICATION
        // response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
        // sm.getString("authenticator.certificates"));
        return false;
      }
      certs = (X509Certificate[])
          request.getAttribute(Globals.CERTIFICATES_ATTR);
    }
    if ((certs == null) || (certs.length < 1)) {
      if (containerLog.isDebugEnabled())
        containerLog.debug("  No certificates included with this request");
      // DISABLE SEND ERROR ON FAILED AUTHENTICATION
      // response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
      // sm.getString("authenticator.certificates"));
      return (false);
    }

    // Authenticate the specified certificate chain
    principal = context.getRealm().authenticate(certs);
    if (principal == null) {
      if (containerLog.isDebugEnabled())
        containerLog.debug("  Realm.authenticate() returned false");
      // DISABLE SEND ERROR ON FAILED AUTHENTICATION
      // response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
      // sm.getString("authenticator.unauthorized"));
      return (false);
    }

    // Cache the principal (if requested) and record this authentication
    register(request, response, principal,
        HttpServletRequest.CLIENT_CERT_AUTH, null, null);
    return (true);

  }

}
