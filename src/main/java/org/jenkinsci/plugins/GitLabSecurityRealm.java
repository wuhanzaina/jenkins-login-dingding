/**
 * The MIT License
 * <p>
 * Copyright (c) 2016 Mohamed EL HABIB
 * <p>
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * <p>
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * <p>
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package org.jenkinsci.plugins;

import static java.util.UUID.randomUUID;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.thoughtworks.xstream.converters.ConversionException;
import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;
import hudson.Extension;
import hudson.ProxyConfiguration;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import hudson.security.UserMayOrMayNotExistException2;
import hudson.tasks.Mailer;
import hudson.util.Secret;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import jenkins.model.Jenkins;
import jenkins.security.SecurityListener;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.builder.HashCodeBuilder;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.NameValuePair;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.gitlab4j.api.Constants.TokenType;
import org.gitlab4j.api.GitLabApiException;
import org.gitlab4j.api.models.Group;
import org.jfree.util.Log;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.Header;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest2;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * Implementation of the AbstractPasswordBasedSecurityRealm that uses gitlab
 * oauth to verify the user can login.
 * <p>
 * This is based on the GitLabSecurityRealm from the gitlab-auth-plugin written
 * by Alex Ackerman.
 */
public class GitLabSecurityRealm extends SecurityRealm {
    private String gitlabWebUri;
    private String gitlabApiUri;
    private String clientID;
    private Secret clientSecret;

    /**
     * @param gitlabWebUri The URI to the root of the web UI for GitLab or GitLab
     *                     Enterprise, including the protocol (e.g. https).
     * @param gitlabApiUri The URI to the root of the API for GitLab or GitLab
     *                     Enterprise, including the protocol (e.g. https).
     * @param clientID     The client ID for the created OAuth Application.
     * @param clientSecret The client secret for the created GitLab OAuth Application.
     *                     Should be encrypted value of a {@link hudson.util.Secret},
     *                     for compatibility also plain text values are accepted.
     */
    @DataBoundConstructor
    public GitLabSecurityRealm(String gitlabWebUri, String gitlabApiUri, String clientID, String clientSecret) {
        this.gitlabWebUri = Util.fixEmptyAndTrim(gitlabWebUri);
        this.gitlabApiUri = Util.fixEmptyAndTrim(gitlabApiUri);
        this.clientID = Util.fixEmptyAndTrim(clientID);
        setClientSecret(Util.fixEmptyAndTrim(clientSecret));
    }

    private GitLabSecurityRealm() {
    }

    /**
     * @param gitlabWebUri the string representation of the URI to the root of the Web UI
     *                     for GitLab or GitLab Enterprise.
     */
    private void setGitlabWebUri(String gitlabWebUri) {
        this.gitlabWebUri = gitlabWebUri;
    }

    /**
     * @param clientID the clientID to set
     */
    private void setClientID(String clientID) {
        this.clientID = clientID;
    }

    /**
     * @param clientSecret the clientSecret to set
     */
    private void setClientSecret(String clientSecret) {
        this.clientSecret = Secret.fromString(clientSecret);
    }

    /**
     * @return the URI to the API root of GitLab or GitLab Enterprise.
     */
    public String getGitlabApiUri() {
        return gitlabApiUri;
    }

    /**
     * @param gitlabApiUri the URI to the API root of GitLab or GitLab Enterprise.
     */
    private void setGitlabApiUri(String gitlabApiUri) {
        this.gitlabApiUri = gitlabApiUri;
    }

    public static final class ConverterImpl implements Converter {

        @Override
        public boolean canConvert(Class type) {
            return type == GitLabSecurityRealm.class;
        }

        @Override
        public void marshal(Object source, HierarchicalStreamWriter writer, MarshallingContext context) {
            GitLabSecurityRealm realm = (GitLabSecurityRealm) source;

            writer.startNode("gitlabWebUri");
            writer.setValue(realm.getGitlabWebUri());
            writer.endNode();

            writer.startNode("gitlabApiUri");
            writer.setValue(realm.getGitlabApiUri());
            writer.endNode();

            writer.startNode("clientID");
            writer.setValue(realm.getClientID());
            writer.endNode();

            writer.startNode("clientSecret");
            writer.setValue(realm.clientSecret.getEncryptedValue());
            writer.endNode();
        }

        @Override
        public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext context) {

            GitLabSecurityRealm realm = new GitLabSecurityRealm();

            String node;
            String value;

            while (reader.hasMoreChildren()) {
                reader.moveDown();
                node = reader.getNodeName();
                value = reader.getValue();
                setValue(realm, node, value);
                reader.moveUp();
            }

            return realm;
        }

        private void setValue(GitLabSecurityRealm realm, String node, String value) {
            switch (node.toLowerCase()) {
                case "clientid":
                    realm.setClientID(value);
                    break;
                case "clientsecret":
                    realm.setClientSecret(value);
                    break;
                case "gitlabweburi":
                    realm.setGitlabWebUri(value);
                    break;
                case "gitlabapiuri":
                    realm.setGitlabApiUri(value);
                    break;
                default:
                    throw new ConversionException("Invalid node value = " + node);
            }
        }
    }

    /**
     * @return the uri to the web root of GitLab (varies for GitLab Enterprise
     * Edition)
     */
    public String getGitlabWebUri() {
        return gitlabWebUri;
    }

    /**
     * @return the clientID
     */
    public String getClientID() {
        return clientID;
    }

    /**
     * Used by jelly
     *
     * @return the client secret
     */
    public Secret getClientSecret() {
        return clientSecret;
    }

    // "from" is coming from SecurityRealm/loginLink.jelly
    public HttpResponse doCommenceLogin(
            StaplerRequest2 request, @QueryParameter String from, @Header("Referer") final String referer)
            throws IOException {
        // 2. Requesting authorization :
        // http://doc.gitlab.com/ce/api/oauth2.html

        String redirectOnFinish;

        // Setting a value for the state parameter
        final String state = randomUUID().toString();

        if (from != null && Util.isSafeToRedirectTo(from)) {
            redirectOnFinish = from;
        } else if (referer != null
                && (referer.startsWith(Jenkins.get().getRootUrl()) || Util.isSafeToRedirectTo(referer))) {
            redirectOnFinish = referer;
        } else {
            redirectOnFinish = Jenkins.get().getRootUrl();
        }
        request.getSession().setAttribute(REFERER_ATTRIBUTE, redirectOnFinish);
        request.getSession().setAttribute(STATE_ATTRIBUTE, state);

        List<NameValuePair> parameters = new ArrayList<>();
        parameters.add(new BasicNameValuePair("redirect_uri", buildRedirectUrl(request)));
        parameters.add(new BasicNameValuePair("response_type", "code"));
        parameters.add(new BasicNameValuePair("client_id", clientID));
        parameters.add(new BasicNameValuePair("scope", "api"));
        parameters.add(new BasicNameValuePair("state", state));

        return new HttpRedirect(
                gitlabWebUri + "/oauth/authorize?" + URLEncodedUtils.format(parameters, StandardCharsets.UTF_8));
    }

    private String buildRedirectUrl(StaplerRequest2 request) throws MalformedURLException {
        URL currentUrl = new URL(Jenkins.get().getRootUrl());

        URL redirect_uri = new URL(
                currentUrl.getProtocol(),
                currentUrl.getHost(),
                currentUrl.getPort(),
                request.getContextPath() + "/securityRealm/finishLogin");
        return redirect_uri.toString();
    }

    /**
     * This is where the user comes back to at the end of the OpenID redirect
     * ping-pong.
     */
    public HttpResponse doFinishLogin(StaplerRequest2 request) throws IOException {
        String code = request.getParameter("code");
        String state = request.getParameter(STATE_ATTRIBUTE);
        String expectedState = (String) request.getSession().getAttribute(STATE_ATTRIBUTE);

        if (StringUtils.isBlank(code)) {
            Log.info("doFinishLogin: missing code or private_token.");
            return HttpResponses.redirectToContextRoot();
        }

        if (state == null) {
            LOGGER.info("doFinishLogin: missing state parameter from GitLab response.");
            return HttpResponses.redirectToContextRoot();
        } else if (expectedState == null) {
            LOGGER.info("doFinishLogin: missing state parameter from user's session.");
            return HttpResponses.redirectToContextRoot();
        } else if (!MessageDigest.isEqual(state.getBytes(Charset.forName("UTF-8")), expectedState.getBytes(Charset.forName("UTF-8")))) {
            LOGGER.info(
                    "state parameter value [" + state + "] does not match the expected one [" + expectedState + "].");
            return HttpResponses.redirectToContextRoot();
        }

        if (clientSecret == null) {
            Log.info("doFinishLogin: missing client secret.");
            return HttpResponses.redirectToContextRoot();
        }
        String referer = (String) request.getSession().getAttribute(REFERER_ATTRIBUTE);
        HttpPost httpPost = new HttpPost(gitlabWebUri + "/oauth/token");
        List<NameValuePair> parameters = new ArrayList<>();
        parameters.add(new BasicNameValuePair("client_id", clientID));
        parameters.add(new BasicNameValuePair("client_secret", clientSecret.getPlainText()));
        parameters.add(new BasicNameValuePair("code", code));
        parameters.add(new BasicNameValuePair("grant_type", "authorization_code"));
        parameters.add(new BasicNameValuePair("redirect_uri", buildRedirectUrl(request)));
        httpPost.setEntity(new UrlEncodedFormEntity(parameters, StandardCharsets.UTF_8));

        CloseableHttpClient httpclient = HttpClients.createDefault();
        HttpHost proxy = getProxy(httpPost);
        if (proxy != null) {
            RequestConfig config = RequestConfig.custom().setProxy(proxy).build();
            httpPost.setConfig(config);
        }

        org.apache.http.HttpResponse response = httpclient.execute(httpPost);

        HttpEntity entity = response.getEntity();

        String content = EntityUtils.toString(entity);

        // When HttpClient instance is no longer needed,
        // shut down the connection manager to ensure
        // immediate de-allocation of all system resources
        httpclient.close();

        String accessToken = extractToken(content);

        if (StringUtils.isNotBlank(accessToken)) {
            try {
                // only set the access token if it exists.
                GitLabAuthenticationToken auth =
                        new GitLabAuthenticationToken(accessToken, getGitlabApiUri(), TokenType.OAUTH2_ACCESS);

                HttpSession session = request.getSession(false);
                if (session != null) {
                    // avoid session fixation
                    session.invalidate();
                }
                request.getSession(true);

                SecurityContextHolder.getContext().setAuthentication(auth);

                org.gitlab4j.api.models.User self = auth.getMyself();
                User user = User.current();
                if (user != null) {
                    user.setFullName(self.getName());
                    // Set email from gitlab only if empty
                    if (!user.getProperty(Mailer.UserProperty.class).hasExplicitlyConfiguredAddress()) {
                        user.addProperty(
                                new Mailer.UserProperty(auth.getMyself().getEmail()));
                    }
                }
                SecurityListener.fireAuthenticated2(new GitLabOAuthUserDetails(self, auth.getAuthorities()));
            } catch (GitLabApiException e) {
                throw new RuntimeException(e);
            }
        } else {
            Log.info("GitLab did not return an access token.");
        }

        if (StringUtils.isNotBlank(referer)) {
            return HttpResponses.redirectTo(referer);
        }
        return HttpResponses.redirectToContextRoot();
    }

    /**
     * Returns the proxy to be used when connecting to the given URI.
     */
    private HttpHost getProxy(HttpUriRequest method) {
        Jenkins jenkins = Jenkins.get();
        ProxyConfiguration proxy = jenkins.proxy;
        if (proxy == null) {
            return null; // defensive check
        }

        Proxy p = proxy.createProxy(method.getURI().getHost());
        switch (p.type()) {
            case DIRECT:
                return null; // no proxy
            case HTTP:
                InetSocketAddress sa = (InetSocketAddress) p.address();
                return new HttpHost(sa.getHostName(), sa.getPort());
            case SOCKS:
            default:
                return null; // not supported yet
        }
    }

    private String extractToken(String content) {

        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode jsonTree = mapper.readTree(content);
            JsonNode node = jsonTree.get("access_token");
            if (node != null) {
                return node.asText();
            }
        } catch (IOException e) {
            Log.error(e.getMessage(), e);
        }
        return null;
    }

    /**
     * To store the state parameter in the user's session.
     */
    private static final String STATE_ATTRIBUTE = "state";

    /*
     * (non-Javadoc)
     *
     * @see hudson.security.SecurityRealm#allowsSignup()
     */
    @Override
    public boolean allowsSignup() {
        return false;
    }

    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents(
                new AuthenticationManager() {

                    @Override
                    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                        if (authentication instanceof GitLabAuthenticationToken) {
                            return authentication;
                        }
                        if (authentication instanceof UsernamePasswordAuthenticationToken) {
                            try {
                                UsernamePasswordAuthenticationToken token =
                                        (UsernamePasswordAuthenticationToken) authentication;
                                GitLabAuthenticationToken gitlab = new GitLabAuthenticationToken(
                                        token.getCredentials().toString(), getGitlabApiUri(), TokenType.PRIVATE);
                                SecurityContextHolder.getContext().setAuthentication(gitlab);
                                return gitlab;
                            } catch (GitLabApiException e) {
                                throw new RuntimeException(e);
                            }
                        }
                        throw new BadCredentialsException("Unexpected authentication type: " + authentication);
                    }
                },
                new UserDetailsService() {
                    @Override
                    public UserDetails loadUserByUsername(String username)
                            throws UsernameNotFoundException {
                        return GitLabSecurityRealm.this.loadUserByUsername2(username);
                    }
                });
    }

    @Override
    public String getLoginUrl() {
        return "securityRealm/commenceLogin";
    }

    @Override
    protected String getPostLogOutUrl2(StaplerRequest2 req, Authentication auth) {
        // if we just redirect to the root and anonymous does not have Overall read then we will start a login all over
        // again.
        // we are actually anonymous here as the security context has been cleared
        Jenkins jenkins = Jenkins.get();
        if (jenkins.hasPermission(Jenkins.READ)) {
            // TODO until JEP-227 is merged and core requirement is updated, this will prevent stackoverflow
            return req.getContextPath() + "/";
        }
        return req.getContextPath() + "/" + GitLabLogoutAction.POST_LOGOUT_URL;
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {

        @Override
        public String getHelpFile() {
            return "/plugin/gitlab-oauth/help/help-security-realm.html";
        }

        @Override
        public String getDisplayName() {
            return "GitLab Authentication Plugin";
        }

        public DescriptorImpl() {
            // default constructor
        }

        public DescriptorImpl(Class<? extends SecurityRealm> clazz) {
            super(clazz);
        }
    }

    // Overridden for better type safety.
    // If your plugin doesn't really define any property on Descriptor,
    // you don't have to do this.
    @Override
    public DescriptorImpl getDescriptor() {
        return (DescriptorImpl) super.getDescriptor();
    }

    /**
     * @param username
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername2(String username) throws UsernameNotFoundException {
        GitLabAuthenticationToken authToken;
        if (SecurityContextHolder.getContext().getAuthentication() instanceof GitLabAuthenticationToken) {
            authToken = (GitLabAuthenticationToken)
                    SecurityContextHolder.getContext().getAuthentication();
        } else {
            throw new UserMayOrMayNotExistException2("Could not get auth token.");
        }

        try {
            GitLabOAuthUserDetails userDetails = authToken.getUserDetails(username);
            if (userDetails == null) {
                throw new UsernameNotFoundException("Unknown user: " + username);
            }

            // Check the username is not an homonym of an organization
            Group ghOrg = authToken.loadOrganization(username);
            if (ghOrg != null) {
                throw new UsernameNotFoundException("user(" + username + ") is also an organization");
            }

            return userDetails;
        } catch (Error e) {
            throw new AuthenticationServiceException("loadUserByUsername (username=" + username + ")", e);
        }
    }

    /**
     * Compare an object against this instance for equivalence.
     *
     * @param object An object to campare this instance to.
     * @return true if the objects are the same instance and configuration.
     */
    @Override
    public boolean equals(Object object) {
        if (object instanceof GitLabSecurityRealm) {
            GitLabSecurityRealm obj = (GitLabSecurityRealm) object;
            return this.getGitlabWebUri().equals(obj.getGitlabWebUri())
                    && this.getGitlabApiUri().equals(obj.getGitlabApiUri())
                    && this.getClientID().equals(obj.getClientID())
                    && this.clientSecret.equals(obj.clientSecret);
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {
        return HashCodeBuilder.reflectionHashCode(this, false);
    }

    /**
     * @param groupName
     * @throws UsernameNotFoundException
     */
    @Override
    public GroupDetails loadGroupByGroupname2(String groupName, boolean fetchMembers) throws UsernameNotFoundException {

        GitLabAuthenticationToken authToken =
                (GitLabAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();

        if (authToken == null) {
            throw new UsernameNotFoundException("No known group: " + groupName);
        }

        Group gitlabGroup = authToken.loadOrganization(groupName);
        return new GitLabOAuthGroupDetails(gitlabGroup);
    }

    /**
     * Logger for debugging purposes.
     */
    private static final Logger LOGGER = Logger.getLogger(GitLabSecurityRealm.class.getName());

    private static final String REFERER_ATTRIBUTE = GitLabSecurityRealm.class.getName() + ".referer";
}
