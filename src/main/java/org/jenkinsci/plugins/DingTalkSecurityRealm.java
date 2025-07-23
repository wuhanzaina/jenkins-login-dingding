package org.jenkinsci.plugins;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.security.SecurityRealm;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import jenkins.security.SecurityListener;
import org.apache.http.client.fluent.Request;
import org.apache.http.entity.ContentType;
import org.kohsuke.stapler.*;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.logging.Logger;

/**
 * 基于钉钉扫码登录的 SecurityRealm 实现
 */
public class DingTalkSecurityRealm extends SecurityRealm {
    private static final Logger LOGGER = Logger.getLogger(DingTalkSecurityRealm.class.getName());

    private final String appKey;
    private final Secret appSecret;
    //private final String redirectUri;

    @DataBoundConstructor
    public DingTalkSecurityRealm(String appKey, String appSecret) {
        this.appKey = Util.fixEmptyAndTrim(appKey);
        this.appSecret = Secret.fromString(Util.fixEmptyAndTrim(appSecret));

    }

    public String getAppKey() {
        return appKey;
    }

    public Secret getAppSecret() {
        return appSecret;
    }
    //public String getRedirectUri() { return redirectUri; }


    /**
     * 登录入口：重定向到钉钉扫码登录页
     */
    public HttpResponse doCommenceLogin(StaplerRequest2 req, @QueryParameter String from) throws IOException {
        String state = UUID.randomUUID().toString();
        // 保存 state 防 CSRF，并保存原始请求路径
        HttpSession session = req.getSession(true);
        session.setAttribute("DINGTALK_OAUTH_STATE", state);
        session.setAttribute("DINGTALK_OAUTH_ORIGIN", from != null ? from : Jenkins.get().getRootUrl());
        String redirectUri = Jenkins.get().getRootUrl() + "securityRealm/finishLogin";

        String redirectUriEncoded = URLEncoder.encode(redirectUri, StandardCharsets.UTF_8);

        String dingAuthUrl = "https://login.dingtalk.com/oauth2/auth"
                + "?redirect_uri=" + redirectUriEncoded
                + "&response_type=code"
                + "&client_id=" + appKey
                + "&scope=openid%20corpid"
                + "&state=" + state
                + "&prompt=consent";
        System.out.println(dingAuthUrl);
        return HttpResponses.redirectTo(dingAuthUrl);

    }


    /**
     * 回调处理：使用 code 换取用户信息，并在 Jenkins 里完成登录
     */
    public HttpResponse doFinishLogin(StaplerRequest2 req) throws IOException {
        String code = req.getParameter("code");
        String state = req.getParameter("state");

        HttpSession session = (HttpSession) req.getSession(false);
        if (session == null || !state.equals(session.getAttribute("DINGTALK_OAUTH_STATE"))) {
            LOGGER.warning("钉钉 OAuth state 校验失败");
            return HttpResponses.redirectToContextRoot();
        }

        // 1. 获取钉钉 access_token（应用级）
        String tokenResp = Request.Post("https://api.dingtalk.com/v1.0/oauth2/userAccessToken")
                .addHeader("Content-Type", "application/json")
                .bodyString(
                        new ObjectMapper().writeValueAsString(Map.of(
                                "clientId", appKey,
                                "clientSecret", appSecret.getPlainText(),
                                "code", code,
                                "grantType", "authorization_code"
                        )),
                        ContentType.APPLICATION_JSON
                ).execute().returnContent().asString(StandardCharsets.UTF_8);

        JsonNode tokenJson = new ObjectMapper().readTree(tokenResp);
        String accessToken = tokenJson.path("accessToken").asText();

        String userMeResp = Request.Get("https://api.dingtalk.com/v1.0/contact/users/me")
                .addHeader("x-acs-dingtalk-access-token", accessToken)
                .execute().returnContent().asString(StandardCharsets.UTF_8);

        JsonNode meJson = new ObjectMapper().readTree(userMeResp);
        String unionId = meJson.path("unionId").asText();
        String nick = meJson.path("nick").asText(); // 昵称

        // 3. 构造 Jenkins Authentication
        DingTalkAuthenticationToken auth = new DingTalkAuthenticationToken(unionId, nick);
        SecurityContextHolder.getContext().setAuthentication(auth);

        // 4. 更新 Jenkins User 对象
        User u = User.current();
        if (u != null) {
            u.setFullName(nick);

            u.save();
        }
        // 4. 通知 Jenkins 完成认证（替换掉 fireLoggedIn）
        SecurityListener.fireAuthenticated2((UserDetails) auth);

        // 5. 重定向回原页面
        String origin = (String) session.getAttribute("DINGTALK_OAUTH_ORIGIN");
        return HttpResponses.redirectTo(
                origin != null ? origin : Jenkins.get().getRootUrl()
        );

    }

    @Override
    public SecurityComponents createSecurityComponents() {
        // 1. 认证管理器：只接受我们自定义的 DingTalkAuthenticationToken
        AuthenticationManager authManager = new AuthenticationManager() {
            @Override
            public Authentication authenticate(Authentication authentication) {
                if (authentication instanceof DingTalkAuthenticationToken) {
                    // 已经是我们发起的、并且在 doFinishLogin 中 setAuthenticated(true) 的令牌
                    return authentication;
                }
                throw new BadCredentialsException("Unsupported authentication: " + authentication);
            }
        };

        // 2. 用户详情服务：Jenkins 会在内部调用 loadUserByUsername2，使用 unionId 作为 username
        UserDetailsService uds = this::loadUserByUsername2;

        return new SecurityComponents(authManager, uds);
    }

    @Override
    public UserDetails loadUserByUsername2(String username) throws UsernameNotFoundException {
        // username 传入的是 unionId
        String unionId = username;

        // 从 SecurityContext 取我们当时保存的 token
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (!(auth instanceof DingTalkAuthenticationToken)) {
            throw new UsernameNotFoundException("Unexpected authentication type: " + auth);
        }
        String nick = ((DingTalkAuthenticationToken) auth).getNick();

        // 构造至少带一个角色的权限列表
        List<GrantedAuthority> authorities =
                AuthorityUtils.createAuthorityList("ROLE_USER");  // 或者 "authenticated"

        // 用 Spring 的 UserDetailsBuilder，username/nick 可根据喜好调换
        return org.springframework.security.core.userdetails.User
                .withUsername(nick)          // Jenkins UI 上显示的账号名
                .password("")                // OAuth2 无需密码
                .authorities(authorities)
                .accountExpired(false)
                .accountLocked(false)
                .credentialsExpired(false)
                .disabled(false)
                .build();
    }


    @Override
    public String getLoginUrl() {
        return "/securityRealm/commenceLogin";
    }

    @Override
    public boolean allowsSignup() {
        return false;
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<SecurityRealm> {
        @Override
        public String getDisplayName() {
            return "钉钉扫码登录";
        }
    }

    // ----- 自定义 AuthenticationToken -----
    public static class DingTalkAuthenticationToken extends AbstractAuthenticationToken implements UserDetails {

        private final String unionId, nick;

        public DingTalkAuthenticationToken(String unionId, String nick) {
            super(AuthorityUtils.createAuthorityList("authenticated"));
            this.unionId = unionId;
            this.nick = nick;
            setAuthenticated(true);
        }

        // Authentication 接口
        @Override
        public Object getCredentials() {
            return "";
        }

        @Override
        public Object getPrincipal() {
            return this;
        }

        @Override
        public String getName() {
            return unionId;
        }

        // UserDetails 接口
        @Override
        public String getUsername() {
            return unionId;
        }

        @Override
        public String getPassword() {
            return "";
        }

        @Override
        public Collection<GrantedAuthority> getAuthorities() {
            return AuthorityUtils.createAuthorityList("authenticated");
        }


        @Override
        public boolean isAccountNonExpired() {
            return true;
        }

        @Override
        public boolean isAccountNonLocked() {
            return true;
        }

        @Override
        public boolean isCredentialsNonExpired() {
            return true;
        }

        @Override
        public boolean isEnabled() {
            return true;
        }

        // getter for nick
        public String getNick() {
            return nick;
        }
    }

}
