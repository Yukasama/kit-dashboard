package com.dashboard.backend;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;

import com.dashboard.backend.auth.utils.KeycloakTokenUtil;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import java.util.Map;
import java.util.UUID;

@Controller
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
class AuthController {
    @Value("${spring.security.oauth2.client.registration.keycloak.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.keycloak.client-secret}")
    private String clientSecret;

    @Value("${spring.security.oauth2.client.registration.keycloak.redirect-uri}")
    private String redirectUri;

    @Value("${spring.security.oauth2.client.provider.keycloak.authorization-uri}")
    private String authorizationUri;

    @Value("${spring.security.oauth2.client.provider.keycloak.token-uri}")
    private String tokenUri;

    private final KeycloakTokenUtil tokenUtil;

    @GetMapping("/login")
    public void login(final HttpSession session, final HttpServletResponse response) {
        String state = UUID.randomUUID().toString();
        session.setAttribute("oauth_state", state);
        log.info("Generated OAuth state: {}", state);
    
        String authorizationUrl = String.format(
            "%s?client_id=%s&redirect_uri=%s&response_type=code&scope=openid&state=%s&kc_idp_hint=google&prompt=login",
            authorizationUri, clientId, redirectUri, state
        );
    
        log.info("Final Authorization URL: {}", authorizationUrl);
    
        try {
            response.setHeader("Location", authorizationUrl);
            response.setStatus(302);
        } catch (Exception e) {
            log.error("Failed to redirect to Keycloak", e);
        }
    }
    
    @GetMapping("/callback")
    public RedirectView callback(
            @RequestParam final String code,
            @RequestParam final String state,
            final HttpSession session,
            final HttpServletResponse response
            ) {
        log.info("Received callback with code: {} and state: {}", code, state);

        final String sessionState = (String) session.getAttribute("oauth_state");
        if (sessionState == null || !sessionState.equals(state)) {
            log.warn("Invalid state parameter. Expected: {}, Received: {}", sessionState, state);
            return new RedirectView("/login?error=invalid_state");
        }

        try {
            final Map<String, Object> tokenResponse = tokenUtil.exchangeCodeForToken(code);
            final String accessToken = (String) tokenResponse.get("access_token");
            final String refreshToken = (String) tokenResponse.get("refresh_token");

            if (accessToken == null || refreshToken == null) {
                log.error("Token response missing access or refresh token");
                return new RedirectView("/login?error=token_error");
            }

            log.info("Obtained access token and refresh token");

            final Cookie accessTokenCookie = createCookie("access_token", accessToken);
            response.addCookie(accessTokenCookie);

            log.info("Access token cookie added to response");

            return new RedirectView("/");
        } catch (Exception e) {
            log.error("Exception occurred during token exchange", e);
            return new RedirectView("/login?error=exception");
        }
    }

    private Cookie createCookie(final String name, final String value) {
        final Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        // TODO Set secure to true in production
        cookie.setSecure(false);
        cookie.setMaxAge(3600);
        log.debug("Created cookie: {} with expiry: {}", name, cookie.getMaxAge());
        return cookie;
    }
}