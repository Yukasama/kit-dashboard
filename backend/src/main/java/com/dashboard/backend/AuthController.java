package com.dashboard.backend;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.UriComponentsBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;

@Controller
@RequestMapping("/auth")
public class AuthController {
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

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

    @Value("${frontend.url}")
    private String frontendUrl;

    private final KeycloakTokenUtil tokenUtil;

    public AuthController(KeycloakTokenUtil tokenUtil) {
        this.tokenUtil = tokenUtil;
        logger.info("AuthController initialized");
    }

    @GetMapping("/login")
    public void login(HttpSession session, HttpServletResponse response) {
        String state = UUID.randomUUID().toString();
        session.setAttribute("oauth_state", state);
        logger.info("Generated OAuth state: {}", state);
    
        String authorizationUrl = String.format(
            "%s?client_id=%s&redirect_uri=%s&response_type=code&scope=openid&state=%s&kc_idp_hint=google&prompt=login",
            authorizationUri, clientId, redirectUri, state
        );
    
        logger.info("Final Authorization URL: {}", authorizationUrl);
    
        try {
            response.setHeader("Location", authorizationUrl);
            response.setStatus(302);
        } catch (Exception e) {
            logger.error("Failed to redirect to Keycloak", e);
        }
    }
    
    @GetMapping("/callback")
    public RedirectView callback(
            @RequestParam final String code,
            @RequestParam final String state,
            final HttpSession session,
            final HttpServletResponse response
            ) {
        logger.info("Received callback with code: {} and state: {}", code, state);

        final String sessionState = (String) session.getAttribute("oauth_state");
        if (sessionState == null || !sessionState.equals(state)) {
            logger.warn("Invalid state parameter. Expected: {}, Received: {}", sessionState, state);
            return new RedirectView(frontendUrl + "/login?error=invalid_state");
        }

        try {
            final Map<String, Object> tokenResponse = tokenUtil.exchangeCodeForToken(code);
            final String accessToken = (String) tokenResponse.get("access_token");
            final String refreshToken = (String) tokenResponse.get("refresh_token");

            if (accessToken == null || refreshToken == null) {
                logger.error("Token response missing access or refresh token");
                return new RedirectView(frontendUrl + "/login?error=token_error");
            }

            logger.info("Obtained access token and refresh token");

            final Cookie accessTokenCookie = createCookie("access_token", accessToken);
            response.addCookie(accessTokenCookie);

            logger.info("Access token cookie added to response");

            return new RedirectView(frontendUrl);
        } catch (Exception e) {
            logger.error("Exception occurred during token exchange", e);
            return new RedirectView(frontendUrl + "/login?error=exception");
        }
    }

    private Cookie createCookie(final String name, final String value) {
        final Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        // TODO Set secure to true in production
        cookie.setSecure(false);
        cookie.setMaxAge(3600);
        logger.debug("Created cookie: {} with expiry: {}", name, cookie.getMaxAge());
        return cookie;
    }
}