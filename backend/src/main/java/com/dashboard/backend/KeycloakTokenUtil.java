package com.dashboard.backend;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;
import com.fasterxml.jackson.databind.ObjectMapper;

@Component
class KeycloakTokenUtil {
    @Value("${spring.security.oauth2.client.provider.keycloak.token-uri}")
    private String tokenUri;

    @Value("${spring.security.oauth2.client.registration.keycloak.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.keycloak.client-secret}")
    private String clientSecret;

    @Value("${spring.security.oauth2.client.registration.keycloak.redirect-uri}")
    private String redirectUri;

    @Value("${spring.security.oauth2.client.provider.keycloak.authorization-uri}")
    private String authorizationUri;

    public Map<String, Object> exchangeCodeForToken(String code) {
      try {
          final HttpClient client = HttpClient.newHttpClient();
  
          String body = String.format(
              "grant_type=authorization_code&client_id=%s&client_secret=%s&redirect_uri=%s&code=%s",
              clientId,
              clientSecret,
              redirectUri,
              code
          );
  
          final HttpRequest request = HttpRequest.newBuilder()
              .uri(URI.create(tokenUri))
              .header("Content-Type", "application/x-www-form-urlencoded")
              .POST(HttpRequest.BodyPublishers.ofString(body))
              .build();
  
          final HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
  
          if (response.statusCode() != 200) {
              throw new RuntimeException("Failed to exchange code for token: " + response.body());
          }
  
          // Parse JSON response
          final ObjectMapper mapper = new ObjectMapper();
          return mapper.readValue(response.body(), Map.class);
      } catch (final Exception e) {
          throw new RuntimeException("Failed to exchange code for token", e);
      }
  }
}
