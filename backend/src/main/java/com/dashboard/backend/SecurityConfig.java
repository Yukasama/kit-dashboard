package com.dashboard.backend;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
      http
              .authorizeHttpRequests(authorize -> authorize
                      .requestMatchers("/").permitAll()
                      .requestMatchers("/auth/**").permitAll()
                      .anyRequest().authenticated()
              )
              .oauth2Login(oauth2 -> oauth2
              .authorizationEndpoint(endpoint -> endpoint
              .baseUri("/auth/login")
              )
              )
              .logout(logout -> logout
                      .logoutSuccessUrl("/")
                      .invalidateHttpSession(true)
                      .clearAuthentication(true)
                      .deleteCookies("JSESSIONID")
              );

      return http.build();
  }
}
