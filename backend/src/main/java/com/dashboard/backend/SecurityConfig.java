package com.dashboard.backend;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
interface SecurityConfig {
  @Bean
  default SecurityFilterChain filterChain(final HttpSecurity http) throws Exception {
      return http
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
              ).build();
  }
}
