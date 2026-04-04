package com.example.OAuth2;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class Security {

  @Autowired private OAuthLoginSuccessHandler oAuth2SuccessHandler;

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
            .csrf(AbstractHttpConfigurer::disable)

            .authorizeHttpRequests(auth -> auth
                    .requestMatchers(
                            "/login/**",
                            "/oauth2/**",
                            "/error"
                    ).permitAll()
                    .requestMatchers("/api/**").authenticated()
                    .anyRequest().permitAll()
            )

            .oauth2Login(oauth2 -> oauth2
//                    .authorizationEndpoint(authorization ->
//                            authorization.authorizationRequestRepository(
//                                    new CookieOAuth2AuthorizationRequestRepository()
//                            )
//                    )
                    .successHandler(oAuth2SuccessHandler)
            );
    return http.build();
  }
}
