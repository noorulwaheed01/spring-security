package com.example.OAuth2;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.web.SecurityFilterChain;

@Configuration

public class Security {

    @Autowired
    private OAuthLoginSuccessHandler oAuth2SuccessHandler;
    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

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
                            .authorizationEndpoint(auth -> auth
                                    .authorizationRequestResolver(authorizationRequestResolver(clientRegistrationRepository))
                            )
                    .successHandler(oAuth2SuccessHandler)
            );
    return http.build();
  }

    /**
     * 👇 This is the KEY part: adds audience to Auth0 request
     */
    @Bean
    public OAuth2AuthorizationRequestResolver authorizationRequestResolver(
            ClientRegistrationRepository repo) {

        DefaultOAuth2AuthorizationRequestResolver resolver =
                new DefaultOAuth2AuthorizationRequestResolver(
                        repo, "/oauth2/authorization");

        resolver.setAuthorizationRequestCustomizer(builder ->
                builder.additionalParameters(params ->
                        params.put("audience", "https://testing.com")
                )
        );

        return resolver;
    }
}
