package com.example.OAuth2;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Component
public class OAuthLoginSuccessHandler implements AuthenticationSuccessHandler {
  private static final Logger log = LoggerFactory.getLogger(OAuthLoginSuccessHandler.class);

  @Autowired
  private OAuth2AuthorizedClientService clientService;

  @Override
  public void onAuthenticationSuccess(
      HttpServletRequest request, HttpServletResponse response, Authentication authentication)
      throws IOException, ServletException {

    log.info("onAuthenticationSuccess : {}", authentication.getPrincipal());

    OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;

    OAuth2AuthorizedClient client =clientService.loadAuthorizedClient(token.getAuthorizedClientRegistrationId(), token.getName());

    response.setStatus(HttpServletResponse.SC_OK);
    response.setContentType("application/json");
    response.setCharacterEncoding("UTF-8");
//    response.getWriter().write(token.toString());
    response.getWriter().write(client.getAccessToken().getTokenValue());
  }
}
