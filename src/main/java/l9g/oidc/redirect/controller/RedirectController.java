/*
 * Copyright 2025 Thorsten Ludewig (t.ludewig@gmail.com).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package l9g.oidc.redirect.controller;

import jakarta.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;
import l9g.oidc.redirect.config.RedirectServicesConfig;
import l9g.oidc.redirect.config.RedirectServicesConfig.ServiceConfig;
import l9g.oidc.redirect.dto.OAuth2Tokens;
import l9g.oidc.redirect.service.JwtService;
import l9g.oidc.redirect.service.OidcService;
import l9g.oidc.redirect.service.PKCE;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

/**
 *
 * @author Thorsten Ludewig (t.ludewig@gmail.com)
 */
@Slf4j
@RestController()
@RequiredArgsConstructor
public class RedirectController
{
  private static final String SESSION_OAUTH2_STATE = "oauth2State";

  private static final String SESSION_OAUTH2_TOKENS = "oauth2Tokens";

  private static final String SESSION_REDIRECT_SERVICE_ID = "redirectServiceId";

  private static final String SESSION_REDIRECT_IDP_HINT = "redirectIdpHint";

  private static final String SESSION_OAUTH2_CODE_VERIFIER = "oauth2CodeVerifier";

  private final OidcService oidcService;

  private final JwtService jwtService;

  private final RedirectServicesConfig redirectServicesConfig;

  private final HashMap<String, HttpSession> sessionStore = new HashMap<>();

  @Value("${oauth2.client.id}")
  private String oauth2ClientId;

  @Value("${oauth2.client.scope}")
  private String oauth2ClientScope;

  @Value("${oauth2.redirect-uri}")
  private String oauth2RedirectUri;

  @Value("${valid-idp-hints}")
  private List<String> validIdpHints;

  @GetMapping
  public ResponseEntity<Void> redirect(
    @RequestParam(name = "service-id", required = true) String serviceId,
    @RequestParam(name = "idp-hint", required = true) String idpHint,
    HttpSession session, Model model)
    throws Exception
  {
    log.debug("redirect serviceId = {}, idpHint = {}", serviceId, idpHint);
    log.debug("valid idp hints = {}", validIdpHints);
    log.debug("redirect service = {}", redirectServicesConfig);

    if ( !validIdpHints.contains(idpHint))
    {
      log.error("Error: invalid idp hint '{}'", idpHint);
      return ResponseEntity
        .status(404)
        .build();
    }
    
    /*
    OAuth2Tokens oauth2Tokens = (OAuth2Tokens)session.getAttribute(SESSION_OAUTH2_TOKENS);
    if(oauth2Tokens != null && oauth2Tokens.idToken() != null)
    {
      log.debug("Session already authenticated");
      return ResponseEntity
        .status(302)
        .header("Location", DEV_SERVICE_URI)
        .build();
    }
     */
    session.setAttribute(SESSION_REDIRECT_SERVICE_ID, serviceId);
    session.setAttribute(SESSION_REDIRECT_IDP_HINT, idpHint);

    String oauth2State = UUID.randomUUID().toString();
    String oauth2CodeVerifier = PKCE.generateCodeVerifier();
    String oauth2CodeChallenge = PKCE.generateCodeChallenge(oauth2CodeVerifier);

    session.setAttribute(SESSION_OAUTH2_STATE, oauth2State);
    session.setAttribute(SESSION_OAUTH2_CODE_VERIFIER, oauth2CodeVerifier);

    UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(
      oidcService.getOauth2AuthorizationEndpoint());
    builder.queryParam("client_id", oauth2ClientId);
    builder.queryParam("response_type", "code");
    builder.queryParam("redirect_uri", oauth2RedirectUri);
    builder.queryParam("scope", oauth2ClientScope);
    builder.queryParam("state", oauth2State);
    builder.queryParam("code_challenge", oauth2CodeChallenge);
    builder.queryParam("code_challenge_method", "S256");
    builder.queryParam("kc_idp_hint", idpHint);
    String oauth2LoginUri = builder.build().toUriString();
    log.debug("oauth2LoginUri={}", oauth2LoginUri);

    return ResponseEntity
      .status(302)
      .header("Location", oauth2LoginUri)
      .build();
  }

  @GetMapping("/login")
  public ResponseEntity<Void> oidcLogin(
    @RequestParam(name = "code", required = false) String code,
    @RequestParam(name = "state", required = false) String state,
    @RequestParam(name = "error", required = false) String error,
    @RequestParam(name = "error_description", required = false) String errorDescription,
    HttpSession session,
    Model model)
  {
    log.debug("oidcLogin: code={}", code);
    log.debug("oidcLogin: state={}", state);
    log.debug("oidcLogin: error={}", error);
    log.debug("oidcLogin: error_description={}", errorDescription);

    if(error != null &&  ! error.isBlank())
    {
      log.error("Error: {} / {}", error, errorDescription);
      return ResponseEntity
        .status(404)
        .build();
    }

    String oauth2State = (String)session.getAttribute(SESSION_OAUTH2_STATE);

    if(oauth2State == null ||  ! oauth2State.equals(state))
    {
      log.error("Illegal 'state'");
      return ResponseEntity
        .status(404)
        .build();
    }

    OAuth2Tokens tokens = oidcService.fetchOAuth2Tokens(
      code, (String)session.getAttribute(SESSION_OAUTH2_CODE_VERIFIER), oauth2RedirectUri);
    session.setAttribute(SESSION_OAUTH2_TOKENS, tokens);

    log.debug("service id = {}", session.getAttribute(SESSION_REDIRECT_SERVICE_ID));
    log.debug("idp hint = {}", session.getAttribute(SESSION_REDIRECT_IDP_HINT));

    sessionStore.put(
      jwtService.decodeJwtPayload(tokens.idToken()).get("sid"), session);

    ServiceConfig service = redirectServicesConfig.getMap()
      .get(session.getAttribute(SESSION_REDIRECT_SERVICE_ID));

    if(service == null ||  ! service.isEnabled())
    {
      return ResponseEntity
        .status(404)
        .build();
    }

    return ResponseEntity
      .status(302)
      .header("Location", service.getServiceUri())
      .build();
  }

  @GetMapping("/logout")
  public ResponseEntity<Void> oidcLogout(HttpSession session)
  {
    log.debug("oidcLogout");
    session.invalidate();
    return ResponseEntity.ok().build();
  }

  @PostMapping("/backchannel-logout")
  public ResponseEntity<Void> handleBackchannelLogout(@RequestBody String logoutToken)
  {
    log.debug("handleBackchannelLogout logoutToken={}", logoutToken);
    log.debug("decoded logoutToken={}", jwtService.decodeJwtPayload(logoutToken));

    String sid = jwtService.decodeJwtPayload(logoutToken).get("sid");

    if(sid != null)
    {
      HttpSession session = sessionStore.get(sid);
      if(session != null)
      {
        log.debug("invalidate session {}", session.getId());
        session.invalidate();
        sessionStore.remove(sid);
      }
    }

    return ResponseEntity.ok().build();
  }

}
