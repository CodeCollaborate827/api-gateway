package com.chat.api_gateway.config;

import com.chat.api_gateway.utils.JwtUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.UUID;

@Component
@RequiredArgsConstructor
@Slf4j
public class AuthenticationFilter implements GlobalFilter, Ordered {


  private final JwtUtils jwtUtils;
  private final String USER_ID = "userId";
  private final String REQUEST_ID = "requestId";


  private static final List<String> UN_PROTECTED_ROUTES = List.of(
          "/api/auth/login",
          "/api/auth/register",
          "/api/auth/login-oauth",
          "/api/auth/verify-email",
          "/api/auth/resend-verification-email",
          "/api/auth/forgot-password",
          "/api/auth/reset-password",


          "/api/auth/health",
          "/api/user/health"

  );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
      // continue if the endpoint doesn't need authentication


      if (isUnauthenticatedRoute(exchange.getRequest())) {
        log.info("Authentication is not required");
        return chain.filter(exchange);
      }

      // extract and valid jwt form AUTHORIZATION header
      ServerHttpRequest request = exchange.getRequest();
      // extract the jwt from the header and validate it
      if (!checkValidJwt(request)) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        return response.setComplete();
      }


      log.info("here");
      // if the jwt valid, set the userId to the token
      String userId = extractUserIdFromJwt(request);

      //TODO: handle exception
      ServerHttpRequest mutated = exchange.getRequest().mutate()
              .header(USER_ID, userId)
              .header(REQUEST_ID, UUID.randomUUID().toString())
              .build();

      return chain.filter(exchange.mutate().request(mutated).build());
    }

  private boolean checkValidJwt(ServerHttpRequest request) {
    boolean authorizationHeaderExists = request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION);

    if (!authorizationHeaderExists) {
      return false;
    }

    String jwt = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0).substring(7); // remove the word Bearer
    log.info("jwt: ", jwt);
    return jwtUtils.validateAccessToken(jwt);
  }

  private String extractUserIdFromJwt(ServerHttpRequest request ) {
    String jwt = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0).substring(7); // remove the word Bearer
    return jwtUtils.extractUserID(jwt);
  }

  private static boolean isUnauthenticatedRoute(ServerHttpRequest request) {
    String path = request.getURI().getPath();
    log.info("path: {}", path);
    return UN_PROTECTED_ROUTES.contains(path);
  }

  @Override
    public int getOrder() {
        return -1;
    }
}
