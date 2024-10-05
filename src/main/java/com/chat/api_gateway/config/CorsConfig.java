package com.chat.api_gateway.config;

import jakarta.validation.constraints.NotNull;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.reactive.config.CorsRegistry;
import org.springframework.web.reactive.config.EnableWebFlux;
import org.springframework.web.reactive.config.WebFluxConfigurer;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Configuration
@Order(value = Ordered.HIGHEST_PRECEDENCE)
@EnableWebFlux
public class CorsConfig implements WebFluxConfigurer {

  @Override
  public void addCorsMappings(CorsRegistry registry) {
    registry
        .addMapping("/**")
        .allowCredentials(false)
        .allowedOrigins("*")
        .allowedHeaders("*")
        .allowedMethods("*");
  }

  @Bean
  public CorsWebFilter corsWebFilter() {

    // Disable per-request CORS

    return new CorsWebFilter(new UrlBasedCorsConfigurationSource()) {
      @Override
      @NotNull
      public Mono<Void> filter(@NotNull ServerWebExchange exchange, @NotNull WebFilterChain chain) {
        return chain.filter(exchange);
      }
    };
  }
}
