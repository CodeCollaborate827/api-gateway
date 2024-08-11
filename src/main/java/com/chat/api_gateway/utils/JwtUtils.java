package com.chat.api_gateway.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.function.Function;

@Component
public class JwtUtils {
  @Value("${jwt.secret-key}")
  private String SECRET_KEY;

  private SecretKey getSigningKey() {
    byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
    return Keys.hmacShaKeyFor(keyBytes);
  }

  public String extractUserID(String jwt) {
    Function<Claims, String> claimsStringFunction = claims -> claims.get(Claims.SUBJECT, String.class);
    return extractClaim(jwt, claimsStringFunction);
  }


  private <T> T extractClaim(String jwt, Function<Claims, T> claimsResolver) {
    final Claims claims = extractAllClaims(jwt);
    return claimsResolver.apply(claims);
  }

  private Claims extractAllClaims(String jwt) {
    try {
      return Jwts.parser().verifyWith(getSigningKey()).build().parseSignedClaims(jwt).getPayload();
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    }
  }

  public String extractUserEmail(String jwt) {
    return extractAllClaims(jwt).getSubject();
  }

  public boolean validateAccessToken(String jwt) {
//    final String userAgent = extractUserAgent(jwt);
//    final String ipAddress = extractIpAddress(jwt);
    final String userId = extractUserID(jwt);


     if (isTokenExpired(jwt)) {
      return false;
    }
    return true;
  }



  public boolean isTokenExpired(String jwt) {
    return extractExpiration(jwt).before(new Date());
  }

  private Date extractExpiration(String jwt) {
    return extractClaim(jwt, Claims::getExpiration);
  }
}
