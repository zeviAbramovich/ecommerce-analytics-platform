package io.github.zeviabramovich.ecommerce.user.service;

import io.github.zeviabramovich.ecommerce.user.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
@Slf4j
public class JwtTokenService {
    private final SecretKey secretKey;

    @Value("${app.jwt.expiration-hours:24}")
    private Long expirationHours;

    @Value("${app.jwt.issuer:ecommerce-platform}")
    private String issuer;

    public JwtTokenService(@Value("${app.jwt.secret:MyDefaultSecretKeyThatShouldBeChangedInProduction123456789}") String secret) {
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes());
        log.info("JWT Token Service initialized with expiration: {} hours", expirationHours);
    }

    public String generateToken(User user) {
        log.debug("Generating JWT token for user: {}", user.getUserId());

        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", user.getUserId());
        claims.put("email", user.getEmail());
        claims.put("firstName", user.getFirstName());
        claims.put("lastName", user.getLastName());
        claims.put("isActive", user.getIsActive());

        return createToken(claims, user.getUserId());
    }

    /**
     * יצירת token עם claims מותאמים אישית
     */
    private String createToken(Map<String, Object> claims, String subject) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + (expirationHours * 60 * 60 * 1000));

        String token = Jwts.builder()
                .claims(claims)                    // המידע שנשמר בtoken
                .subject(subject)                  // המשתמש (userId)
                .issuer(issuer)                    // מי יצר את הtoken
                .issuedAt(now)                     // מתי נוצר
                .expiration(expiryDate)            // מתי פג תוקף
                .signWith(secretKey)               // חתימה עם הsecret key
                .compact();                        // המרה לstring

        log.debug("Token created for subject: {}, expires at: {}", subject, expiryDate);
        return token;
    }

    public String getUserIdFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    public String getEmailFromToken(String token) {
        return getClaimFromToken(token, claims -> claims.get("email", String.class));
    }

    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    private Claims getAllClaimsFromToken(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(secretKey)         // וידוא החתימה
                    .build()
                    .parseSignedClaims(token)      // פיענוח הtoken
                    .getPayload();                 // קבלת הנתונים
        } catch (JwtException e) {
            log.warn("Failed to parse JWT token: {}", e.getMessage());
            throw new IllegalArgumentException("Invalid JWT token", e);
        }
    }

    public Boolean isTokenExpired(String token) {
        try {
            final Date expiration = getExpirationDateFromToken(token);
            return expiration.before(new Date());
        } catch (Exception e) {
            log.warn("Error checking token expiration: {}", e.getMessage());
            return true; // אם יש שגיאה, נחשב שהtoken פג תוקף
        }
    }

    public Boolean validateToken(String token, User user) {
        try {
            final String tokenUserId = getUserIdFromToken(token);
            return (tokenUserId.equals(user.getUserId()) && !isTokenExpired(token) && user.getIsActive());
        } catch (Exception e) {
            log.warn("Token validation failed for user {}: {}", user.getUserId(), e.getMessage());
            return false;
        }
    }

    public Boolean isValidToken(String token) {
        try {
            getAllClaimsFromToken(token); // אם זה לא זורק exception, הtoken תקף
            return !isTokenExpired(token);
        } catch (Exception e) {
            log.debug("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    public String extractTokenFromHeader(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7); // מסיר "Bearer "
        }
        return null;
    }

    public Long getExpirationTime() {
        return expirationHours * 60 * 60; // המרה לשניות
    }

    public String generateRefreshToken(User user) {
        log.debug("Generating refresh token for user: {}", user.getUserId());

        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", user.getUserId());
        claims.put("tokenType", "refresh");

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + (expirationHours * 7 * 24 * 60 * 60 * 1000)); // 7 ימים

        return Jwts.builder()
                .claims(claims)
                .subject(user.getUserId())
                .issuer(issuer)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(secretKey)
                .compact();
    }

    public Boolean isRefreshToken(String token) {
        try {
            String tokenType = getClaimFromToken(token, claims -> claims.get("tokenType", String.class));
            return "refresh".equals(tokenType);
        } catch (Exception e) {
            return false;
        }
    }

    public Map<String, Object> getTokenInfo(String token) {
        Map<String, Object> info = new HashMap<>();
        try {
            Claims claims = getAllClaimsFromToken(token);
            info.put("userId", claims.getSubject());
            info.put("email", claims.get("email"));
            info.put("issuer", claims.getIssuer());
            info.put("issuedAt", claims.getIssuedAt());
            info.put("expiration", claims.getExpiration());
            info.put("isExpired", isTokenExpired(token));
            info.put("isValid", isValidToken(token));
        } catch (Exception e) {
            info.put("error", e.getMessage());
            info.put("isValid", false);
        }
        return info;
    }
}
