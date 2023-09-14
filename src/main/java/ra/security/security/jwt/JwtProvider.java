package ra.security.security.jwt;

import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import ra.security.security.user_principle.UserPrinCiple;

import java.security.SignatureException;
import java.util.Date;

@Component
public class JwtProvider {
    public final Logger logger =  LoggerFactory.getLogger(JwtProvider.class);

    @Value("${jwt.secret-key}")
    private String SECRET;
    @Value("${jwt.exprirater}")
    private Long EXPIRED;

    public String generateToken(Authentication authentication) {
        UserPrinCiple userPrinCiple = (UserPrinCiple) authentication.getPrincipal();
        return Jwts.builder().setSubject(userPrinCiple.getUsername())
                .setIssuedAt(new Date()) // thoi gian bat dau
                .setExpiration(new Date(new Date().getTime() + EXPIRED)) // thoi gian ket thuc
                .signWith(SignatureAlgorithm.HS512, SECRET)// chu ki va thuat toan ma hoa , chuoi bi mat
                .compact();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(SECRET).parseClaimsJws(token);
            return true;

        } catch (ExpiredJwtException e) {
            logger.error("Failed -> Expired Token Message {}", e.getMessage());
        }catch (UnsupportedJwtException e) {
            logger.error("Failed -> Unsupported Token Message {}", e.getMessage());
        }catch (MalformedJwtException e) {
            logger.error("Failed -> Invalid Format Token Message {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("Failed -> Claims Empty Token Message {}", e.getMessage());
        }
        return false;
    }
    public String getUserNameFromToken(String token) {
        return Jwts.parser().setSigningKey(SECRET).parseClaimsJws(token).getBody().getSubject();
    }
}
