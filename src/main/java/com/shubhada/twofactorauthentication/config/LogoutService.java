package com.shubhada.twofactorauthentication.config;

import com.shubhada.twofactorauthentication.token.TokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {
    private final TokenRepository tokenRepository;

    @Override
    public void logout(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication)
    {

        final String authHeader=request.getHeader("Authorization");//this header contains JWT
        final String jwt;


        //check JWT Token
        if(authHeader==null || !authHeader.startsWith("Bearer "))
        {
            return;//don't want to continue with rest of filters
        }
        //extract jwt token
        jwt=authHeader.substring(7);

        var storedToken=tokenRepository.findByToken(jwt)
                .orElse(null);
        if(storedToken!=null)
        {
            //header is valid, valid token
            storedToken.setExpired(true);
            storedToken.setRevoked(true);
            tokenRepository.save(storedToken);
        }
    }
}
