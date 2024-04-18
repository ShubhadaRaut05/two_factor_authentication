package com.shubhada.twofactorauthentication.Auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.shubhada.twofactorauthentication.config.JwtService;
import com.shubhada.twofactorauthentication.models.Role;
import com.shubhada.twofactorauthentication.models.User;
import com.shubhada.twofactorauthentication.repositories.UserRepository;
import com.shubhada.twofactorauthentication.token.Token;
import com.shubhada.twofactorauthentication.token.TokenRepository;
import com.shubhada.twofactorauthentication.token.TokenType;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
private final UserRepository repository;
private final TokenRepository tokenRepository;
private final PasswordEncoder passwordEncoder;
private final JwtService jwtService;
private final AuthenticationManager authenticationManager;
    public AuthenticationResponse register(RegisterRequest request) {
        var user= User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        var savedUser= repository.save(user);
        var jwtToken=jwtService.generateToken(user);
        var refreshToken=jwtService.generateRefreshToken(user);
        //after generating token we need to persist token into db
        saveUserToken(savedUser, jwtToken);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }


    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        //if both username and password are correct need to create user
        var user=repository.findByEmail(request.getEmail())
                .orElseThrow();
        var jwtToken=jwtService.generateToken(user);
        var refreshToken=jwtService.generateRefreshToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user,jwtToken);//save token after authentication complete
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }
    private void revokeAllUserTokens(User user)
    {
        var validUserTokens=tokenRepository.findAllValidTokensByUser(user.getId());
        if(validUserTokens.isEmpty())
        {
            return;
        }
        validUserTokens.forEach(t->{
            t.setExpired(true);
            t.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }

    private void saveUserToken(User user, String jwtToken) {
        var token= Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .revoked(false) //when we create token, not yet revoked and expired yet
                .expired(false)
                .build();
        tokenRepository.save(token);
    }

    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {

        final String authHeader=request.getHeader(HttpHeaders.AUTHORIZATION);//this header contains JWT
        final String refreshToken;
        final String userEmail;

        //check JWT Token
        if(authHeader==null || !authHeader.startsWith("Bearer "))
        {
            return;//don't want to continue with rest of filters
        }
        //extract jwt token
        refreshToken=authHeader.substring(7);
        //extract user email from jwt
        userEmail=jwtService.extractUsername(refreshToken);

        if(userEmail!=null && SecurityContextHolder.getContext().getAuthentication()==null)
        {
            //authentication is null i.e user is not yet authenticate
            //get data from database
           var user=this.repository.findByEmail(userEmail)
                   .orElseThrow();

            if(jwtService.isTokenValid(refreshToken,user) )
            {
               var accessToken=jwtService.generateToken(user);
               revokeAllUserTokens(user);
               saveUserToken(user,accessToken);
               var authResponse=AuthenticationResponse.builder()
                       .accessToken(accessToken)
                       .refreshToken(refreshToken)
                       .build();
               new ObjectMapper().writeValue(response.getOutputStream(),authResponse);
            }
        }

    }

    //}
}
