package com.shubhada.twofactorauthentication.Auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.shubhada.twofactorauthentication.config.JwtService;
import com.shubhada.twofactorauthentication.models.Role;
import com.shubhada.twofactorauthentication.models.User;
import com.shubhada.twofactorauthentication.repositories.UserRepository;
import com.shubhada.twofactorauthentication.tfa.TwoFactorAuthenticationService;
import com.shubhada.twofactorauthentication.token.Token;
import com.shubhada.twofactorauthentication.token.TokenRepository;
import com.shubhada.twofactorauthentication.token.TokenType;
import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
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
private final TwoFactorAuthenticationService tfaService;
    public AuthenticationResponse register(RegisterRequest request) {
        var user= User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
               // .role(request.getRole())
                .role(Role.ADMIN)
                .mfaEnabled(request.isMfaEnabled())
                .build();
        //if mfaEnabled ---> generate a secret
        if(request.isMfaEnabled())
        {
            user.setSecret(tfaService.generateNewSecret());
        }
       repository.save(user);
        var jwtToken=jwtService.generateToken(user);
        var refreshToken=jwtService.generateRefreshToken(user);
        //after generating token we need to persist token into db
        //saveUserToken(savedUser, jwtToken);
        return AuthenticationResponse.builder()
                .secretImageUri(tfaService.generateQrCodeImageUri(user.getSecret()))
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .mfaEnabled(user.isMfaEnabled())
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
        if(user.isMfaEnabled())
        {
            return  AuthenticationResponse.builder()
                .accessToken("")
                .refreshToken("")
                    .mfaEnabled(true)
                .build();
        }
        var jwtToken=jwtService.generateToken(user);
        var refreshToken=jwtService.generateRefreshToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user,jwtToken);//save token after authentication complete
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .mfaEnabled(false)
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

        if(userEmail!=null )
        {
            //authentication is null  user is not yet authenticate
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
                       .mfaEnabled(false)
                       .build();
                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            }
        }

    }

    public AuthenticationResponse verifyCode(
            VerificationRequest verificationRequest)
    {
        User user=repository.findByEmail(verificationRequest.getEmail())
                .orElseThrow(()->new EntityNotFoundException(
                        String.format("No user found with %s",verificationRequest.getEmail())));
        if(tfaService.isOtpNotValid(user.getSecret(),verificationRequest.getCode()))
        {
            throw new BadCredentialsException("Code is not correct");
        }
        var jwtToken=jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .mfaEnabled(user.isMfaEnabled())
                .build();
    }

    //}
}
