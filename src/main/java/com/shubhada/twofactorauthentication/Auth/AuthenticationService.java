package com.shubhada.twofactorauthentication.Auth;

import com.shubhada.twofactorauthentication.config.JwtService;
import com.shubhada.twofactorauthentication.models.Role;
import com.shubhada.twofactorauthentication.models.User;
import com.shubhada.twofactorauthentication.repositories.UserRepository;
import com.shubhada.twofactorauthentication.token.Token;
import com.shubhada.twofactorauthentication.token.TokenRepository;
import com.shubhada.twofactorauthentication.token.TokenType;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

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
        //after generating token we need to persist token into db
        saveUserToken(savedUser, jwtToken);
        return AuthenticationResponse.builder()
                .token(jwtToken)
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
        revokeAllUserTokens(user);
        saveUserToken(user,jwtToken);//save token after authentication complete
        return AuthenticationResponse.builder()
                .token(jwtToken)
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

    //}
}
