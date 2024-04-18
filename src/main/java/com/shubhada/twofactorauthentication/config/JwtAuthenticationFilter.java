package com.shubhada.twofactorauthentication.config;

import com.shubhada.twofactorauthentication.token.TokenRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final TokenRepository tokenRepository;


    @Override
    protected void doFilterInternal(
         @NonNull HttpServletRequest request,
         @NonNull HttpServletResponse response,
         @NonNull  FilterChain filterChain) //it contains list of other filters we need to execute
            throws ServletException, IOException {

        final String authHeader=request.getHeader("Authorization");//this header contains JWT
        final String jwt;
        final String userEmail;

        //check JWT Token
        if(authHeader==null || !authHeader.startsWith("Bearer "))
        {

            filterChain.doFilter(request,response);
            return;//don't want to continue with rest of filters
        }
        //extract jwt token
        jwt=authHeader.substring(7);
        //extract user email from jwt
        userEmail=jwtService.extractUsername(jwt);

        if(userEmail!=null && SecurityContextHolder.getContext().getAuthentication()==null)
        {
            //authentication is null i.e user is not yet authenticate
            //get data from database
            UserDetails userDetails=this.userDetailsService.loadUserByUsername(userEmail);
            var isTokenValid=tokenRepository.findByToken(jwt)
                    .map(t-> !t.isExpired() && !t.isRevoked())
                    .orElse(false);//need to got to Db and check valid token
            if(jwtService.isTokenValid(jwt,userDetails) && isTokenValid)
            {
                //token is valid update security context holder

                UsernamePasswordAuthenticationToken authToken=new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request)
                );

                //update security context holder
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
       filterChain.doFilter(request,response);
    }
}
