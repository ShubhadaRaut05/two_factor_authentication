package com.shubhada.twofactorauthentication;

import com.shubhada.twofactorauthentication.Auth.AuthenticationService;
import com.shubhada.twofactorauthentication.Auth.RegisterRequest;
import com.shubhada.twofactorauthentication.models.Role;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class TwoFactorAuthenticationApplication {

    public static void main(String[] args) {
        SpringApplication.run(TwoFactorAuthenticationApplication.class, args);
    }
        @Bean
                public CommandLineRunner commandLineRunner(
                        AuthenticationService service
                )
        {
            return args->{
              var admin= RegisterRequest.builder()
                      .firstName("Admin")
                      .lastName("Admin")
                      .email("admin@gmail.com")
                      .password("password")
                      .role(Role.ADMIN)
                      .build();
                System.out.println("Admin token: " + service.register(admin).getAccessToken());

                var manager = RegisterRequest.builder()
                        .firstName("Admin")
                        .lastName("Admin")
                        .email("manager@mail.com")
                        .password("password")
                        .role(Role.MANAGER)
                        .build();
                System.out.println("Manager token: " + service.register(manager).getAccessToken());

            };
        }


}
