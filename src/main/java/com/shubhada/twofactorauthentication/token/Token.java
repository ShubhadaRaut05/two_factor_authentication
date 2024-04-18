package com.shubhada.twofactorauthentication.token;

import com.shubhada.twofactorauthentication.models.User;
import jakarta.persistence.*;
import lombok.*;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class Token {

    @Id
    @GeneratedValue
    private Integer id;

    private String token;
    @Enumerated(EnumType.STRING)
    private TokenType tokenType;
    private boolean expired;

    private boolean revoked;
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    public User user;
}
