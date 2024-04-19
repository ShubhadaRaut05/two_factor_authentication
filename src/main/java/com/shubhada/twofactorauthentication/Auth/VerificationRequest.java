package com.shubhada.twofactorauthentication.Auth;

import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class VerificationRequest {
    private String email;
    private String code;
}
