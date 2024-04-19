package com.shubhada.twofactorauthentication.Auth;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_EMPTY)
//if user did not enable tfa, secretImageUri will be empty, client will not see this attribute
public class AuthenticationResponse {

    private String accessToken;

    private String refreshToken;

    private boolean mfaEnabled;
    private String secretImageUri;
}
