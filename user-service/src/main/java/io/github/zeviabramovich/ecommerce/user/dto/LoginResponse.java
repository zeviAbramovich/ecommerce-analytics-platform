package io.github.zeviabramovich.ecommerce.user.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class LoginResponse {
    private String token;

    @Builder.Default
    private String tokenType = "Bearer";

    private Long expiresIn;

    private UserInfo user;
}
