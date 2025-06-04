package io.github.zeviabramovich.ecommerce.user.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class LoginRequest {
    @Email(message = "Email format is invalid")
    @NotBlank(message = "Email is required")
    private String email;

    @NotBlank(message = "Password is required")
    private String password;
}
