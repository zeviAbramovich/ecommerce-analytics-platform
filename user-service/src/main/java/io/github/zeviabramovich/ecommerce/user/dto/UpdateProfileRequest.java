package io.github.zeviabramovich.ecommerce.user.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UpdateProfileRequest {
    @NotBlank(message = "First name is required")
    @Size(max = 100, message = "First name must be less than 100 characters")
    private String firstName;

    @NotBlank(message = "Last name is required")
    @Size(max = 100, message = "Last name must be less than 100 characters")
    private String lastName;
}
