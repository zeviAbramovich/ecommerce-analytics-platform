package io.github.zeviabramovich.ecommerce.user.dto;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class UserSummary {
    private String userId;
    private String email;
    private String fullName;
    private LocalDateTime createdAt;
    private LocalDateTime lastLoginAt;
    private Boolean isActive;
}
