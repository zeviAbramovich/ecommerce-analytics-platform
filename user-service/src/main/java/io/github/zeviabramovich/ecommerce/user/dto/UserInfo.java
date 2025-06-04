package io.github.zeviabramovich.ecommerce.user.dto;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class UserInfo {
    private String userId;
    private String email;
    private String firstName;
    private String lastName;
    private String fullName;
    private LocalDateTime createdAt;
    private LocalDateTime lastLoginAt;
    private Boolean isActive;
    private Boolean isNewUser;
}
