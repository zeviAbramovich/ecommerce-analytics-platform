package io.github.zeviabramovich.ecommerce.user.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "users", indexes = {
        @Index(name = "idx_user_email", columnList = "email"),
        @Index(name = "idx_user_active", columnList = "isActive"),
        @Index(name = "idx_user_created", columnList = "createdAt")})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User {
    @Id
    @Column(name = "user_id", length = 36)
    private String userId;

    @Email(message = "Email format is invalid")
    @NotBlank(message = "Email is required")
    @Column(name = "email", unique = true, nullable = false)
    @Size(max = 255, message = "Email must be less than 255 characters")
    private String email;

    @NotBlank(message = "Password is required")
    @Column(name = "password_hash", nullable = false)
    @Size(min = 60, max = 255, message = "Password hash must be between 60-255 characters")
    private String passwordHash;

    @NotBlank(message = "First name is required")
    @Column(name = "first_name", nullable = false, length = 100)
    @Size(max = 100, message = "First name must be less than 100 characters")
    private String firstName;

    @NotBlank(message = "Last name is required")
    @Column(name = "last_name", nullable = false, length = 100)
    @Size(max = 100, message = "Last name must be less than 100 characters")
    private String lastName;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @Column(name = "last_login_at")
    private LocalDateTime lastLoginAt;

    @Builder.Default
    @Column(name = "is_active", nullable = false)
    private Boolean isActive = true;

    @PrePersist
    protected void onCreate() {
        if (userId == null) {
            userId = UUID.randomUUID().toString();
        }
    }

    public void markAsLoggedIn() {
        this.lastLoginAt = LocalDateTime.now();
    }

    public void deactivate() {
        this.isActive = false;
    }

    public void activate() {
        this.isActive = true;
    }

    public String getFullName() {
        return firstName + " " + lastName;
    }

    public boolean isNewUser() {
        return lastLoginAt == null;
    }
}
