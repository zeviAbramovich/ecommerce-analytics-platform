package io.github.zeviabramovich.ecommerce.user.controller;

import io.github.zeviabramovich.ecommerce.user.dto.*;
import io.github.zeviabramovich.ecommerce.user.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.Authentication;

import java.util.List;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "User Management", description = "APIs for user registration, authentication, and profile management")
public class UserController {
    private final UserService userService;

    @PostMapping("/register")
    @Operation(summary = "Register new user", description = "Create a new user account with email and password")
    @ApiResponses({
            @ApiResponse(responseCode = "201", description = "User registered successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid input data"),
            @ApiResponse(responseCode = "409", description = "Email already exists")
    })
    public ResponseEntity<io.github.zeviabramovich.ecommerce.user.dto.ApiResponse<UserInfo>> registerUser(@Valid @RequestBody RegisterRequest request) {
        log.info("Registration request received for email: {}", request.getEmail());
        UserInfo userInfo = userService.registerUser(request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(io.github.zeviabramovich.ecommerce.user.dto.ApiResponse.success("User registered successfully", userInfo));
    }

    @PostMapping("/login")
    @Operation(summary = "User login", description = "Authenticate user and return JWT token")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Login successful"),
            @ApiResponse(responseCode = "401", description = "Invalid credentials"),
            @ApiResponse(responseCode = "403", description = "Account deactivated")
    })
    public ResponseEntity<io.github.zeviabramovich.ecommerce.user.dto.ApiResponse<LoginResponse>> loginUser(@Valid @RequestBody LoginRequest request) {
        log.info("Login request received for email: {}", request.getEmail());
        LoginResponse loginResponse = userService.authenticateUser(request);
        return ResponseEntity.ok(io.github.zeviabramovich.ecommerce.user.dto.ApiResponse.success("Login successful", loginResponse));
    }

    @GetMapping("/profile")
    @SecurityRequirement(name = "JWT")
    @Operation(summary = "Get current user profile", description = "Retrieve profile information for authenticated user")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Profile retrieved successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized - JWT token required"),
            @ApiResponse(responseCode = "404", description = "User not found")
    })
    public ResponseEntity<io.github.zeviabramovich.ecommerce.user.dto.ApiResponse<UserInfo>> getCurrentUserProfile() {
        String userId = getCurrentUserId();
        log.debug("Profile request for user: {}", userId);
        UserInfo userInfo = userService.getUserProfile(userId);
        return ResponseEntity.ok(io.github.zeviabramovich.ecommerce.user.dto.ApiResponse.success(userInfo));
    }

    @PutMapping("/profile")
    @SecurityRequirement(name = "JWT")
    @Operation(summary = "Update user profile", description = "Update profile information for authenticated user")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Profile updated successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid input data"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "User not found")
    })
    public ResponseEntity<io.github.zeviabramovich.ecommerce.user.dto.ApiResponse<UserInfo>> updateProfile(@Valid @RequestBody UpdateProfileRequest request) {
        String userId = getCurrentUserId();
        log.info("Profile update request for user: {}", userId);
        UserInfo updatedUserInfo = userService.updateUserProfile(userId, request);
        return ResponseEntity.ok(io.github.zeviabramovich.ecommerce.user.dto.ApiResponse.success("Profile updated successfully", updatedUserInfo));
    }

    @PutMapping("/password")
    @SecurityRequirement(name = "JWT")
    @Operation(summary = "Change password", description = "Change password for authenticated user")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Password changed successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid current password or weak new password"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "User not found")
    })
    public ResponseEntity<io.github.zeviabramovich.ecommerce.user.dto.ApiResponse<String>> changePassword(@Valid @RequestBody ChangePasswordRequest request) {
        String userId = getCurrentUserId();
        log.info("Password change request for user: {}", userId);
        userService.changePassword(userId, request);
        return ResponseEntity.ok(io.github.zeviabramovich.ecommerce.user.dto.ApiResponse.success("Password changed successfully", null));
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    @SecurityRequirement(name = "JWT")
    @Operation(summary = "Get all users", description = "Retrieve list of all users (Admin only)")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Users retrieved successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Admin access required")
    })
    public ResponseEntity<io.github.zeviabramovich.ecommerce.user.dto.ApiResponse<List<UserInfo>>> getAllUsers() {
        log.debug("Admin request for all users");
        List<UserInfo> users = userService.getAllUsers();
        return ResponseEntity.ok(io.github.zeviabramovich.ecommerce.user.dto.ApiResponse.success(users));
    }

    @GetMapping("/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    @SecurityRequirement(name = "JWT")
    @Operation(summary = "Get user by ID", description = "Retrieve user by ID (Admin only)")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "User retrieved successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Admin access required"),
            @ApiResponse(responseCode = "404", description = "User not found")
    })
    public ResponseEntity<io.github.zeviabramovich.ecommerce.user.dto.ApiResponse<UserInfo>> getUserById(@PathVariable String userId) {
        log.debug("Admin request for user: {}", userId);
        UserInfo userInfo = userService.getUserProfile(userId);
        return ResponseEntity.ok(io.github.zeviabramovich.ecommerce.user.dto.ApiResponse.success(userInfo));
    }

    @PutMapping("/{userId}/status")
    @PreAuthorize("hasRole('ADMIN')")
    @SecurityRequirement(name = "JWT")
    @Operation(summary = "Update user status", description = "Activate or deactivate user account (Admin only)")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "User status updated successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Admin access required"),
            @ApiResponse(responseCode = "404", description = "User not found")
    })
    public ResponseEntity<io.github.zeviabramovich.ecommerce.user.dto.ApiResponse<String>> updateUserStatus(
            @PathVariable String userId,
            @RequestParam boolean active) {
        log.info("Admin status update request for user: {} to status: {}", userId, active);
        userService.updateUserStatus(userId, active);
        return ResponseEntity.ok(io.github.zeviabramovich.ecommerce.user.dto.ApiResponse.success(
                "User " + (active ? "activated" : "deactivated") + " successfully", null));
    }

    private String getCurrentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication.getName();
    }
}
