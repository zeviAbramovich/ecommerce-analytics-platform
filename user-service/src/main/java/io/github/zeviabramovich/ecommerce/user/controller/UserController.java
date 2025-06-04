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

        io.github.zeviabramovich.ecommerce.user.dto.ApiResponse<UserInfo> response =
                io.github.zeviabramovich.ecommerce.user.dto.ApiResponse.success(
                        "User registered successfully", userInfo);

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/login")
    @Operation(summary = "User login", description = "Authenticate user and return JWT token")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Login successful"),
            @ApiResponse(responseCode = "401", description = "Invalid credentials"),
            @ApiResponse(responseCode = "403", description = "Account deactivated")
    })
    public ResponseEntity<io.github.zeviabramovich.ecommerce.user.dto.ApiResponse<LoginResponse>> loginUser(
            @Valid @RequestBody LoginRequest request) {

        log.info("Login request received for email: {}", request.getEmail());

        LoginResponse loginResponse = userService.authenticateUser(request);

        io.github.zeviabramovich.ecommerce.user.dto.ApiResponse<LoginResponse> response =
                io.github.zeviabramovich.ecommerce.user.dto.ApiResponse.success(
                        "Login successful", loginResponse);

        return ResponseEntity.ok(response);
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

        io.github.zeviabramovich.ecommerce.user.dto.ApiResponse<UserInfo> response =
                io.github.zeviabramovich.ecommerce.user.dto.ApiResponse.success(userInfo);

        return ResponseEntity.ok(response);
    }

    @GetMapping("/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    @SecurityRequirement(name = "JWT")
    @Operation(summary = "Get user profile by ID", description = "Retrieve user profile by user ID (Admin only)")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Profile retrieved successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Admin access required"),
            @ApiResponse(responseCode = "404", description = "User not found")
    })
    public ResponseEntity<io.github.zeviabramovich.ecommerce.user.dto.ApiResponse<UserInfo>> getUserProfile(
            @Parameter(description = "User ID") @PathVariable String userId) {

        log.debug("Admin profile request for user: {}", userId);

        UserInfo userInfo = userService.getUserProfile(userId);

        io.github.zeviabramovich.ecommerce.user.dto.ApiResponse<UserInfo> response =
                io.github.zeviabramovich.ecommerce.user.dto.ApiResponse.success(userInfo);

        return ResponseEntity.ok(response);
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
    public ResponseEntity<io.github.zeviabramovich.ecommerce.user.dto.ApiResponse<UserInfo>> updateProfile(
            @Valid @RequestBody UpdateProfileRequest request) {

        String userId = getCurrentUserId();
        log.info("Profile update request for user: {}", userId);

        UserInfo updatedUserInfo = userService.updateUserProfile(userId, request);

        io.github.zeviabramovich.ecommerce.user.dto.ApiResponse<UserInfo> response =
                io.github.zeviabramovich.ecommerce.user.dto.ApiResponse.success(
                        "Profile updated successfully", updatedUserInfo);

        return ResponseEntity.ok(response);
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
    public ResponseEntity<io.github.zeviabramovich.ecommerce.user.dto.ApiResponse<String>> changePassword(
            @Valid @RequestBody ChangePasswordRequest request) {

        String userId = getCurrentUserId();
        log.info("Password change request for user: {}", userId);

        userService.changePassword(userId, request);

        io.github.zeviabramovich.ecommerce.user.dto.ApiResponse<String> response =
                io.github.zeviabramovich.ecommerce.user.dto.ApiResponse.success(
                        "Password changed successfully", null);

        return ResponseEntity.ok(response);
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    @SecurityRequirement(name = "JWT")
    @Operation(summary = "Get all active users", description = "Retrieve list of all active users (Admin only)")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Users retrieved successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Admin access required")
    })
    public ResponseEntity<io.github.zeviabramovich.ecommerce.user.dto.ApiResponse<List<UserSummary>>> getAllUsers() {

        log.debug("Admin request for all active users");

        List<UserSummary> users = userService.getActiveUsers();

        io.github.zeviabramovich.ecommerce.user.dto.ApiResponse<List<UserSummary>> response =
                io.github.zeviabramovich.ecommerce.user.dto.ApiResponse.success(users);

        return ResponseEntity.ok(response);
    }

    @GetMapping("/search")
    @PreAuthorize("hasRole('ADMIN')")
    @SecurityRequirement(name = "JWT")
    @Operation(summary = "Search users by name", description = "Search users by first or last name (Admin only)")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Search completed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Admin access required")
    })
    public ResponseEntity<io.github.zeviabramovich.ecommerce.user.dto.ApiResponse<List<UserSummary>>> searchUsers(
            @Parameter(description = "Search term for user name") @RequestParam String name) {

        log.debug("Admin search request for users with name: {}", name);

        List<UserSummary> users = userService.searchUsersByName(name);

        io.github.zeviabramovich.ecommerce.user.dto.ApiResponse<List<UserSummary>> response =
                io.github.zeviabramovich.ecommerce.user.dto.ApiResponse.success(users);

        return ResponseEntity.ok(response);
    }

    @GetMapping("/stats")
    @PreAuthorize("hasRole('ADMIN')")
    @SecurityRequirement(name = "JWT")
    @Operation(summary = "Get user statistics", description = "Retrieve user statistics and metrics (Admin only)")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Statistics retrieved successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Admin access required")
    })
    public ResponseEntity<io.github.zeviabramovich.ecommerce.user.dto.ApiResponse<UserStats>> getUserStatistics() {

        log.debug("Admin request for user statistics");

        UserStats stats = userService.getUserStatistics();

        io.github.zeviabramovich.ecommerce.user.dto.ApiResponse<UserStats> response =
                io.github.zeviabramovich.ecommerce.user.dto.ApiResponse.success(stats);

        return ResponseEntity.ok(response);
    }

    @PutMapping("/{userId}/deactivate")
    @PreAuthorize("hasRole('ADMIN')")
    @SecurityRequirement(name = "JWT")
    @Operation(summary = "Deactivate user", description = "Deactivate user account (Admin only)")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "User deactivated successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Admin access required"),
            @ApiResponse(responseCode = "404", description = "User not found")
    })
    public ResponseEntity<io.github.zeviabramovich.ecommerce.user.dto.ApiResponse<String>> deactivateUser(
            @Parameter(description = "User ID") @PathVariable String userId) {

        log.info("Admin deactivation request for user: {}", userId);

        userService.deactivateUser(userId);

        io.github.zeviabramovich.ecommerce.user.dto.ApiResponse<String> response =
                io.github.zeviabramovich.ecommerce.user.dto.ApiResponse.success(
                        "User deactivated successfully", null);

        return ResponseEntity.ok(response);
    }

    @PutMapping("/{userId}/activate")
    @PreAuthorize("hasRole('ADMIN')")
    @SecurityRequirement(name = "JWT")
    @Operation(summary = "Activate user", description = "Activate user account (Admin only)")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "User activated successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Admin access required"),
            @ApiResponse(responseCode = "404", description = "User not found")
    })
    public ResponseEntity<io.github.zeviabramovich.ecommerce.user.dto.ApiResponse<String>> activateUser(
            @Parameter(description = "User ID") @PathVariable String userId) {

        log.info("Admin activation request for user: {}", userId);

        userService.activateUser(userId);

        io.github.zeviabramovich.ecommerce.user.dto.ApiResponse<String> response =
                io.github.zeviabramovich.ecommerce.user.dto.ApiResponse.success(
                        "User activated successfully", null);

        return ResponseEntity.ok(response);
    }

    @GetMapping("/health")
    @Operation(summary = "Health check", description = "Check if user service is running")
    @ApiResponse(responseCode = "200", description = "Service is healthy")
    public ResponseEntity<io.github.zeviabramovich.ecommerce.user.dto.ApiResponse<String>> healthCheck() {

        io.github.zeviabramovich.ecommerce.user.dto.ApiResponse<String> response =
                io.github.zeviabramovich.ecommerce.user.dto.ApiResponse.success(
                        "User service is running", "OK");

        return ResponseEntity.ok(response);
    }

    private String getCurrentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new RuntimeException("User not authenticated");
        }

        // זה יעבד אחרי שנגדיר את ה-JWT authentication
        return authentication.getName(); // במקרה של JWT, זה יהיה ה-userId
    }
}
