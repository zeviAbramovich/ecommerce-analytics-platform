package io.github.zeviabramovich.ecommerce.user.service;

import io.github.zeviabramovich.ecommerce.user.dto.*;
import io.github.zeviabramovich.ecommerce.user.entity.User;
import io.github.zeviabramovich.ecommerce.user.exception.InvalidCredentialsException;
import io.github.zeviabramovich.ecommerce.user.exception.UserAlreadyExistsException;
import io.github.zeviabramovich.ecommerce.user.exception.UserNotFoundException;
import io.github.zeviabramovich.ecommerce.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenService jwtTokenService;

    @Transactional
    public UserInfo registerUser(RegisterRequest request) {
        log.info("Attempting to register user with email: {}", request.getEmail());

        // בדיקה שהאימייל לא קיים
        if (userRepository.existsByEmail(request.getEmail())) {
            log.warn("Registration failed - email already exists: {}", request.getEmail());
            throw new UserAlreadyExistsException("Email already registered: " + request.getEmail());
        }

        // יצירת משתמש חדש
        User user = User.builder()
                .email(request.getEmail())
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .isActive(true)
                .build();

        User savedUser = userRepository.save(user);
        log.info("User registered successfully with ID: {}", savedUser.getUserId());

        return mapToUserInfo(savedUser);
    }

    @Transactional
    public LoginResponse authenticateUser(LoginRequest request) {
        log.info("Authentication attempt for email: {}", request.getEmail());

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> {
                    log.warn("Authentication failed - user not found: {}", request.getEmail());
                    return new InvalidCredentialsException("Invalid email or password");
                });

        if (!user.getIsActive()) {
            log.warn("Authentication failed - user inactive: {}", request.getEmail());
            throw new InvalidCredentialsException("Account is deactivated");
        }

        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            log.warn("Authentication failed - invalid password for: {}", request.getEmail());
            throw new InvalidCredentialsException("Invalid email or password");
        }

        // עדכון זמן התחברות אחרונה
        user.markAsLoggedIn();
        userRepository.save(user);

        // יצירת JWT token
        String token = jwtTokenService.generateToken(user);
        Long expiresIn = jwtTokenService.getExpirationTime();

        log.info("User authenticated successfully: {}", user.getUserId());

        return LoginResponse.builder()
                .token(token)
                .tokenType("Bearer")
                .expiresIn(expiresIn)
                .user(mapToUserInfo(user))
                .build();
    }

    @Cacheable(value = "user-profiles", key = "#userId")
    public UserInfo getUserProfile(String userId) {
        log.debug("Fetching user profile for ID: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> UserNotFoundException.byUserId("User not found: " + userId));

        return mapToUserInfo(user);
    }

    @Transactional
    @CacheEvict(value = "user-profiles", key = "#userId")
    public UserInfo updateUserProfile(String userId, UpdateProfileRequest request) {
        log.info("Updating profile for user: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> UserNotFoundException.byUserId("User not found: " + userId));

        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());

        User updatedUser = userRepository.save(user);
        log.info("Profile updated successfully for user: {}", userId);

        return mapToUserInfo(updatedUser);
    }

    @Transactional
    public void changePassword(String userId, ChangePasswordRequest request) {
        log.info("Password change attempt for user: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> UserNotFoundException.byUserId("User not found: " + userId));

        // בדיקת סיסמה נוכחית
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPasswordHash())) {
            log.warn("Password change failed - invalid current password for user: {}", userId);
            throw new IllegalArgumentException("Current password is incorrect");
        }

        // עדכון סיסמה
        user.setPasswordHash(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);

        log.info("Password changed successfully for user: {}", userId);
    }

    @Cacheable(value = "active-users")
    public List<UserSummary> getActiveUsers() {
        log.debug("Fetching all active users");

        return userRepository.findByIsActiveTrue()
                .stream()
                .map(this::mapToUserSummary)
                .collect(Collectors.toList());
    }

    public List<UserSummary> searchUsersByName(String name) {
        log.debug("Searching users by name: {}", name);

        if (name == null || name.trim().isEmpty()) {
            throw new IllegalArgumentException("Search name cannot be empty");
        }

        return userRepository.findByNameContainingIgnoreCase(name.trim())
                .stream()
                .map(this::mapToUserSummary)
                .collect(Collectors.toList());
    }

    @Cacheable(value = "user-stats", unless = "#result.totalUsers == 0")
    public UserStats getUserStatistics() {
        log.debug("Calculating user statistics");

        long totalUsers = userRepository.count();
        long activeUsers = userRepository.countActiveUsers();
        long newUsersToday = userRepository.countNewUsersToday();

        // חישוב משתמשים חדשים בחודש
        LocalDateTime monthStart = LocalDateTime.now()
                .withDayOfMonth(1)
                .withHour(0)
                .withMinute(0)
                .withSecond(0)
                .withNano(0);

        long newUsersThisMonth = userRepository
                .findByCreatedAtBetween(monthStart, LocalDateTime.now())
                .size();

        double activePercentage = totalUsers > 0 ?
                (double) activeUsers / totalUsers * 100 : 0;

        UserStats stats = UserStats.builder()
                .totalUsers(totalUsers)
                .activeUsers(activeUsers)
                .newUsersToday(newUsersToday)
                .newUsersThisMonth(newUsersThisMonth)
                .activeUserPercentage(Math.round(activePercentage * 100.0) / 100.0)
                .build();

        log.debug("User statistics calculated: {} total, {} active", totalUsers, activeUsers);
        return stats;
    }

    @Transactional
    @CacheEvict(value = {"user-profiles", "active-users"}, key = "#userId")
    public void deactivateUser(String userId) {
        log.info("Deactivating user: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> UserNotFoundException.byUserId("User not found: " + userId));

        if (!user.getIsActive()) {
            log.warn("User already deactivated: {}", userId);
            throw new IllegalStateException("User is already deactivated");
        }

        user.deactivate();
        userRepository.save(user);

        log.info("User deactivated successfully: {}", userId);
    }

    @Transactional
    @CacheEvict(value = {"user-profiles", "active-users"}, key = "#userId")
    public void activateUser(String userId) {
        log.info("Activating user: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> UserNotFoundException.byUserId("User not found: " + userId));

        if (user.getIsActive()) {
            log.warn("User already active: {}", userId);
            throw new IllegalStateException("User is already active");
        }

        user.activate();
        userRepository.save(user);

        log.info("User activated successfully: {}", userId);
    }

    public boolean existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }

    public User findByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> UserNotFoundException.byEmail("User not found with email: " + email));
    }

    private UserInfo mapToUserInfo(User user) {
        return UserInfo.builder()
                .userId(user.getUserId())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .fullName(user.getFullName())
                .createdAt(user.getCreatedAt())
                .lastLoginAt(user.getLastLoginAt())
                .isActive(user.getIsActive())
                .isNewUser(user.isNewUser())
                .build();
    }

    private UserSummary mapToUserSummary(User user) {
        return UserSummary.builder()
                .userId(user.getUserId())
                .email(user.getEmail())
                .fullName(user.getFullName())
                .createdAt(user.getCreatedAt())
                .lastLoginAt(user.getLastLoginAt())
                .isActive(user.getIsActive())
                .build();
    }
}
