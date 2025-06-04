package io.github.zeviabramovich.ecommerce.user.exception;

public class UserNotFoundException extends RuntimeException {
    public UserNotFoundException(String message) {
        super(message);
    }

    public UserNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }

    public static UserNotFoundException byUserId(String userId) {
        return new UserNotFoundException("User not found with ID: " + userId);
    }

    public static UserNotFoundException byEmail(String email) {
        return new UserNotFoundException("User not found with email: " + email);
    }
}
