package io.github.zeviabramovich.ecommerce.user.exception;

import io.github.zeviabramovich.ecommerce.user.dto.ApiResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    /**
     * טיפול במשתמש לא נמצא
     */
    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ApiResponse<String>> handleUserNotFoundException(
            UserNotFoundException ex, WebRequest request) {

        log.warn("User not found: {} - Request: {}", ex.getMessage(), request.getDescription(false));

        ApiResponse<String> response = ApiResponse.<String>builder()
                .success(false)
                .message(ex.getMessage())
                .timestamp(LocalDateTime.now())
                .build();

        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
    }

    /**
     * טיפול במשתמש כבר קיים
     */
    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<ApiResponse<String>> handleUserAlreadyExistsException(
            UserAlreadyExistsException ex, WebRequest request) {

        log.warn("User already exists: {} - Request: {}", ex.getMessage(), request.getDescription(false));

        ApiResponse<String> response = ApiResponse.<String>builder()
                .success(false)
                .message(ex.getMessage())
                .timestamp(LocalDateTime.now())
                .build();

        return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
    }

    /**
     * טיפול בפרטי התחברות שגויים
     */
    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<ApiResponse<String>> handleInvalidCredentialsException(
            InvalidCredentialsException ex, WebRequest request) {

        log.warn("Invalid credentials: {} - Request: {}", ex.getMessage(), request.getDescription(false));

        ApiResponse<String> response = ApiResponse.<String>builder()
                .success(false)
                .message(ex.getMessage())
                .timestamp(LocalDateTime.now())
                .build();

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    /**
     * טיפול בשגיאות validation
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Map<String, String>>> handleValidationExceptions(
            MethodArgumentNotValidException ex, WebRequest request) {

        log.warn("Validation error - Request: {}", request.getDescription(false));

        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
            log.debug("Validation error - Field: {}, Message: {}", fieldName, errorMessage);
        });

        ApiResponse<Map<String, String>> response = ApiResponse.<Map<String, String>>builder()
                .success(false)
                .message("Validation failed")
                .data(errors)
                .timestamp(LocalDateTime.now())
                .build();

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    /**
     * טיפול בשגיאות אימות Spring Security
     */
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ApiResponse<String>> handleAuthenticationException(
            AuthenticationException ex, WebRequest request) {

        log.warn("Authentication error: {} - Request: {}", ex.getMessage(), request.getDescription(false));

        ApiResponse<String> response = ApiResponse.<String>builder()
                .success(false)
                .message("Authentication failed")
                .timestamp(LocalDateTime.now())
                .build();

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    /**
     * טיפול בשגיאות הרשאות
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiResponse<String>> handleAccessDeniedException(
            AccessDeniedException ex, WebRequest request) {

        log.warn("Access denied: {} - Request: {}", ex.getMessage(), request.getDescription(false));

        ApiResponse<String> response = ApiResponse.<String>builder()
                .success(false)
                .message("Access denied. Insufficient permissions.")
                .timestamp(LocalDateTime.now())
                .build();

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
    }

    /**
     * טיפול בארגומנטים לא חוקיים
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiResponse<String>> handleIllegalArgumentException(
            IllegalArgumentException ex, WebRequest request) {

        log.warn("Illegal argument: {} - Request: {}", ex.getMessage(), request.getDescription(false));

        ApiResponse<String> response = ApiResponse.<String>builder()
                .success(false)
                .message(ex.getMessage())
                .timestamp(LocalDateTime.now())
                .build();

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    /**
     * טיפול בכל החריגים שלא נתפסו
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<String>> handleGlobalException(
            Exception ex, WebRequest request) {

        log.error("Unexpected error: {} - Request: {}", ex.getMessage(), request.getDescription(false), ex);

        ApiResponse<String> response = ApiResponse.<String>builder()
                .success(false)
                .message("An unexpected error occurred. Please try again later.")
                .timestamp(LocalDateTime.now())
                .build();

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }
}
