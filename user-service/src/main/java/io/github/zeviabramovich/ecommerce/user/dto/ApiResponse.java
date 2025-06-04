package io.github.zeviabramovich.ecommerce.user.dto;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class ApiResponse<T> {
    private boolean success;

    private String message;

    private T data;

    @Builder.Default
    private LocalDateTime timestamp = LocalDateTime.now();

    /**
     * Success response with data
     */
    public static <T> ApiResponse<T> success(T data) {
        return ApiResponse.<T>builder()
                .success(true)
                .data(data)
                .build();
    }

    /**
     * Success response with message and data
     */
    public static <T> ApiResponse<T> success(String message, T data) {
        return ApiResponse.<T>builder()
                .success(true)
                .message(message)
                .data(data)
                .build();
    }

    /**
     * Error response with message
     */
    public static <T> ApiResponse<T> error(String message) {
        return ApiResponse.<T>builder()
                .success(false)
                .message(message)
                .build();
    }
}
