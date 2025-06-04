package io.github.zeviabramovich.ecommerce.user.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserStats {
    private long totalUsers;
    private long activeUsers;
    private long newUsersToday;
    private long newUsersThisMonth;
    private double activeUserPercentage;
}
