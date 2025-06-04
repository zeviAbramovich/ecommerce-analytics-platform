package io.github.zeviabramovich.ecommerce.user.repository;

import io.github.zeviabramovich.ecommerce.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, String> {
    Optional<User> findByEmail(String email);
    boolean existsByEmail(String email);
    Optional<User> findByEmailAndIsActiveTrue(String email);
    List<User> findByIsActiveTrue();
    List<User> findByIsActiveFalse();
    List<User> findByCreatedAtBetween(LocalDateTime start, LocalDateTime end);
    List<User> findByLastLoginAtAfter(LocalDateTime date);
    List<User> findByFirstNameContainingIgnoreCase(String firstName);
    List<User> findByLastNameContainingIgnoreCase(String lastName);

    @Query("SELECT u FROM User u WHERE " +
            "LOWER(u.firstName) LIKE LOWER(CONCAT('%', :name, '%')) OR " +
            "LOWER(u.lastName) LIKE LOWER(CONCAT('%', :name, '%')) OR " +
            "LOWER(CONCAT(u.firstName, ' ', u.lastName)) LIKE LOWER(CONCAT('%', :name, '%'))")
    List<User> findByNameContainingIgnoreCase(@Param("name") String name);

    @Query("SELECT u FROM User u WHERE u.lastLoginAt IS NULL AND u.isActive = true")
    List<User> findNewUsers();

    @Query("SELECT u FROM User u WHERE u.lastLoginAt >= :date AND u.isActive = true")
    List<User> findActiveUsersSince(@Param("date") LocalDateTime date);

    @Query("SELECT u FROM User u WHERE " +
            "u.lastLoginAt < :cutoffDate OR " +
            "(u.lastLoginAt IS NULL AND u.createdAt < :cutoffDate)")
    List<User> findInactiveUsersBefore(@Param("cutoffDate") LocalDateTime cutoffDate);

    @Query("SELECT u FROM User u WHERE LOWER(u.email) LIKE LOWER(CONCAT('%', :emailPart, '%'))")
    List<User> findByEmailContainingIgnoreCase(@Param("emailPart") String emailPart);

    @Query("SELECT u FROM User u WHERE u.isActive = true AND u.lastLoginAt IS NOT NULL " +
            "ORDER BY u.lastLoginAt DESC")
    List<User> findMostActiveUsers();

    @Query("SELECT COUNT(u) FROM User u WHERE u.isActive = true")
    long countActiveUsers();

    @Query(value = "SELECT COUNT(*) FROM users WHERE DATE(created_at) = CURRENT_DATE",
            nativeQuery = true)
    long countNewUsersToday();

    @Query(value = "SELECT COUNT(*) FROM users WHERE created_at >= DATE_TRUNC('week', CURRENT_DATE)",
            nativeQuery = true)
    long countNewUsersThisWeek();

    @Query(value = "SELECT COUNT(*) FROM users WHERE created_at >= DATE_TRUNC('month', CURRENT_DATE)",
            nativeQuery = true)
    long countNewUsersThisMonth();

    @Query(value = "SELECT COUNT(*) FROM users WHERE last_login_at >= DATE_TRUNC('week', CURRENT_DATE)",
            nativeQuery = true)
    long countLoggedInThisWeek();

    @Query(value = "SELECT AVG(daily_count) FROM " +
            "(SELECT COUNT(*) as daily_count FROM users " +
            "WHERE created_at >= CURRENT_DATE - INTERVAL '30 days' " +
            "GROUP BY DATE(created_at)) as daily_stats",
            nativeQuery = true)
    Double getAverageNewUsersPerDay();

    @Modifying
    @Query("UPDATE User u SET u.lastLoginAt = :loginTime WHERE u.userId = :userId")
    int updateLastLoginTime(@Param("userId") String userId, @Param("loginTime") LocalDateTime loginTime);

    @Modifying
    @Query("UPDATE User u SET u.isActive = :isActive WHERE u.userId = :userId")
    int updateUserActiveStatus(@Param("userId") String userId, @Param("isActive") boolean isActive);

    @Modifying
    @Query("UPDATE User u SET u.firstName = :firstName, u.lastName = :lastName " +
            "WHERE u.userId = :userId")
    int updateUserProfile(@Param("userId") String userId,
                          @Param("firstName") String firstName,
                          @Param("lastName") String lastName);

    @Modifying
    @Query("DELETE FROM User u WHERE u.isActive = false AND u.lastLoginAt < :cutoffDate")
    int deleteInactiveUsersBefore(@Param("cutoffDate") LocalDateTime cutoffDate);

    @Query("SELECT u FROM User u WHERE " +
            "(:email IS NULL OR LOWER(u.email) LIKE LOWER(CONCAT('%', :email, '%'))) AND " +
            "(:firstName IS NULL OR LOWER(u.firstName) LIKE LOWER(CONCAT('%', :firstName, '%'))) AND " +
            "(:lastName IS NULL OR LOWER(u.lastName) LIKE LOWER(CONCAT('%', :lastName, '%'))) AND " +
            "(:isActive IS NULL OR u.isActive = :isActive) AND " +
            "(:fromDate IS NULL OR u.createdAt >= :fromDate) AND " +
            "(:toDate IS NULL OR u.createdAt <= :toDate)")
    List<User> findUsersWithFilters(@Param("email") String email,
                                    @Param("firstName") String firstName,
                                    @Param("lastName") String lastName,
                                    @Param("isActive") Boolean isActive,
                                    @Param("fromDate") LocalDateTime fromDate,
                                    @Param("toDate") LocalDateTime toDate);

    List<User> findTop10ByOrderByCreatedAtDesc();

    List<User> findTop10ByIsActiveTrueAndLastLoginAtIsNotNullOrderByLastLoginAtDesc();
}
