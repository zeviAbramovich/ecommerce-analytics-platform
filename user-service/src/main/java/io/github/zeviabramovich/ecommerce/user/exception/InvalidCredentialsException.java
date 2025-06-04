package io.github.zeviabramovich.ecommerce.user.exception;

public class InvalidCredentialsException extends RuntimeException {

    public InvalidCredentialsException(String message) {
        super(message);
    }

    public InvalidCredentialsException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Factory method לאימייל או סיסמה שגויים
     * לא חושף פרטים על הסיבה הספציפית (אבטחה)
     */
    public static InvalidCredentialsException invalidEmailOrPassword() {
        return new InvalidCredentialsException("Invalid email or password");
    }

    /**
     * Factory method לחשבון לא פעיל
     */
    public static InvalidCredentialsException accountDeactivated() {
        return new InvalidCredentialsException("Account is deactivated");
    }

    /**
     * Factory method לחשבון נעול
     */
    public static InvalidCredentialsException accountLocked() {
        return new InvalidCredentialsException("Account is locked due to multiple failed login attempts");
    }

    /**
     * Factory method לחשבון שפג תוקפו
     */
    public static InvalidCredentialsException accountExpired() {
        return new InvalidCredentialsException("Account has expired");
    }
}
