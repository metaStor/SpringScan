package burp.CustomException;

/**
 * @author : metaStor
 * @date : Created 2023/11/13 9:18 AM
 * @description:
 */
public class CustomTimeoutException extends RuntimeException {
    public CustomTimeoutException() {
        super();
    }

    public CustomTimeoutException(String message) {
        super(message);
    }

    public CustomTimeoutException(String message, Throwable cause) {
        super(message, cause);
    }

    public CustomTimeoutException(Throwable cause) {
        super(cause);
    }

    protected CustomTimeoutException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
