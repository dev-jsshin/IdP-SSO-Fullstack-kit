package com.idpserver.common.response.exception;

import com.idpserver.common.response.code.StatusCode;
import lombok.Getter;

/**
 * 사용자 정의 예외 Class
 * 최초 작성 - 2025.03.18
 *
 * @author 신준섭
 * @version 1.0
 */
@Getter
public class GeneralException extends RuntimeException {

    private final StatusCode statusCode;

    /**
     * Default
     * <p>
     * @ return Enum에 정의된 Code 및 Message Return (Internal Server Error)
     */
    public GeneralException() {
        super(StatusCode.INTERNAL_ERROR.getMessage());
        this.statusCode = StatusCode.INTERNAL_ERROR;
    }

    /**
     * Custom Message
     * <p>
     * @ param String message Custom Message 삽입
     * @ return Enum에 정의된 Code 및 Custom Message Return (Internal server error)
     */
    public GeneralException(String message) {
        super(StatusCode.INTERNAL_ERROR.getMessage(message));
        this.statusCode = StatusCode.INTERNAL_ERROR;
    }

    /**
     * Throwable Message
     * <p>
     * @ param Throwable cause throwable 삽입
     * @ return Enum에 정의된 Code 및 throwable Message Return (Internal server error)
     */
    public GeneralException(Throwable cause) {
        super(StatusCode.INTERNAL_ERROR.getMessage(cause));
        this.statusCode = StatusCode.INTERNAL_ERROR;
    }

    /**
     * Only Enum
     * <p>
     * @ param StatusCode errorCode Enum에 정의된 Code 삽입
     * @ return Enum에 정의된 Code 및 Message Return
     */
    public GeneralException(StatusCode errorCode) {
        super(errorCode.getMessage());
        this.statusCode = errorCode;
    }

    /**
     * Enum Code And Custom Message
     * <p>
     * @ param StatusCode errorCode Enum에 정의된 Code 삽입
     * @ param String message Custom Message 삽입
     * @ return Enum에 정의된 Code 및 Custom Message Return
     */
    public GeneralException(StatusCode errorCode, String message) {
        super(errorCode.getMessage(message));
        this.statusCode = errorCode;
    }

    /**
     * Enum Code And Throwable Message
     * <p>
     * @ param StatusCode errorCode Enum에 정의된 Code 삽입
     * @ param Throwable cause throwable 삽입
     * @ return Enum에 정의된 Code 및 throwable Message Return
     */
    public GeneralException(StatusCode errorCode, Throwable cause) {
        super(errorCode.getMessage(cause), cause);
        this.statusCode = errorCode;
    }
}