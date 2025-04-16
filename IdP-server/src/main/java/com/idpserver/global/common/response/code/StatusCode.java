package com.idpserver.global.common.response.code;

import com.idpserver.global.common.response.exception.GeneralException;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

import java.util.Arrays;
import java.util.Optional;
import java.util.function.Predicate;

/**
 * Common StatusCode
 * 최초 작성 - 2025.03.18
 *
 * @author 신준섭
 * @version 1.0
 */
@Getter
@RequiredArgsConstructor
public enum StatusCode {

    OK(200, HttpStatus.OK, "정상적으로 조회되었습니다."),
    NO_CONTENT(204, HttpStatus.NO_CONTENT, "조회된 정보가 없습니다."),
    VALIDATION_ERROR(10001, HttpStatus.BAD_REQUEST, "Validation error"),
    BAD_REQUEST(400, HttpStatus.BAD_REQUEST, "Bad request"),
    INTERNAL_ERROR(20000, HttpStatus.INTERNAL_SERVER_ERROR, "오류가 발생하였습니다. 관리자에게 문의바랍니다."),
    DATA_ACCESS_ERROR(20001, HttpStatus.INTERNAL_SERVER_ERROR, "Data access error"),
    UNAUTHORIZED(401, HttpStatus.UNAUTHORIZED, "User unauthorized");

    private final Integer code;
    private final HttpStatus httpStatus;
    private final String message;

    /**
     * Message Blank Check
     * Custom Message 혹은 Throwable Message가 Blank일 경우 Enum에서 정의된 Message Return
     * 매개변수 Message가 Blank면 StatusCode로 구분해서 Message Return
     * <p>
     * @ param String message Return 대상의 Message
     * @ return Message
     */
    public String getMessage(String message) {
        return Optional.ofNullable(message)
                       .filter(Predicate.not(String::isBlank))
                       .orElse(this.getMessage());
    }

    /**
     * Throwable Message Set 후 Blank Check
     * <p>
     * @ param Throwable e Message Set 대상의 Throwable
     * @ return Message
     */
    public String getMessage(Throwable e) {
        return this.getMessage(e.getMessage());
    }


    /**
     * httpStatus Check
     * 오류로 인해 Global로 설정된 로직을 경유하지 못할 때 + Enum에 정의되어있지않은 Http Code에 대한 처리
     * <p>
     * @ param HttpStatus httpStatus 체크하고자하는 HttpStatus
     * @ return Message
     */
    public static StatusCode valueOf(HttpStatus httpStatus) {
        if (httpStatus == null) {
            throw new GeneralException("HttpStatus is null");
        }

        return Arrays.stream(values())
                    .filter(errorCode -> errorCode.getHttpStatus() == httpStatus)
                    .findFirst()
                    .orElseGet(() -> {
                        if (httpStatus.is4xxClientError()) {
                            return StatusCode.BAD_REQUEST;
                        } else if (httpStatus.is5xxServerError()) {
                            return StatusCode.INTERNAL_ERROR;
                        } else {
                            return StatusCode.OK;
                        }
                    });
    }
}
