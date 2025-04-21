package com.idpserver.config.handler;

import com.idpserver.common.response.code.StatusCode;
import com.idpserver.common.response.dto.ErrorResponseDto;
import com.idpserver.common.response.exception.GeneralException;
import jakarta.validation.ConstraintViolationException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

/**
 * Global Exception Handler
 * 최초 작성 - 2025.03.18
 *
 * @author 신준섭
 * @version 1.0
 */
@RestControllerAdvice(annotations = {RestController.class})
public class ExceptionHandler extends ResponseEntityExceptionHandler {

    /**
     * Default Exception
     * <p>
     * @ return Enum에 정의된 Code Return (Internal Server Error)
     */
    @org.springframework.web.bind.annotation.ExceptionHandler
    public ResponseEntity<Object> exception(Exception e, WebRequest request) {
        return handleExceptionInternal(e, StatusCode.INTERNAL_ERROR, request);
    }

    /**
     * Validation Exception
     * <p>
     * @ return Enum에 정의된 Code Return (Validation Error)
     */
    @org.springframework.web.bind.annotation.ExceptionHandler
    public ResponseEntity<Object> validation(ConstraintViolationException e, WebRequest request) {
        return handleExceptionInternal(e, StatusCode.VALIDATION_ERROR, request);
    }

    /**
     * General Exception
     * 다른 곳에서 정의된 Handler 혹은 Global 로직을 경유하지 못할 때
     *
     * <p>
     * @ return 실제 Status Code Return
     */
    @org.springframework.web.bind.annotation.ExceptionHandler
    public ResponseEntity<Object> general(GeneralException e, WebRequest request) {
        return handleExceptionInternal(e, e.getStatusCode(), request);
    }

    protected ResponseEntity<Object> handleExceptionInternal(Exception e,
                                                             Object body,
                                                             HttpHeaders headers,
                                                             HttpStatus status,
                                                             WebRequest request) {

        return handleExceptionInternal(e, StatusCode.valueOf(status), headers, status, request);
    }

    private ResponseEntity<Object> handleExceptionInternal(Exception e,
                                                           StatusCode errorCode,
                                                           WebRequest request) {

        return handleExceptionInternal(e, errorCode, HttpHeaders.EMPTY, errorCode.getHttpStatus(), request);
    }

    private ResponseEntity<Object> handleExceptionInternal(Exception e,
                                                           StatusCode errorCode,
                                                           HttpHeaders headers,
                                                           HttpStatus status,
                                                           WebRequest request) {

        return super.handleExceptionInternal(e, ErrorResponseDto.of(errorCode, errorCode.getMessage(e)), headers, status, request);
    }
}