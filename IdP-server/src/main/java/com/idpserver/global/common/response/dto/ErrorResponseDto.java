package com.idpserver.global.common.response.dto;


import com.idpserver.global.common.response.code.StatusCode;

/**
 * 요청에 대한 응답이 실패했을 경우 사용
 * 상속받은 ResponseDto 통해 최종적으로 Return 처리
 * 최초 작성 - 2025.03.18
 *
 * @author 신준섭
 * @version 1.0
 */
public class ErrorResponseDto extends ResponseDto {

    /**
     * 요청 실패 처리 및 Enum에 정의된 Message Return
     * <p>
     * @ param StatusCode statusCode 실패 사유에 대한 에러 코드
     * @ return 요청에 대한 실패 처리 및 Enum 에 정의된 Message Return
     */
    private ErrorResponseDto(StatusCode errorCode) {
        super(false, errorCode.getCode(), errorCode.getMessage(), null, null);
    }

    /**
     * 요청 실패 처리 및 Custom Message Return
     * <p>
     * @ param StatusCode statusCode 실패 사유에 대한 에러 코드
     * @ param String message Custom Message 삽입
     * @ return 요청에 대한 실패 처리 및 Custom Message Return
     */
    private ErrorResponseDto(StatusCode errorCode, String message) {
        super(false, errorCode.getCode(), errorCode.getMessage(message), null, null);
    }

    /**
     * 요청 실패 처리 및 Exception Error Message Return
     * <p>
     * @ param StatusCode statusCode 실패 사유에 대한 에러 코드
     * @ param Exception e Exception 삽입
     * @ return 요청에 대한 실패 처리 및 Exception Error Message Return
     */
    private ErrorResponseDto(StatusCode errorCode, Exception e) {
        super(false, errorCode.getCode(), errorCode.getMessage(e), null, null);
    }

    public static ErrorResponseDto of(StatusCode errorCode) {
        return new ErrorResponseDto(errorCode);
    }

    public static ErrorResponseDto of(StatusCode errorCode, Exception e) {
        return new ErrorResponseDto(errorCode, e);
    }

    public static ErrorResponseDto of(StatusCode errorCode, String message) {
        return new ErrorResponseDto(errorCode, message);
    }
}