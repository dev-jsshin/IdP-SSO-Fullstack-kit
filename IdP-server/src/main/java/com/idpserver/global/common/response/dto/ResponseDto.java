package com.idpserver.global.common.response.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.idpserver.global.common.response.code.StatusCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;


/**
 * Common ResponseDto
 * 최초 작성 - 2025.03.18
 *
 * @author 신준섭
 * @version 1.0
 */
@Getter
@ToString
@JsonInclude(JsonInclude.Include.NON_NULL)
@RequiredArgsConstructor
public class ResponseDto {

    private final Boolean status;
    private final Integer code;
    private final String message;
    private final Object data;
    private final Object page;

    /**
     * 요청에 대한 성공 여부와 상태 코드, Enum에 정의된 Message Return
     * <p>
     * @ param boolean status 요청 성공 여부
     * @ param StatusCode statusCode Enum에 정의된 코드
     * @ param Object data Return data
     * @ return API Response
     */
    public static ResponseDto of(Boolean status, StatusCode statusCode, Object data) {
        return new ResponseDto(status, statusCode.getCode(), statusCode.getMessage(), data, null);
    }

    /**
     * 요청에 대한 성공 여부와 상태 코드, Enum에 정의된 Message, 페이지 정보 Return
     * <p>
     * @ param boolean status 요청 성공 여부
     * @ param StatusCode statusCode Enum에 정의된 코드
     * @ param Object data Return data
     * @ param page data Return page
     * @ return API Response
     */
    public static ResponseDto of(Boolean status, StatusCode statusCode, Object data, Object page) {
        return new ResponseDto(status, statusCode.getCode(), statusCode.getMessage(), data, page);
    }


    /**
     * 요청에 대한 성공 여부와 상태 코드, Custom Message Return
     * <p>
     * @ param boolean status 요청 성공 여부
     * @ param StatusCode Enum에 정의된 코드
     * @ param String message Custom Message 삽입
     * @ param Object data Return data
     * @ return API Response
     */
    public static ResponseDto of(Boolean status, StatusCode statusCode, String message, Object data) {
        return new ResponseDto(status, statusCode.getCode(), message, data, null);
    }

    /**
     * 요청에 대한 성공 여부와 상태 코드, Error Message Return
     * <p>
     * @ param boolean status 요청 성공 여부
     * @ param StatusCode statusCode Enum에 정의된 코드
     * @ param Exception e Exception 삽입
     * @ return API Response
     */
    public static ResponseDto of(Boolean status, StatusCode statusCode, Exception e) {
        return new ResponseDto(status, statusCode.getCode(), e.getMessage(), null, null);
    }
}