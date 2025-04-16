package com.idpserver.global.common.response.dto;

import com.idpserver.global.common.response.code.StatusCode;
import lombok.Getter;

/**
 * 요청에 대한 응답이 성공적으로 이루어졌울 경우 사용
 * 상속받은 ResponseDto 통해 최종적으로 Return 처리
 * 최초 작성 - 2025.03.18
 *
 * @author 신준섭
 * @version 1.0
 */
@Getter
public class DataResponseDto<T> extends ResponseDto {


    /**
     * 요청에 대한 데이터와 성공 처리 및 Enum에 정의된 Message Return
     * <p>
     * @ param T data Return 대상 데이터
     * @ return 요청에 대한 응답 데이터, 성공 처리 및 Enum 에 정의된 Message, Response Data Return
     */
    private DataResponseDto(T data) {
        super(true, StatusCode.OK.getCode(), StatusCode.OK.getMessage(), data, null);
    }

    /**
     * 요청에 대한 데이터와 성공 처리 및 Custom Message Return
     * <p>
     * @ param T data Return 대상 데이터
     * @ param T page 페이지 데이터
     * @ return 요청에 대한 응답 데이터, 성공 처리 및 Enum 에 정의된 Message, Response Data, Page Data Return
     */
    private DataResponseDto(T data, T page) {
        super(true, StatusCode.OK.getCode(), StatusCode.OK.getMessage(), data, page);
    }

    /**
     * 요청에 대한 데이터와 성공 처리 및 Custom Message Return
     * <p>
     * @ param T data Return 대상 데이터
     * @ param String message Custom Message 삽입
     * @ return 요청에 대한 응답 데이터, 성공 처리 및 Custom Message, Response Data Return
     */
    private DataResponseDto(T data, String message) {
        super(true, StatusCode.OK.getCode(), message, data, null);
    }

    public static <T> DataResponseDto<T> of(T data) {
        return new DataResponseDto<>(data);
    }

    public static <T> DataResponseDto<T> of(T data, T page) {
        return new DataResponseDto<>(data, page);
    }

    public static <T> DataResponseDto<T> of(T data, String message) {
        return new DataResponseDto<>(data, message);
    }

    public static <T> DataResponseDto<T> empty() {
        return new DataResponseDto<>(null);
    }
}