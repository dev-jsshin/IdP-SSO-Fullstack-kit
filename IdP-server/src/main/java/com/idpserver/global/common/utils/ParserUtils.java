package com.idpserver.global.common.utils;

import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.Collections;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * 문자 파싱 관련 유틸리티 메소드를 제공하는 클래스.
 */
public final class ParserUtils {

    private ParserUtils() {
        throw new IllegalStateException("Utility class");
    }

    private static final String COMMA_OR_WHITESPACE_REGEX = "[,\\s]+";

    /**
     * 콤마(,) 또는 하나 이상의 공백 문자(\s+)로 구분된 문자열을 파싱하여,
     * 각 요소를 주어진 매핑 함수(mapper)를 통해 변환하고 그 결과를 Set<T> 형태로 반환하는 제네릭 유틸리티 메소드
     *
     * @param <T>    반환될 Set의 요소 타입
     * @param input  파싱할 입력 문자열
     * @param mapper 분리된 각 문자열 조각(trim 처리 후)을 최종 타입 T로 변환하는 함수(Function).
     *               예를 들어, 문자열을 그대로 사용하려면 {@code Function.identity()}를,
     *               특정 Enum이나 객체로 변환하려면 해당 생성자 참조(예: {@code Enum::new})를 전달합니다.
     * @return 파싱 및 매핑된 결과가 포함된 Set<T>. 입력이 유효하지 않거나 변환 결과가 없으면 빈 Set을 반환합니다.
     */
    public static <T> Set<T> parseCommaSeparatedString(String input, Function<String, T> mapper) {
        if (!StringUtils.hasText(input)) return Collections.emptySet();
        return Arrays.stream(input.split(COMMA_OR_WHITESPACE_REGEX))
                .map(String::trim).filter(StringUtils::hasText)
                .map(mapper).filter(Objects::nonNull)
                .collect(Collectors.toSet());
    }

}
