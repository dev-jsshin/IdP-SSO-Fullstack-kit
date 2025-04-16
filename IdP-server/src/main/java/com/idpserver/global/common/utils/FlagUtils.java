package com.idpserver.global.common.utils;


/**
 * 플래그 값 관련 유틸리티 메소드를 제공하는 클래스.
 */
public final class FlagUtils {

    private static final String YES_FLAG_UPPER = "Y";

    private FlagUtils() {
        throw new IllegalStateException("Utility class");
    }

    /**
     * 주어진 문자열 플래그 값이 'Y' 또는 'y'인지 확인
     *
     * @param ynValue 확인할 플래그 문자열 값
     * @return 플래그 값이 'Y', 'y'이면 true, 아니면 false
     */
    public static boolean isYesIgnoreCase(String ynValue) {
        return YES_FLAG_UPPER.equalsIgnoreCase(ynValue);
    }

    /**
     * 주어진 문자열 플래그 값이 'Y' 또는 'y'가 아닌지 확인
     *
     * @param ynValue 확인할 플래그 문자열 값 (null이 들어와도 안전합니다)
     * @return 플래그 값이 'Y', 'y'가 아니면 true, 'Y' 또는 'y'이면 false
     */
    public static boolean isNoOrOtherIgnoreCase(String ynValue) {
        return !isYesIgnoreCase(ynValue);
    }

}
