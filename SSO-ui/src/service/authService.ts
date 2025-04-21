import apiClient from '../common/axiosInstance';
import axios, { AxiosError } from 'axios'; // AxiosError 타입 사용

// 로그인 폼 데이터 인터페이스
interface LoginData {
    username?: string;
    password?: string;
}

// 로그인 결과 인터페이스
interface LoginResult {
    success: boolean;
    message?: string;
    redirectUrl?: string; // 서버가 보내줄 리디렉션 URL
}

/**
 * IDP 서버의 /login 엔드포인트로 로그인 요청 (formLogin 방식 사용)
 * 성공 시 SpaLoginSuccessHandler 가 200 OK 와 함께 JSON ({success: true, redirectUrl: '...'}) 응답을 반환.
 * 실패 시 401 Unauthorized 등 에러 응답 반환.
 *
 * @param loginData username, password 포함 객체
 * @returns Promise<LoginResult> 로그인 시도 결과 (리디렉션 URL 포함 가능)
 */
export const loginUser = async (loginData: LoginData): Promise<LoginResult> => {
    const loginUrl = '/login';

    // x-www-form-urlencoded 데이터 생성
    const params = new URLSearchParams();
    params.append('username', loginData.username || '');
    params.append('password', loginData.password || '');

    try {
        console.log(`POST ${loginUrl} with x-www-form-urlencoded data...`);

        const response = await apiClient.post<LoginResult>(loginUrl, params, {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
        });

        console.log('Login POST successful, received data:', response.data);

        // 서버 응답 데이터가 LoginResult 형식에 맞는지 확인 (필수는 아님)
        if (response.data && typeof response.data.success === 'boolean') {
             // 서버가 보낸 JSON 데이터를 그대로 반환 (redirectUrl 포함 가능성 있음)
             return response.data;
        } else {
             // 예상치 못한 성공 응답 형식 처리
             console.warn('Login successful, but response format is unexpected:', response.data);
             return { success: false, message: '로그인 응답 형식이 예상과 다릅니다.' };
        }

    } catch (error) {
        const axiosError = error as AxiosError<LoginResult>; // 에러 응답 타입도 지정 가능
        console.error('Login request failed:', axiosError.message);

        if (axiosError.response) {
            // ===>>> 서버가 에러 응답 반환 (예: 401 Unauthorized - 자격 증명 실패) <<<===
            console.error('Server responded with error:', axiosError.response.status, axiosError.response.data);
            const errorData = axiosError.response.data;
            return {
                success: false,
                message: errorData?.message || `로그인 실패 (서버 상태: ${axiosError.response.status})`,
            };
        } else if (axiosError.request) {
            // ===>>> 네트워크 에러 (서버 응답 없음) <<<===
            // 서버 다운, CORS Preflight 실패 (이론상 가능성은 낮음), DNS 문제 등
            console.error('No response received from server:', axiosError.request);
            let message = '서버에 연결할 수 없습니다. 네트워크 상태 또는 서버 주소를 확인하세요.';
            // CORS Preflight 실패 가능성 메시지 (OPTIONS 요청 실패 시 발생 가능)
            if (axiosError.message?.includes('Network Error') && !navigator.onLine) {
                message = '네트워크 연결이 끊어졌습니다.';
            } else if (axiosError.message?.includes('Network Error')) {
                 message += ' CORS 설정 문제 또는 서버가 실행 중이지 않을 수 있습니다. 브라우저 개발자 도구의 네트워크 탭을 확인하세요.';
            }
            return { success: false, message: message };
        } else {
            // ===>>> 요청 설정 중 발생한 에러 등 <<<===
            console.error('Error setting up login request:', axiosError.message);
            return { success: false, message: `로그인 요청 설정 중 오류: ${axiosError.message}` };
        }
    }
};