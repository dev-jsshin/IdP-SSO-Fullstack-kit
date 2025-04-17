import apiClient from '../common/axiosInstance';

interface LoginData {
  username?: string;
  password?: string;
}

interface LoginResponse {
  success: boolean;
  message?: string;
}

export const loginUser = async (loginData: LoginData): Promise<LoginResponse> => {
  try {
    const response = await apiClient.post<LoginResponse>('/login', loginData);
    return response.data;
  } catch (error) {
    if (axios.isAxiosError(error) && error.response) {
      return error.response.data as LoginResponse;
    } else {
      return { success: false, message: '로그인 중 오류가 발생했습니다.' };
    }
  }
};

import axios from 'axios';