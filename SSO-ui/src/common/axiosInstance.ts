import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_SERVER_DOMAIN; // 기본값 설정

// Axios 인스턴스 생성
const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded',
  },
});

export default apiClient;
