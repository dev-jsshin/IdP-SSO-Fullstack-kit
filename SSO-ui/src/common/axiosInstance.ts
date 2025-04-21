import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_SERVER_DOMAIN;

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true
});

export default apiClient;
