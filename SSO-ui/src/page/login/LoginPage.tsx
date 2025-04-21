import React, { useState, FormEvent } from 'react';
import { loginUser, LoginResult } from '../../service/authService';
import styles from './LoginPage.module.css';

const LoginPage: React.FC = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    try {
      // authService의 loginUser 호출 (LoginResult 타입을 반환)
      const result: LoginResult = await loginUser({ username, password });

      if (result.success && result.redirectUrl) {
          window.location.href = result.redirectUrl;
      } else if (result.success) {
           // 로그인 성공했지만 리디렉션 URL이 없는 경우 (예: 기본 성공 처리)
           console.log('Login successful, no redirect URL provided.');
           alert('로그인 성공!');
           setLoading(false);
      }
      else {
          setError(result.message || '로그인에 실패했습니다.');
          setLoading(false);
      }
    } catch (err) {
       console.error("Unexpected error during login process:", err);
       setError('로그인 처리 중 예상치 못한 오류가 발생했습니다.');
       setLoading(false); // 로딩 상태 해제
    }
  };

  return (
    <div className={styles.loginContainer}>
      <h2>로그인</h2>
      <form onSubmit={handleSubmit} className={styles.loginForm}>
        <div className={styles.inputGroup}>
          <label htmlFor="username">아이디</label>
          <input
            type="text"
            id="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            disabled={loading}
          />
        </div>
        <div className={styles.inputGroup}>
          <label htmlFor="password">비밀번호</label>
          <input
            type="password"
            id="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            disabled={loading}
          />
        </div>
        {error && <p className={styles.errorMessage}>{error}</p>}
        <button type="submit" disabled={loading} className={styles.loginButton}>
          {loading ? '로그인 중...' : '로그인'}
        </button>
      </form>
    </div>
  );
};

export default LoginPage;