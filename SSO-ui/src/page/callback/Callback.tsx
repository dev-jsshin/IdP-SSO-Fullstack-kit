import React, { useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';

/* 
  * CallbackPage.tsx
  * 인가 코드 수신 후 처리하는 페이지 (테스트용 페이지)
  *
*/
const CallbackPage: React.FC = () => {

  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  useEffect(() => {
    const code = searchParams.get('code');
    const state = searchParams.get('state');

    console.log('인가 코드:', code);
    console.log('State:', state);

    if (code) {
      console.log('인가 코드 수신 성공. 잠시 후 이동합니다...');

      // setTimeout(() => {
      //   navigate('/');
      // }, 1000);
    } else {
      navigate('/login');
    }
  }, []);

  return (
    <div>
      Redirect Success! 
      code : {searchParams.get('code')} 
      state : {searchParams.get('state')}
    </div>
  );
};

export default CallbackPage;