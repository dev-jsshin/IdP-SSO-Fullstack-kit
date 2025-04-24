import LoginPage from './page/login/LoginPage'
import CallbackPage from './page/callback/Callback';
import { Route, Routes } from 'react-router-dom';

function App() {

  return (

    <Routes>
          <Route path='/login' element={<LoginPage />} />
          <Route path='/callback' element={<CallbackPage />} />
        </Routes>
  )
}

export default App
