import { Button, Form, Input } from 'antd';
import { useState } from 'react';
import Link from '@mui/material/Link';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

function Login() {

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const navigate = useNavigate();

  const handleRegisterLinkClick = (e) => {
    e.preventDefault();
    navigate('/');
}

  console.log('data', email, password);

  const URL = process.env.REACT_APP_BE_ENDPOINT
  console.log('URL', URL)

  
  const onLoginSubmit = () => {
      console.log(`email: ${email}, password: ${password}`)
        axios.post(`${URL}/v1/auth/login`, {
          email,
          password
        })
          .then(function (response) {
            console.log('login success', response);
              if (response && response.data && response.data.tokens && response.data.tokens.access) {
                localStorage.setItem('token', JSON.stringify(response.data.tokens.access.token))
                localStorage.setItem('user', JSON.stringify(response.data.user))
                navigate('/product')
              }
          })
            .catch(function (error) {
              console.error('Login error', error.message);
               window.alert('error', 'Login Failed', `<b>[CODE] ${error.code}</b><br>Please check your username and password`);
              }
          );
        }

  return (
    <div className="App">
      <Form
        labelCol={{
          span: 8,
        }}
        wrapperCol={{
          span: 16,
        }}
        style={{
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
          alignItems: 'center',
          height: '100vh',
          maxWidth: '',
        }}
        initialValues={{
          remember: true,
        }}
        autoComplete="off"
      >
      <div>

          <Form.Item 
          label="Email"
          id="outlined-emailText"
          type="email"
          onChange={(e) => setEmail(e.target.value)}
          rules={[
            {
              required: true,
              message: 'Please input your email here!',
            },
          ]}>
            <Input />
          </Form.Item>

          <Form.Item
          label="Password"
          type="password"
          defaultValue=""
          id="outlined-passwordText"
          onChange={(e) => setPassword(e.target.value)}
          rules={[
            {
              required: true,
              message: 'Please input your password!',
            },
          ]}
        >
            <Input.Password />
          </Form.Item>
        
          <Form.Item
            wrapperCol={{
              offset: 10,
              span: 16,
            }}
        >
          <Button type="primary" onClick={() => onLoginSubmit()} htmlType="login">
            Login  
          </Button>

            <Link href="#" onClick={handleRegisterLinkClick}>
              Don't have an account? Register here!
            </Link>

        </Form.Item>
      </div>
     </Form>
    </div>
  );
}

export default Login;
