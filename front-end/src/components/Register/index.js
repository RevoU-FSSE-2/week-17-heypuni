import { Button } from '@mui/material';
import Box from '@mui/material/Box';
import TextField from '@mui/material/TextField';
import Link from '@mui/material/Link';
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

function Register () {
  // const [token, setToken] = useState(null)
  const [registerName, setRegisterName] = useState('')
  const [registerEmail, setRegisterEmail] = useState('')
  const [registerPassword, setRegisterPassword] = useState('')  
  const navigate = useNavigate();

  const handleLoginLinkClick = (e) => {
    e.preventDefault();
    navigate('/login');
  }

  const URL = process.env.REACT_APP_BE_ENDPOINT
  // console.log('URL', URL)  

  const onRegisterSubmit = () => {
    console.log(`name: ${registerName}, email: ${registerEmail}, password: ${registerPassword}`)
    axios.post(`${URL}/v1/auth/register`, {
      name: registerName,
      email: registerEmail,
      password: registerPassword
    })
      .then(function (response) {
        console.log('register success', response);
        if (response && response.data && response.data.tokens && response.data.tokens.access) {
          localStorage.setItem('token', JSON.stringify(response.data.tokens.access.token))
          localStorage.setItem('user', JSON.stringify(response.data.user))
          navigate ('/login');
        }
      })
      .catch(function (error) {
        if (error.response && error.response.status === 400 && error.response.data.message) {
            window.alert('error', 'Registration Failed', `<b>[CODE] ${error.response.data.message}</b><br>Please check your username and password`);
        } else {
            window.alert('error', 'Registration Failed', `<b>[CODE] </b><br>An error occured during registration. Please try again later`);
        }
        console.error('Registration error', error.message);
    }
    );
  }

  console.log('data', registerName, registerEmail, registerPassword);
  
  // useEffect(() => {
  //   const tokenFromLS = localStorage.getItem('token')
  //   setToken(tokenFromLS)
  // }, [])

  // console.log('token', token)

    return (
        <div>
          <Box
            component="form"
            sx={{
              '& .MuiTextField-root': { mt: 1, mb: 1, width: '25ch' },
              height: '100vh',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'center',
              alignItems: 'center',
            }}
            noValidate
            autoComplete="off"
          >

            <Box sx={{
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'center',
              alignItems: 'center',
            }}>
              <TextField
                id="outlined-registerNameText"
                label="Name"
                defaultValue=""
                helperText="Type your name here"
                type='text'
                onChange={(e) => setRegisterName(e.target.value)}
              />
              <TextField
                id="outlined-registerEmailText"
                label="Email"
                defaultValue=""
                helperText="Type your email here"
                type='email'
                onChange={(e) => setRegisterEmail(e.target.value)}
              />
              <TextField
                id="outlined-registerPasswordText"
                label="Password"
                defaultValue=""
                helperText="Type your password here"
                type='password'
                onChange={(e) => setRegisterPassword(e.target.value)}
              />
              <Button variant="contained" onClick={() => onRegisterSubmit()}>Register</Button>
            </Box>       

            <Link href="#" onClick={handleLoginLinkClick} target="_blank" rel="noopener">
                Login here if you already have an account 
            </Link>

      </Box>
      </div>
    );  
}

export default Register;