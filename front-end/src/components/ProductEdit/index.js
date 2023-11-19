
import { Button, Form, Input, Select } from 'antd';
import { useState, useEffect } from 'react';
import axios from 'axios';

function ProductCreate() {
  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const [priority, setPriority] = useState('')
  const [dueDate, setDueDate] = useState('')
  const [token, setToken] = useState(null)

  const URL = process.env.REACT_APP_BE_ENDPOINT

  console.log('data', title, description, priority, dueDate)

  const handleChange = (event) => {
     setPriority(event.target.value);
  };

  const onProductSubmit = () => {
      console.log(`title: ${title}, desc: ${description}, priority: ${priority}`)
    
      axios.post(`${URL}/v1/products`, {
        title,
        description,
        priority,
        dueDate,
      },
          config
        )
          .then(function (response) {
            console.log('create product success', response);
            window.location.reload()
          })
          .catch(function (error) {
            console.log(error);
          });
      }
    
      useEffect(() => {
        const tokenFromLS = localStorage.getItem('token')
        setToken(tokenFromLS)
      }, [])

      const config = {
          headers: { Authorization: `Bearer ${JSON.parse(token)}` }
      };


  return (
    <div className="ProductEdit">
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
          label="Title"
          id="outlined-titleText"
          type="text"
          defaultValue=""
          onChange={(e) => setTitle(e.target.value)}
          rules={[
            {
              required: true,
              message: 'Input your title here!',
            },
          ]}>
            <Input />
          </Form.Item>

          <Form.Item
          label="Description"
          type="text"
          defaultValue=""
          id="outlined-descriptionText"
          onChange={(e) => setDescription(e.target.value)}
          rules={[
            {
              required: true,
              message: 'Input your description here!',
            },
          ]}
        >
            <Input.Password />
          </Form.Item>
        
          <Select
              defaultValue="Low"
              labelId="priority-select-label"
              id='priority-select-input'
              value={priority}
              label="Priority"
              style={{
                width: 120,
              }}
              onChange={handleChange}
              options={[
                {
                  value: 'low',
                  label: 'low',
                },
                {
                  value: 'medium',
                  label: 'medium',
                },
                {
                  value: 'high',
                  label: 'high',
                },
              ]}
            />

          <Form.Item
              label="Due Date"
              type="text"
              defaultValue=""
              id="outlined-dueDateText"
              onChange={(e) => setDueDate(e.target.value)}
              rules={[
                {
                  required: true,
                  message: 'Input due date here!',
                },
              ]}
            >
                <Input.DueDate />
          </Form.Item>        

          <Form.Item
            wrapperCol={{
              offset: 10,
              span: 16,
            }}
        >
          <Button type="primary" onClick={() => onProductSubmit()} htmlType="login">
            Login  
          </Button>
        </Form.Item>
      </div>
     </Form>
    </div>
  );

}

export default ProductCreate;