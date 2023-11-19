import {
  Product,
  Register,
  Login
} from "./components";
import { createBrowserRouter, RouterProvider } from "react-router-dom";
import "./App.css";

function App() {
  const router = createBrowserRouter([
    {
      path: "/product",
      element: <Product />,
    },
    {
      path: "/",
      element: <Register />,
    },
    {
      path: "/login",
      element: <Login />,
    },

  ]);

  return (
    <>
      <RouterProvider router={router} />
    </>
  );
}

export default App;