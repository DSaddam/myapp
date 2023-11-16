import React, { useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";
import { ToastContainer, toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
function LoginPage({ setLoggedIn }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const navigate = useNavigate();
  const handleLogin = () => {
    axios
      .post("https://dynamic-auto-shipp-app.onrender.com/userauth", {
        username: username,
        password: password
      })
      .then((response) => {
        // Assuming response.data.token is the authentication token
        toast.success("login successfully...", {
            position: "top-right",
            autoClose: 5000,
            hideProgressBar: false,
            closeOnClick: true,
            pauseOnHover: true,
            draggable: true,
            progress: undefined,
            theme: "dark",
          });
        const token = response.data.token;
        console.log("token:",token)
        if (token) {
          setLoggedIn(true);
          localStorage.setItem("token", token);
          localStorage.setItem("isLoggedIn", "true");
        }
      })
      .catch((error) => {
        toast.error("login failled...", {
            position: "top-right",
            autoClose: 5000,
            hideProgressBar: false,
            closeOnClick: true,
            pauseOnHover: true,
            draggable: true,
            progress: undefined,
            theme: "light",
          });
        console.error("Error:", error);
      });
  };

  return (
    <>
    <div className="login">
        <div className="login_content">
      <h1>Login</h1>
      <div>
        <label>
            <span>
          Username:
          </span>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </label>
      </div>
      <div>
        <label>
            <span>
          Password:
          </span>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>
      </div>
      <button onClick={handleLogin}>Login</button>
      
    </div>
   </div>
    <ToastContainer
        position="top-right"
        autoClose={5000}
        hideProgressBar={false}
        newestOnTop={false}
        closeOnClick
        rtl={false}
        pauseOnFocusLoss
        draggable
        pauseOnHover
        theme="dark"
      />
      </>
  );
}

export default LoginPage;
