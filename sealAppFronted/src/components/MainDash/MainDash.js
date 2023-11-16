import React, { useState, useEffect } from "react";
import axios from 'axios';
import "./MainDash.css";

const MainDash = () => {
  const [isChecked, setIsChecked] = useState(false);

  useEffect(() => {
    // Restore the toggle state from local storage when the component mounts
    const storedToggleState = localStorage.getItem('subscriptionToggleState');
    if (storedToggleState) {
      setIsChecked(storedToggleState === 'true');
    }
  }, []);

  const handleToggleChange = () => {
    const newValue = !isChecked;
    setIsChecked(newValue);
    
    localStorage.setItem('subscriptionToggleState', newValue);

    axios.post('https://dynamic-auto-shipp-app.onrender.com/scriptrender/toggle', { isChecked: newValue })
      .then((response) => {
        console.log('Data sent successfully:', response.data);
      })
      .catch((error) => {
        console.error('Error sending data:', error);
      });
  };

  return (
    <div className="MainDash">
      <div className="MainDashConetent">
        <h1>Dashboard</h1>
        <div className="MaindashboardSlide">
          <h3>App embeds Subscription script</h3>
          <label>
            <input
              type="checkbox"
              checked={isChecked}
              onChange={handleToggleChange}
            />
            <span className="toggle-slider"></span>
          </label>
        </div>
      </div>
    </div>
  );
};

export default MainDash;
