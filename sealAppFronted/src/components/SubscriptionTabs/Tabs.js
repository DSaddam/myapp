import React, { useState } from 'react';
import './Tabs.css'; // Import the custom CSS file

const Tabs = ({ tabsData }) => {
  const [activeTab, setActiveTab] = useState(0);

  const handleTabClick = (index) => {
    setActiveTab(index);
  };

  return (
    <div className="tabs">
      <div className="tab-buttons">
        {tabsData.map((tab, index) => (
          <button
            key={index}
            className={index === activeTab ? 'active btn btn-primary' : 'btn btn-light'}
            onClick={() => handleTabClick(index)}
          >
            {tab.label}
          </button>
        ))}
      </div>
      <div className="tab-content">
        {tabsData[activeTab].content}
      </div>
    </div>
  );
};

export default Tabs;
