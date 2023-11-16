import React from 'react';
// import Tabs from './Tabs';
import SettingsTab from './SettTab';
import { SettingConfigApp } from './SettingConfigApp';
const SettingsMainTab = () => {
  const tabsData = [
    {
      label: 'General settings',
      content: <div className='SettingConfigApp'><SettingConfigApp /></div>
    }
    // {
    //   label: 'Upcoming subscriptions',  
    //   content: <div>skdahgdhb</div>,
    // },
    // {
    //   label: 'With failed payment',
    //   content: <div>Content for With failed payment</div>,
    // },
    // {
    //   label: 'With pending payment',
    //   content: <div>Content for With pending payment</div>,
    // },
    // {
    //   label: 'Paused',
    //   content: <div>Content for Paused</div>,
    // },
    // {
    //   label: 'Cancelled',
    //   content: <div>ashahgdhhj</div>,
    // },
  ];

  return (
    <div>
      <SettingsTab tabsData={tabsData} />
    </div>
  );
};

export default SettingsMainTab;
