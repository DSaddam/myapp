import React from 'react';
import Tabs from './Tabs';
import Pagination from "../Pagination/PaginationApp";
import SubscriptionUppcoming from '../Pagination/SubscriptionUppcoming';
import SubscriptionCancelOrder from '../Pagination/SubscriptionCancelOrder';
const SubscriptionComponent = () => {
  const tabsData = [
    {
      label: 'All',
      content: <div><Pagination /></div>,
    },
    {
      label: 'Upcoming subscriptions',  
      content: <div><SubscriptionUppcoming/></div>,
    },
    {
      label: 'With failed payment',
      content: <div>Content for With failed payment</div>,
    },
    {
      label: 'With pending payment',
      content: <div>Content for With pending payment</div>,
    },
    {
      label: 'Paused',
      content: <div>Content for Paused</div>,
    },
    {
      label: 'Cancelled',
      content: <div><SubscriptionCancelOrder/></div>,
    },
  ];

  return (
    <div>
      <Tabs tabsData={tabsData} />
    </div>
  );
};

export default SubscriptionComponent;
