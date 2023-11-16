import React, { useState, useEffect, useMemo } from "react";
import Dashboard from "../MainDash/MainDash";
import Tabs from "../SubscriptionTabs/SubscriptionComponent";
import AddIntervalDays from "../IntervalDays/AddIntervalDays";
import SettingsMainTab from "../Settings/SettingsMainTab";
import OrderDetails from "../Pagination/OrderDetails";
import OrderDetailsData from "../Pagination/OrderDetailsData"
import ShopifyCreatePage from "../ShopifyPage/ShopifyCreatePage";
const Item = (props) => {
  const { page } = props;
  const [showOrderDetails, setShowOrderDetails] = useState(false);
  // const [showTabs, setShowTabs] = useState(true);
  if (page === "homepage") {
    return <div id="page">{page}</div>;
  } else if (page === "dashboard") {
    return (
      <div id="page">
        <Dashboard />
        {/* Render the Dashboard component */}
      </div>
    );
  } else if (page === "Subscriptions") {
    return (
      <>
        <div id="page">
          <div className="pagination">
            <h1
              style={{
                fontSize: 22,
                padding: 10,
                color: "#fff",
                background: "#343a40",
              }}
            >
              Subscriptions
            </h1>
            {/* < Pagination />  */}
            <Tabs />
          </div>
        </div>
        {showOrderDetails && (
          <OrderDetails
            orderData={showOrderDetails}
            onClose={() => {
              setShowOrderDetails(false);
              // Show the Tabs component again
            }}
          />
        )}
      </>
    );
  } else if (page === "Add Interval") {
    return (
      <div id="page">
        <div className="pagination">
          <h1
            style={{
              fontSize: 22,
              padding: 10,
              color: "#fff",
              background: "#343a40",
            }}
          >
            Add Interval
          </h1>
          <AddIntervalDays />
        </div>
      </div>
    );
  } else if (page === "Integrate  Auto Shipped") {
    return (
      <div id="page">
        <div className="pagination">
          <h1
            style={{
              fontSize: 22,
              padding: 10,
              color: "#fff",
              background: "#343a40",
            }}
          >
            Settings
          </h1>
          {/* <SettingsMainTab /> */}
          <h2 style={{fontSize:22,padding: 20}}> Auto Shipped</h2>
        </div>
      </div>
    );
  } else if (page === "Add Page") {
    return (
      <div id="page">
        <div className="pagination">
          <h1
            style={{
              fontSize: 22,
              padding: 10,
              color: '#fff',
              backgroundColor: '#343a40',
            }}
          >
            Create page in Shopify Store
          </h1>
          <span>Create Page Name like <b>[portalsubscription]</b></span>
          <ShopifyCreatePage />
        </div>
      </div>
    );
  // }  else if ("OrderDetails" === "OrderDetails") {
  //   return (
  //     <div id="page">
  //       <div className="pagination">
  //         <h1
  //           style={{
  //             fontSize: 22,
  //             padding: 10,
  //             color: '#fff',
  //             backgroundColor: '#343a40',
  //           }}
  //         >
  //        </h1>
  //         <OrderDetails />
  //       </div>
  //     </div>
  //   );
  } else {
    return <div id="page"><Dashboard /></div>;
  }
};

export default Item;
