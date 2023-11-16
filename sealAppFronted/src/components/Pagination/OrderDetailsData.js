import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Dna } from "react-loader-spinner";

const OrderDetailsData = () => {
  const [orderData, setOrderData] = useState(null);
  const [isLoading, setIsLoading] = useState(true);

  var dynamicSubscriptionOrderUrl ,SubscriptionOrderId ,subscriptionPortalToken ,subscription_order_id ,Subscription_email_id ;
  useEffect(() => {
    // Fetch data from the API
    fetch("http://localhost:7709/order")
      .then((response) => response.json())
      .then((data) => {
        setOrderData(data); // Set the fetched data to state
         dynamicSubscriptionOrderUrl = `https://admin.shopify.com/store/genucel105/orders/${data[0].subscription_order_id}`;
         SubscriptionOrderId = data[0].subscription_order_id;
         subscriptionPortalToken = data[0].portalToken;
         subscription_order_id = data[0].subscription_order_id;
         Subscription_email_id = data[0].subscription_customer_email;
         setIsLoading(false); // Set loading to false once data is loaded
      })
      .catch((error) => {
        console.error("Error fetching data:", error);
      });
  }, []);

  if (!orderData) {
    return null; // If data is not yet loaded, return null or a loading indicator
  }

  function resendSubscription(){
    console.log("resendSubscription is working..............")
    axios
    .post(`https://auto-shipped.onrender.com/resendSubscriptionEmail/order/${subscriptionPortalToken}`, {
      subscriptionPortalToken: subscriptionPortalToken,
      subscription_email_id:Subscription_email_id,
    })
    .then((response) => {
      console.log(response);
    })
    .catch((error) => console.error("Error deleting data:", error));
  }

  return (
    <>
     <Dna
          visible={true}
          height={80}
          width={80}
          ariaLabel="dna-loading"
          wrapperStyle={{}}
          wrapperClass="dna-wrapper"
        />
      {isLoading && (
        <Dna
          visible={true}
          height={80}
          width={80}
          ariaLabel="dna-loading"
          wrapperStyle={{}}
          wrapperClass="dna-wrapper"
        />
      )}
      {!isLoading && (
        <div>
          <h1>Order Details</h1>
          <p>ID: {orderData[0].id}</p>
          <p>Order Name: {orderData[0].subscription_order_name}</p>
          {/* Add other properties as needed */}
          {/* Rest of your component... */}
        </div>
      )}
    </>
  );
}

export default OrderDetailsData;
