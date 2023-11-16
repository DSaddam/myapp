// OrderDetails.js
import {React,useState} from "react";
import axios from "axios";
import Clipboard from "./Clipboard";
import { ToastContainer, toast } from 'react-toastify';
import { useRefresh } from '../RefreshOrderDetails';
import 'react-toastify/dist/ReactToastify.css';
export default function OrderDetails({ orderData, onClose, onChildButtonClick  }) {
 var SubscriptionOrderId = orderData.subscription_order_id;
 var subscriptionPortalToken = orderData.portalToken;
  const subscription_order_id = orderData.subscription_order_id;
  const Subscription_email_id = orderData.subscription_customer_email;
  const [data, setData] = useState();
let subscriptionIntervalDays = "";

if (data && data.length > 0 && data[0].subscription_interval_days) {
  subscriptionIntervalDays = data[0].subscription_interval_days;
}
// var updateData = [];

  
 var dynamicSubscriptionOrderUrl = `https://admin.shopify.com/store/genucel105/orders/${subscription_order_id}`;
//  const { toggleRefresh } = useRefresh();
  function Copyportal() { // Copy the selected text to clipboard
    toast.success('copy successfully...', {
      position: "top-center",
      autoClose: 5000,
      hideProgressBar: false,
      closeOnClick: true,
      pauseOnHover: true,
      draggable: true,
      progress: undefined,
      theme: "dark",
      });
    console.log("order id:",subscriptionPortalToken);
    console.log(orderData.id)
    axios
    .post(`https://dynamic-auto-shipp-app.onrender.com/subscriptionPortal/order/${subscriptionPortalToken}`, {
      subscriptionPortalToken: subscriptionPortalToken,
    })
    .then((response) => {
      // const updatedData = data.filter(
      //   (item) => item.subscription_order_id !== orderId
      // );
      // setData(updatedData);
      // setShowCancelMessage(response.data.message);
      console.log(response.data.message);
    })
    .catch((error) => console.error("Error deleting data:", error));
  }
  
  // console.log("itemnjhskjdjsdhushbdjkashdaghdbhasmgda..........",item.portalToken);
  const handleRefreshClick = async () => {
    try {
      const response = await axios.get('https://dynamic-auto-shipp-app.onrender.com/subscriptionPortal/orderdetails');
  
      // console.log(response.data[0].subscription_interval_days);
      // updateData.push(response.data[0].subscription_interval_days);
      // Assuming that the response contains the order ID
      const orderID = response.data.orderID; // Adjust this based on the actual response
      setData(response.data[0].subscription_interval_days); 
      // Navigate to the order details page
      // navigation(`/order/${item.portalToken}`);
      toast.success("Refresh...", {
        position: "top-right",
        autoClose: 5000,
        hideProgressBar: false,
        closeOnClick: true,
        pauseOnHover: true,
        draggable: true,
        progress: undefined,
        theme: "dark",
      });
    } catch (error) {
      console.error('Error fetching data:', error);
    }
    console.log("aJHnXjhxjxnbzhasbsnbhschbs ",data)
  };

  function resendSubscription(){
    console.log("resendSubscription is working..............")
    axios
    .post(`https://dynamic-auto-shipp-app.onrender.com/resendSubscriptionEmail/order/${subscriptionPortalToken}`, {
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
    <div className="order-details">
      <div className="order_details_container">
        <div className="order__details_top">
          <div className="order__details__row">
            <div className="order__details_col">
              <div className="order__details_col_content">
              <svg
                onClick={onClose}
                viewBox="0 0 20 20"
                class="Polaris-Icon__Svg"
                focusable="false"
                aria-hidden="true"
              >
                <path d="M17 9h-11.586l3.293-3.293a.999.999 0 1 0-1.414-1.414l-5 5a.999.999 0 0 0 0 1.414l5 5a.997.997 0 0 0 1.414 0 .999.999 0 0 0 0-1.414l-3.293-3.293h11.586a1 1 0 1 0 0-2z"></path>
              </svg>
              <h2>
                Subscription
                <span className="order__number">
                  {orderData.subscription_order_name}
                </span>
              </h2>
              </div>
              <span onClick={() => {
                //  onChildButtonClick()
                 handleRefreshClick()
                 } } >Refresh</span>
            </div>

            <div className="order__view__section">
              <div className="order__view__content">
                <div className="order__view__content_orderdata">
                  <h2 className="order__Overview">Overview</h2>
                  <h3 className="order__status">
                    status:<span className="active__status">{orderData.Status} </span>
                  </h3>
                  <div className="Polaris-Stack__Item">
                    <span className="Polaris-TextStyle--variationStrong">
                      Created:
                    </span>{" "}
                    <a
                      target="_blank"
                      className="Polaris-Link date__order"
                      href={dynamicSubscriptionOrderUrl}
                      rel="noopener noreferrer"
                      data-polaris-unstyled="true"
                    >
                      {orderData.create_order_date}
                      <span class="Polaris-Link__IconLockup">
                        <span class="Polaris-Link__IconLayout">
                          <span class="Polaris-Icon">
                            <span class="Polaris-VisuallyHidden">
                              (opens a new window)
                            </span>
                            <svg
                              viewBox="0 0 20 20"
                              class="Polaris-Icon__Svg"
                              focusable="false"
                              aria-hidden="true"
                            >
                              <path d="M14 13v1a1 1 0 0 1-1 1h-7c-.575 0-1-.484-1-1v-7a1 1 0 0 1 1-1h1c1.037 0 1.04 1.5 0 1.5-.178.005-.353 0-.5 0v6h6v-.5c0-1 1.5-1 1.5 0zm-3.75-7.25a.75.75 0 0 1 .75-.75h4v4a.75.75 0 0 1-1.5 0v-1.44l-3.22 3.22a.75.75 0 1 1-1.06-1.06l3.22-3.22h-1.44a.75.75 0 0 1-.75-.75z"></path>
                            </svg>
                          </span>
                        </span>
                      </span>
                    </a>
                  </div>
                  <div class="Polaris-Stack__Item">
                    <span class="Polaris-TextStyle--variationStrong">
                    {/* Repeats every  {orderData.subscription_interval_days} */}
                      Repeats every {data ? (
                      <span class="1">{data}</span>
                      ) : (
                      <span class="2">{orderData.subscription_interval_days}</span>
                      )}
                    </span>
                  </div>
                  <div class="Polaris-Stack__Item">
                    <span class="Polaris-TextStyle--variationStrong">
                      Subscription type:
                    </span>{" "}
                    <span>Auto-charge</span>
                  </div>
                  <div class="Polaris-Stack__Item">
                    <div class="Polaris-Stack">
                      <div class="Polaris-Stack__Item">
                        <a
                          target="_blank"
                          class="Polaris-Button"
                          href={dynamicSubscriptionOrderUrl}
                          rel="noopener noreferrer"
                          data-polaris-unstyled="true"
                        >
                          <span class="Polaris-Button__Content">
                            <span class="Polaris-Button__Text">
                              View initial order
                            </span>
                          </span>
                        </a>
                      </div>
                      <div class="Polaris-Stack__Item">
                        <div>
                          <button class="Polaris-Button" type="button" onClick={resendSubscription}>
                            <span class="Polaris-Button__Content">
                              <span class="Polaris-Button__Text">
                                Resend <i>New subscription</i> email
                              </span>
                            </span>
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                  <div class="Polaris-Stack__Item">
                    <div class="Polaris-Stack Polaris-Stack--alignmentCenter">
                      <div class="Polaris-Stack__Item">
                        <button class="Polaris-Button" type="button">
                          <span class="Polaris-Button__Content">
                            <span class="Polaris-Button__Text">
                              Access customer portal
                            </span>
                          </span>
                        </button>
                      </div>
                      <div class="Polaris-Stack__Item">
                        <div>
                          <div>
                            {/* <button
                              class="Polaris-Button Polaris-Button--plain"
                              type="button"
                              onClick={Copyportal}
                            >
                              <span class="Polaris-Button__Content">
                                <span class="Polaris-Button__Text">
                                  Copy portal link
                                </span>
                              </span>
                            </button> */}
                            {/* <form>
                                <textarea
                                readOnly
                                value="https://proviahair.com/a/subscriptions/manage/opm9/authenticate/?sealkey=76c98b0180a07e6b4bbece114907b243840e2d02e24cfc493d6ce0730b345950"
                                onChange={({target:{value}}) => setTextareaValue(value)}
                                />  
                            </form> */}
                           <Clipboard Copyportal={Copyportal} SubscriptionOrderId={orderData.subscription_order_id}SubscriptionPortalToken = {orderData.portalToken} />
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                  <div class="Polaris-Stack__Item">
                    <span class="Polaris-TextStyle--variationStrong">
                      Customer locale:{" "}
                    </span>
                    English
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
      {/* <button onClick={onClose}>Close</button>
      <ul>
        <li>Order Name: {orderData.subscription_order_name}</li>
        <li>Customer Name: {orderData.subscription_customer_name}</li>
        <li>Customer Email: {orderData.subscription_customer_email}</li>
        <li>Order Date: {orderData.create_order_date}</li>
        <li>Order ID: {orderData.subscription_order_id}</li>
        <li>Next Shipment Date: {orderData.Next_Shipment_Date}</li>
        <li>Interval: {orderData.subscription_interval_days}</li>
        <li>Total Price: {orderData.subscription_total_price}</li>
        <li>Status: {orderData.Status}</li>
        <li>Cancel Date: {orderData.subscription_cancel_date}</li>
      </ul> */}
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
