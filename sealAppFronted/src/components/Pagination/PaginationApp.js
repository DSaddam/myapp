import React, { useState, useEffect, useMemo } from "react";
import Pagination from "./Pagination";
import "./usePagination";
import "./PaginationApp.css";
import axios from "axios";
import OrderDetails from "./OrderDetails";
import { Dna } from "react-loader-spinner";
import { ToastContainer, toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import { Link,useNavigate } from "react-router-dom";
let PageSize = 8;
export default function PaginationApp() {
  const navigation = useNavigate();
  var concatenatedValue;
  const [currentPage, setCurrentPage] = useState(1);
  const [searchTerm, setSearchTerm] = useState("");
  const [data, setData] = useState([]); // State to hold the fetched data
  const [showCancelMessage, setShowCancelMessage] = useState();
  const [showOrderDetails, setShowOrderDetails] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [active, setActive] = useState(true);
  const [refresh, setRefresh] = useState(false);

  const [updateportal,setUpdateportal] = useState();
  
  useEffect(() => {
    // Fetch data from the API
    fetch("https://dynamic-auto-shipp-app.onrender.com/subscription/order")
      .then((response) => response.json())
      .then((data) => {
        setData(data);
        setIsLoading(false);
      })
      .catch((error) => {
        setIsLoading(false);
        console.error("Error fetching data:", error);
      });
  }, [refresh]);


  const viewOrder = (item) => {
    console.log("item", item);
  
    // axios
    //   .post(`http://localhost:7709/order/${item.portalToken}`, {
    //     portalToken: item.portalToken,
    //   })
    //   .then((response) => {
    //     console.log(response);
  
    //     // Assuming that the response contains the order ID
    //     const orderID = response.data.orderID; // Adjust this based on the actual response
  
    //     // Navigate to the order details page
    //     navigation(`/order/${item.portalToken}`);
    //   })
    //   .catch((error) => {
    //     console.error("Error sending data:", error);
    //   });
  };
  
  const handleSearch = (event) => {
    setSearchTerm(event.target.value);
    setCurrentPage(1);
  };
  const handleCancel = (subscriptionPortalToken) => {
    // Get the current date and time
    const dateObject = new Date();
    const numberOfDaysToAdd = 0; // Adjust this if you want to add a specific number of days
    dateObject.setDate(dateObject.getDate() + numberOfDaysToAdd);
    const updatedDate = dateObject.toISOString().slice(0, 10);

    // Extract hours and minutes from the date
    const hours = String(dateObject.getHours()).padStart(2, "0");
    const minutes = String(dateObject.getMinutes()).padStart(2, "0");

    // Form the formatted time string
    const ampm = hours >= 12 ? "PM" : "AM";
    const hours12 = hours % 12 || 12; // Convert to 12-hour format

    const formattedTime = `${hours12}:${minutes
      .toString()
      .padStart(2, "0")} ${ampm}`;

    const date_with_time = `${updatedDate} ${formattedTime}`;

    // Send a DELETE request to your backend API using Axios
    axios
      .post(`https://dynamic-auto-shipp-app.onrender.com/subscription/order/${subscriptionPortalToken}`, {
        cancellationDateTime: date_with_time,
      })
      .then((response) => {
        // Remove the item from the data in state
        const updatedData = data.filter(
          (item) => item.portalToken !== subscriptionPortalToken
        );
        setData(updatedData);
        setShowCancelMessage(response.data.message);
        toast.success("cancel successfully...", {
          position: "top-right",
          autoClose: 5000,
          hideProgressBar: false,
          closeOnClick: true,
          pauseOnHover: true,
          draggable: true,
          progress: undefined,
          theme: "dark",
        });
        console.log(response.data.message);
      })
      .then((response) => {
        const updatedData = data.filter(
          (item) => item.portalToken !== subscriptionPortalToken
        );
        setData(updatedData);
        setShowCancelMessage(response.data.message);
        console.log(response.data.message);
      })
      .catch((error) => console.error("Error deleting data:", error));
  };

  const filteredData = useMemo(() => {
    return data.filter(
      (item) =>
        item.subscription_customer_name
          .toLowerCase()
          .includes(searchTerm.toLowerCase()) ||
        item.subscription_customer_email
          .toLowerCase()
          .includes(searchTerm.toLowerCase()) ||
        item.subscription_order_name
          .toLowerCase()
          .includes(searchTerm.toLowerCase()) ||
        item.subscription_order_id.includes(searchTerm)
    );
  }, [searchTerm, data]);

  const currentTableData = useMemo(() => {
    const firstPageIndex = (currentPage - 1) * PageSize;
    const lastPageIndex = firstPageIndex + PageSize;
    return filteredData.slice(firstPageIndex, lastPageIndex);
  }, [currentPage, filteredData]);

  const handleChildButtonClick = () => {
    setRefresh(prevState => !prevState);
    console.log("refresh parents component....11",currentTableData);
    // return (
    //     <OrderDetails
    //         orderData={showOrderDetails}
    //         onChildButtonClick={handleChildButtonClick}
    //         onClose={() => {
    //             setShowOrderDetails(null)
    //             setActive(true);
    //         }}
    //     />
    // );
     console.log("dlasjdslkdn,sjdkasjdnsksjhn",data)
};
  return (
    <>
      <div className="search-container">
        <input
          type="text"
          placeholder="Search..."
          value={searchTerm}
          onChange={handleSearch}
        />
      </div>
      {active && (
        <>
        <table>
          <thead>
            <tr>
              <th>Order name</th>
              <th>Customer Name</th>
              <th>Customer Email</th>
              <th>Order Date</th>
              <th>Order ID</th>
              <th>NextShipment Date</th>
              <th>Total Price</th>
              <th>Status</th>
              <th colSpan={2}></th>
            </tr>
          </thead>
          <tbody>
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
              <>
                {currentTableData.length > 0 ? (
                  currentTableData.map((item) => (
                  
                    <tr key={item.id}>
                      
                      <td>#{ concatenatedValue = item.id + 1000}</td>
                      <td>{item.subscription_customer_name}</td>
                      <td>{item.subscription_customer_email}</td>
                      {/* <td>{formatDate(item.create_order_date)}</td> */}
                      <td>{item.create_order_date}</td>
                      <td>{item.subscription_order_id}</td>
                      {/* <td>{formatDate(item.Next_Shipment_Date)}</td> */}
                      <td>{item.Next_Shipment_Date}</td>
                      <td>${item.subscription_product__price}</td>
                      <td style={{color:"green",fontWeight:"500"}}>{item.Status}</td>
                      <td>
                        {item.Status === "Active" ? (
                          <button
                            className="delete__order"
                            onClick={() =>
                              handleCancel(item.portalToken)
                            }
                          >
                            Cancel
                          </button>
                        ) : (
                          <span>{item.Status}</span>
                        )}
                      </td>
                      <td>
                        <button
                          className="view__order"
                          onClick={() => {
                            console.log("View button clicked"); // Add this line
                            setShowOrderDetails(item);
                            setActive(false);
                            viewOrder(item);
                          }}
                        >
                          <svg
                            viewBox="0 0 20 20"
                            class="Polaris-Icon__Svg"
                            focusable="false"
                            aria-hidden="true"
                          >
                            <path d="M17.928 9.628C17.836 9.399 15.611 4 9.999 4S2.162 9.399 2.07 9.628a1.017 1.017 0 0 0 0 .744C2.162 10.601 4.387 16 9.999 16s7.837-5.399 7.929-5.628a1.017 1.017 0 0 0 0-.744zM9.999 14a4 4 0 1 1 0-8 4 4 0 0 1 0 8zm0-6A2 2 0 1 0 10 12.001 2 2 0 0 0 10 8z"></path>
                          </svg>
                        </button>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="9" className="text-center">
                      No results found.
                    </td>
                  </tr>
                )}
              </>
            )}
          </tbody>
          <Pagination
           className="pagination-bar"
           currentPage={currentPage}
           totalCount={filteredData.length}
           pageSize={PageSize}
           onPageChange={(page) => setCurrentPage(page)}
         />
        </table>
           
         </>
      )}
      {!active && (
        <>
          {/* {showOrderDetails && ( */}
            <OrderDetails
              orderData={showOrderDetails}
              onChildButtonClick={handleChildButtonClick}
              onClose={() => {
                setShowOrderDetails(null)
                setActive(true);
              }}
            />
          {/* )} */}
          {/* {!showOrderDetails && (
         
          )} */}
        </>
      )}
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
