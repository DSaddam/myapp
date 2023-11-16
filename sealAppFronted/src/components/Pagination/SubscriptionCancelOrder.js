// import React from 'react'

// export const SubscriptionCancelOrder = () => {
//   return (
//     <div>SubscriptionCancelOrder</div>
//   )
// }
import React, { useState, useEffect, useMemo } from 'react';
import Pagination from './Pagination';
import './usePagination';
import './PaginationApp.css';
import { Dna } from 'react-loader-spinner';
// import axios from 'axios';
let PageSize = 8;

export default function PaginationApp() {
  var concatenatedValue;
  const [currentPage, setCurrentPage] = useState(1);
  const [searchTerm, setSearchTerm] = useState('');
  const [data, setData] = useState([]); // State to hold the fetched data
  const [showCancelMessage, setShowCancelMessage] = useState();
  const [isLoading, setIsLoading] = useState(true);
  useEffect(() => {
    // Fetch data from the API
    fetch('https://dynamic-auto-shipp-app.onrender.com/subscription/cancelledorder')
      .then(response => response.json())
      .then(data => {
        setData(data);
        setIsLoading(false);
      })
      .catch(error => {
        setIsLoading(false);
        console.error('Error fetching data:', error)
      });
  }, []);

  const handleSearch = (event) => {
    setSearchTerm(event.target.value);
    setCurrentPage(1);
  };

  //   const handleCancel = (orderId) => {
  //     // Send a DELETE request to your backend API using Axios
  //     axios.post(`https://dynamic-auto-shipp-app.onrender.com/subscription/order/${orderId}`)
  //       .then(response => {
  //         // Remove the item from the data in state
  //         const updatedData = data.filter(item => item.subscription_order_id !== orderId);
  //         setData(updatedData);
  //         setShowCancelMessage(response.data.message);
  //         console.log(response.data.message);
  //       })
  //       .catch(error => console.error('Error deleting data:', error));
  //   };



  const filteredData = useMemo(() => {
    return data.filter(
      (item) =>
        item.subscription_customer_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        item.subscription_customer_email.toLowerCase().includes(searchTerm.toLowerCase()) ||
        item.subscription_order_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        item.subscription_order_id.includes(searchTerm)
    );
  }, [searchTerm, data]);

  const currentTableData = useMemo(() => {
    const firstPageIndex = (currentPage - 1) * PageSize;
    const lastPageIndex = firstPageIndex + PageSize;
    return filteredData.slice(firstPageIndex, lastPageIndex);
  }, [currentPage, filteredData]);

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
      <table className='SubscriptionCancelOrder'>
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
            <th>Cancel Date</th>
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
                    <td>${item.subscription_total_price}</td>
                    <td>{item.Status}</td>
                    <td className='subscription_cancel_date'>{item.subscription_cancel_date}</td>
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
      </table>
      <Pagination
        className="pagination-bar"
        currentPage={currentPage}
        totalCount={filteredData.length}
        pageSize={PageSize}
        onPageChange={(page) => setCurrentPage(page)}
      />
    </>
  );
}
