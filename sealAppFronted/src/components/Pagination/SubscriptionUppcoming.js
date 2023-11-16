import React, { useState, useEffect, useMemo } from 'react';
import Pagination from './Pagination'; // Assuming you have this component
import { Dna } from 'react-loader-spinner'; // Assuming you have this component
import './PaginationApp.css'; // Assuming this is for styling

const PageSize = 10;

export default function SubscriptionUpcoming() {
  var concatenatedValue;
  const [currentPage, setCurrentPage] = useState(1);
  const [searchTerm, setSearchTerm] = useState('');
  const [data, setData] = useState([]); // State to hold the fetched data
  const [isLoading, setIsLoading] = useState(true); // New state for loading indicator

  useEffect(() => {
    fetch('https://dynamic-auto-shipp-app.onrender.com/subscription/order')
      .then(response => response.json())
      .then(data => {
        setData(data);
        setIsLoading(false); // Set isLoading to false when data is loaded
      })
      .catch(error => {
        console.error('Error fetching data:', error);
        setIsLoading(false); // Set isLoading to false in case of an error
      });
  }, []);

  const handleSearch = (event) => {
    setSearchTerm(event.target.value);
    setCurrentPage(1);
  };

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
      <div>
        <div className="search-container">
          <input
            type="text"
            placeholder="Search..."
            value={searchTerm}
            onChange={handleSearch}
          />
        </div>
        <table className='upcomin_subscription'>
          <thead>
            <tr>
              <th>Order name</th>
              <th>Customer Name</th>
              <th>Customer Email</th>
              <th>Next Shipment Date</th>
              <th>Total Price</th>
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
                    <td>{item.Next_Shipment_Date}</td>
                    <td>${item.subscription_total_price}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="5" className="text-center">
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
        
      </div>

    </>
  );
}
