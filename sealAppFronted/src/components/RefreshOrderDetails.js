// import React, { createContext, useState, useContext } from 'react';

// const RefreshContext = createContext();

// export const RefreshProvider = ({ children }) => {
//   const [refresh, setRefresh] = useState(false);

//   const toggleRefresh = () => {
//     setRefresh(prevRefresh => !prevRefresh);
//   };

//   return (
//     <RefreshContext.Provider value={{ refresh, toggleRefresh }}>
//       {children}
//     </RefreshContext.Provider>
//   );
// };

// export const useRefresh = () => {
//   const context = useContext(RefreshContext);
//   if (!context) {
//     throw new Error('useRefresh must be used within a RefreshProvider');
//   }
//   return context;
// };
