// var accessToken;
// var domainName;

// function fetchDataFromDatabase(connection) {
//   const query = `
//     SELECT AccessToken, DomainName 
//     FROM GetAccessTokenWithDomainName 
//     LIMIT 1;
//   `;

//   connection.query(query, (error, results) => {
//     if (error) {
//       console.error(error);
//       // Handle the error, return or exit as needed
//       return;
//     }

//     if (results && results.length > 0) {
//       accessToken = results[0].AccessToken;
//       domainName = results[0].DomainName;
//       console.log('AccessToken:', accessToken);
//       console.log('DomainName:', domainName);
//     }
//   });
// }

// module.exports = {
//   accessToken,
//   domainName,
//   fetchDataFromDatabase
// };
