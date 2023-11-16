// fetch('https://sealapp-6ptb.onrender.com/getadd/addIntervalDays')
// .then(response => response.json())
// .then(data => console.log(data.subscription_interval_days))
// .catch(error => console.error('Error fetching data:', error));var subscription_order_name = "#1024";

// Define the number of times you want to increment
// let counter = 0;

// function processValue(value) {
//     if (value === "#1024" && counter === 0) {
//         counter++;
//         return "#1024";
//     } else if (value === "#1024" && counter === 1) {
//         counter++;
//         return "#1025";
//     } else {
//         return value;
//     }
// }

// // Example usage:
// let firstValue = processValue("#1024"); // This will return "#1024"
// let secondValue = processValue("#1024"); // This will return "#1025"

// console.log(firstValue); // Output: "#1024"
// console.log(secondValue); // Output: "#1025"

// function incrementValue(inputValue) {
//     let numberPart = parseInt(inputValue.slice(1));
//     numberPart++;
//     return "#" + numberPart;
// }

// let value1 = "#1024";
// let updatedValue1 = incrementValue(value1);
// console.log(updatedValue1);  // Output: "#1025"

// let value2 = "#1025";
// let updatedValue2 = incrementValue(value2);
// console.log(updatedValue2);  // Output: "#1026"

// let counter = 0;
// var subscription_order_name = "#1024";
// function processValue(value) {
//     if (value === subscription_order_name && counter === 0) {
//         counter++;
//         return subscription_order_name;
//     } else if (value === subscription_order_name && counter === 1) {
//         counter++;
//         return subscription_order_name;
//     } else {
//         return value;
//     }
// }

// // Example usage:
// let firstValue = processValue("#1024"); // This will return "#1024"
// let secondValue = processValue("#1024"); // This will return "#1025"

// console.log(firstValue); // Output: "#1024"
// console.log(secondValue); // Output: "#1025"

// for (let i = 1; i <= 11; i++) {
//     let concatenatedValue = i + 1000;
//     console.log(i + ' to ' + concatenatedValue);
// }

// const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
// let fiftyCharToken = '';

// for (let i = 0; i < 50; i++) {
//   const randomIndex = Math.floor(Math.random() * characters.length);
//   fiftyCharToken += characters.charAt(randomIndex);
// }

// console.log(fiftyCharToken);

// const path = require('path');
// const fs = require('fs');
// require('dotenv').config();

// function GetAccessToken(access_token_value, shop_domain) {
//   const envFilePath = path.join(__dirname, ".env");
//   const newVariables = {
//     accessToken: access_token_value,
//     shopName: shop_domain
//   };

//   fs.readFile(envFilePath, "utf-8", (err, data) => {
//     if (err) {
//       console.error("Error reading .env file:", err);
//       return;
//     }

//     const envVariables = {};
//     data.split("\n").forEach((line) => {
//       const [key, value] = line.split("=");
//       if (key && value) {
//         envVariables[key] = value;
//       }
//     });

//     const mergedVariables = { ...envVariables, ...newVariables };
//     const updatedEnvContent = Object.keys(mergedVariables)
//       .map((key) => `${key}=${mergedVariables[key]}`)
//       .join("\n");

//     fs.writeFile(envFilePath, updatedEnvContent, "utf-8", (err) => {
//       if (err) {
//         console.error("Error writing .env file:", err);
//         return;
//       }
//       console.log(".env file updated successfully.");
//     });
//   });
// }
// console.log("shopname in env file:-", process.env.shopName);

// // Example usage
// GetAccessToken("myAccessToken", "myShopDomain1");


// Get the URL
// Get the URL
// var url = "https://chamoixapp.myshopify.com/admin/oauth/authorize?client_id=1f484431ebf7cbe9f1b06963f7357765&scope=read_orders,write_orders,read_products,write_products,read_customers,write_customers,read_shipping,write_shipping,read_themes,write_themes,read_checkouts,write_checkouts&state=169758650438300&redirect_uri=https://dynamic-auto-shipp-app.onrender.com/shopify/callback";
// function getParameter(url, param) {
//   var params = new URLSearchParams(new URL(url).search);
//   return params.get(param);
// }

// // Get the client_id value
// var clientId = getParameter(url, 'client_id');

// // Output the value
// console.log(clientId);

// const crypto = require('crypto');
  
// const a = Buffer.alloc("<Buffer 73 4e 39 35 43 67 42 55 44 2f 47 70 46 39 43 38 36 65 72 4e 79 69 66 4e 55 73 67 37 68 78 67 49 36 4e 50 2f 41 6c 71 52 4e 45 55 3d>"); 
// const b = Buffer.alloc("<Buffer 35 71 75 70 36 4e 72 44 68 69 57 62 41 4d 38 6e 4d 78 51 4f 44 6b 34 53 42 42 50 57 6c 53 74 37 43 6f 43 6f 71 34 7a 6c 67 34 4d 3d>"); 
  
// let res = crypto.timingSafeEqual(a, b); 
// console.log(res);

let url = "/shopify?hmac=5e2d5e572746949ce11aec7f5043c545ea69e25e0687d95bf6a85cbb5f26b5b1&host=YWRtaW4uc2hvcGlmeS5jb20vc3RvcmUvY2hhbW9peGFwcA&shop=chamoixapp.myshopify.com&timestamp=1698192625";

let modifiedUrl = url.replace(/^\/shopify/, '');

console.log(modifiedUrl);

let parsedUrl = new URL("http://example.com" + modifiedUrl);

// Remove the first segment (in this case, "/shopify")
parsedUrl.pathname = parsedUrl.pathname.substring(parsedUrl.pathname.indexOf('/', 1));

let RedirectEmbedurl = parsedUrl.toString();

console.log("sjsjkhsjkhsj=",modifiedUrl1)