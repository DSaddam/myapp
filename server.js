const crypto = require("crypto");
const nonce = require("nonce")();
const request = require("request-promise");
const querystring = require("querystring");
// const databaseData = require("./db/demo_db_connection");
// const sendSubscriptionEmail = require("./sendSubscriptionEmail");
// const gdpr_data_request = require("./gdpr/cust_data_request");
// const cust_data_erasure = require("./gdpr/cust_data_erasure");
// const gdpr_shop_redact = require("./gdpr/shop_data_erasure");
const mysql = require("mysql");
const axios = require("axios");
const cookie = require("cookie");
const express = require("express");
const path = require("path");
const dotenv = require("dotenv");
var cron = require("node-cron");
const fs = require("fs");
// const storeOrderId = "./storeOrderId";
// const storeOrderId1 = "./refreshgetod";
// const storeOrderId1 = './refreshgetod.json';

// Application Level Middleware


// const path = require('path');
// const multer = require('multer');
var cors = require("cors");
var helmet = require("helmet");
const { json } = require("express");
dotenv.config();
const bodyParser = require("body-parser");
const { captureRejectionSymbol } = require("events");
// const myProxy = require('./middlewares/proxy-middleware');
const { SHOPIFY_API_KEY, SHOPIFY_API_SECRET, accessToken, shopName } =
  process.env;
const app = express();
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.options("*", cors());
// app.use(
//   helmet.contentSecurityPolicy({
//     directives: {
//       // other directives
//       frameAncestors: ["'admin.shopify.com'"] // Compliant
//     }
//   })
// );
const cspConfig = {
  directives: {
    // ... other directives ...
    'frame-ancestors': ["'self'", 'https://unimedindia.myshopify.com/'],
    // ... other directives ...
  },
};

// Use helmet.contentSecurityPolicy middleware with your CSP configuration
app.use(helmet.contentSecurityPolicy(cspConfig));

app.use((req, res, next) => {
  const shop = req.query.shop;

  if (shop) {
    // Set the `frame-ancestors` header based on the shop domain
    const allowedDomains = [
      `https://${shop}.myshopify.com/`,
      'https://admin.shopify.com'
    ];

    res.setHeader(
      'Content-Security-Policy',
      `frame-ancestors ${allowedDomains.join(' ')};`
    );
  }

  next();
});

// ...

// app.use((req, res) => {
//   const shop = req.query.shop;
//   console.log('test',shop)
//   if (shop) {
//     // Set the `frame-ancestors` header on the response
//     res.setHeader(
//       'Content-Security-Policy',
//       `frame-ancestors https://${shop} https://admin.shopify.com;`
//     );
//   }
// });

const staticPath = path.join(__dirname, "build");
app.use(express.static(staticPath));
// app.use('/shopify/callback', myProxy)
// app.use('/shopify/callback', myProxy);
const apiKey = SHOPIFY_API_KEY;

//const upload = multer({ dest: 'uploads/' });
const apisecret = SHOPIFY_API_SECRET;

const scopes =
  "read_orders,read_content,write_content,write_orders,read_script_tags,write_script_tags,read_products,write_products,read_customers,write_customers,read_shipping,write_shipping ,read_themes,write_themes,read_checkouts,write_checkouts";

const forwardingaddress = "https://testappchecker.onrender.com";

app.use(bodyParser.json({ limit: "10mb" }));
app.use(bodyParser.urlencoded({ limit: "10mb", extended: true }));

var shopify_client_id = [];

 var DynamicAccessToken = [];

 var DynamicShopName = [];

 var getEmbedUrl = [];

app.get('/AddPage',(req,res)=>{
  console.log("url:=========",req.url);
  res.sendFile(path.join(__dirname, "build"));
})


app.get("/shopify", (req, res) => {
  // Shop Name
  console.log("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:====", req.url);
  getEmbedUrl.push(req.url);
  const shop = req.query.shop;
  // res.header('Content-Security-Policy', "frame-ancestors 'admin.shopify.com'")
  if (shop) {
    const state = nonce();
    //  redirect
    const redirectURL = forwardingaddress + "/shopify/callback";
    // Install
    const shopifyURL =
      "https://" +
      shop +
      "/admin/oauth/authorize?client_id=" +
      apiKey +
      "&scope=" +
      scopes +
      "&redirect_uri=" +
      redirectURL;
    console.log("nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn>>>>",state);
    res.redirect(shopifyURL);
  } else {
    return res.status(400).send('Missing "Shop Name" parameter!! please add');
  }
});

app.get("/shopify/callback", async (req, res) => {
    // const shop = req.query.shop;/

  const clientId = req.query.clientId; // Assuming you pass clientId as a query parameter
  // const { shop, hmac, code, shopState } = req.query;
  const { hmac, host, shop, code, timestamp } = req.query;

  var lastgetEmbedUrl = getEmbedUrl[getEmbedUrl.length - 1];

  console.log("/shopify/callback/shopify/callback/shopify/callback/shopify/callback:=",lastgetEmbedUrl);
  // const stateCookie = cookie.parse(req.headers.cookie).shopState;
  // if (shopState !== stateCookie) {
  //   return res.status(400).send("request origin cannot be found");

  // }
  if (shop && hmac && code) {
    const Map = Object.assign({}, req.query);
    delete Map["hmac"];
    const message = querystring.stringify(Map);
    const generatehmac = crypto
      .createHmac("sha256", apisecret)
      .update(message)
      .digest("hex");
    // console.log(generatehmac)
    if (generatehmac !== hmac) {
      return res.status(403).send("validation failed");
    }
    const accessTokenRequestUrl =
      "https://" + shop + "/admin/oauth/access_token";
    const accessTokenPayload = {
      client_id: apiKey,
      client_secret: apisecret,
      code,
    };
    // res.header('Content-Security-Policy', "frame-ancestors 'admin.shopify.com'")

    request
      .post(accessTokenRequestUrl, { json: accessTokenPayload })

      .then((accessTokenResponse) => {
        const accessToken = accessTokenResponse.access_token;

        const apiRequestURL = "https://" + shop + "/admin/products.json";

        const apiRequestHeaders = {
          "X-Shopify-Access-Token": accessToken,
        };

        request
          .get(apiRequestURL, { headers: apiRequestHeaders })

          .then(async (apiResponse) => {
            console.log("accessToken:", accessToken);
            GetAccessToken(accessToken, shop);
               let modifiedUrl = lastgetEmbedUrl.replace(/^\/shopify/, '');
                let parsedUrl = new URL(forwardingaddress + modifiedUrl);

                // Remove the first segment (in this case, "/shopify")
                parsedUrl.pathname = parsedUrl.pathname.substring(parsedUrl.pathname.indexOf('/', 1));

                let RedirectEmbedurl = parsedUrl.toString();
               
                 res.redirect(RedirectEmbedurl);
          })
          .catch((error) => {
            res.status(error.statusCode).send(error.error.error_description);
          });
      })
      .catch((error) => {
        res.status(error.statusCode).send(error.error.error_description);
      });
  } else {
    return res.status(400).send("required parameter missing");
  }
  // res.end();
});

app.get('/test', function(req, res) {
  console.log('test');
  res.header('Content-Security-Policy', "frame-ancestors 'admin.shopify.com'")
  res.end('ok');
})

function GetAccessToken(access_token_value, shop_domain) {
  DynamicAccessToken.push(access_token_value);

  DynamicShopName.push(shop_domain);
}

app.listen(3000, () => {
  console.log("running on port 3000");
});
