const crypto = require("crypto");
function verifyWebhook(data, hmacHeader, SHOPIFY_APP_SECRET) {
    // console.log("data, hmacHeader,SHOPIFY_APP_SECRET:-",data, hmacHeader, SHOPIFY_APP_SECRET);
    const calculatedHmac = crypto
      .createHmac('sha256', SHOPIFY_APP_SECRET)
      .update(data)
      .digest('base64');
      console.log("value boolean ::",hmacHeader,"===================",calculatedHmac)
    return crypto.timingSafeEqual(Buffer.from(hmacHeader), Buffer.from(calculatedHmac));
  }


  module.exports = verifyWebhook;