const { DeliveryMethod } = require("@shopify/shopify-api");
const shopify = require("../../utils/shopifyConfig.js");
const appUninstallHandler = require("./app_uninstalled.js");

const webhookRegistrar = async () => {
  shopify.webhooks.addHandlers({
    APP_UNINSTALLED: {
      deliveryMethod: DeliveryMethod.Http,
      callbackUrl: "/webhooks/app_uninstalled",
      callback: appUninstallHandler,
    },
  });
};

module.exports = webhookRegistrar;
