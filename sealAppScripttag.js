
function insertAfter(referenceNode, newNode) {
  referenceNode.parentNode.insertBefore(newNode, referenceNode.nextSibling);
  const selectElement = document.getElementById("intervalSelect");

  fetch("https://dynamic-auto-shipp-app.onrender.com/getadd/addIntervalDays")
    .then((response) => response.json())
    .then((data) => {
      const options = data.subscription_interval_days;
      options.forEach((option) => {
        const optionElement = document.createElement("option");
        optionElement.textContent = option;
        optionElement.value = option;
        selectElement.appendChild(optionElement);
      });
    })
    .catch((error) => console.error("Error fetching data:", error));
}
let elem1 = document.createElement("div");
elem1.innerHTML = ` <!DOCTYPE html>
  <html lang="en">
  <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Document</title>
      <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
      <style>
          .product__info-container>*+* {
              margin: 1.5rem 0;
          }
  
          .sealsubs-container {
              font-size: 1em;
              margin-bottom: 1em;
              color: rgb(77, 77, 77);
              color: #4d4d4d;
              display: block;
              clear: both;
              flex: 0 0 100%;
              text-transform: none;
              line-height: 1.6;
              text-align: left;
          }
  
          .sealsubs-container .sls-option-container {
              padding: 10px;
              border-radius: 2px;
              cursor: pointer;
              border: 1px solid rgba(255, 255, 255, 0);
              align-items: center;
          }
  
          .seal-row {
              display: flex;
          }
  
          .seal-col-radio {
              display: flex;
              align-items: center;
          }
  
          .seal-col.seal-col-radio {
              padding-right: 0.5em;
          }
  
          .seal-col-radio {
              vertical-align: top;
          }
  
          .sealsubs-target-element .sls-option[type="radio"] {
              opacity: 0;
              width: 0;
              height: 0;
              float: left;
              position: absolute !important;
          }
  
          .sealsubs-container input[type="radio"] {
              height: auto;
              min-height: unset;
              width: auto;
              margin: 0 0.5em 0 0;
              margin: 0 0 0 0;
              vertical-align: middle;
              -webkit-appearance: radio;
              -moz-appearance: radio;
              display: inline-block;
              top: unset;
              right: unset;
              position: relative !important;
          }
  
          .sealsubs-target-element .sls-custom-radio,
          .sls-option[type="radio"]+span.sls-custom-radio {
              display: block;
              display: grid;
              place-content: center;
              width: 18px;
              height: 18px;
              border-radius: 50%;
              border: 1px solid #4d4d4d;
              border: 1px solid #4d4d4d;
              background: white;
              background: #FFFFFF;
              padding: 0;
          }
  
          .sealsubs-container .sls-option-container {
              padding: 10px;
              border-radius: 2px;
              cursor: pointer;
              border: 1px solid rgba(255, 255, 255, 0);
              align-items: center;
          }
  
          .sealsubs-container {
              font-size: 1em;
              margin-bottom: 1em;
              color: rgb(77, 77, 77);
              color: #4d4d4d;
              display: block;
              clear: both;
              flex: 0 0 100%;
              text-transform: none;
              line-height: 1.6;
              text-align: left;
          }
  
          .seal-col:nth-child(2n) {
              width: 100%;
          }
  
          .seal-col,
          .seal-col:empty {
              display: flex;
              vertical-align: baseline;
          }
  
          .sealsubs-container .sls-option-container label {
              display: inline;
              width: auto;
          }
  
          .sealsubs-container label.sls-selling-plan-group-name,
          .sealsubs-container .sls-option-container label,
          .sealsubs-container label.sls-purchase-options-label {
              color: rgb(77, 77, 77);
              color: #4d4d4d;
          }
  
          .sealsubs-container label {
              vertical-align: middle;
              font-size: 1em;
              margin: 0;
              padding: 0;
              text-transform: none;
              cursor: pointer;
              text-align: left;
              letter-spacing: initial;
              line-height: 1.6;
              float: none !important;
              width: auto !important;
          }
  
          .sealsubs-container .sls-option-container {
              padding: 10px;
              border-radius: 2px;
              cursor: pointer;
              border: 1px solid rgba(255, 255, 255, 0);
              align-items: center;
          }
  
          .seal-table {
              display: table;
              width: 100%;
              box-sizing: border-box;
          }
  
          .seal-row {
              display: flex;
              justify-content: center;
              align-items: center;
          }
  
          .sealsubs-target-element .sls-option[type="radio"] {
              opacity: 0;
              width: 0;
              height: 0;
              float: left;
              position: absolute !important;
          }
  
          .sealsubs-container input[type="radio"] {
              height: auto;
              min-height: unset;
              width: auto;
              margin: 0 0.5em 0 0;
              margin: 0 0 0 0;
              vertical-align: middle;
              -webkit-appearance: radio;
              -moz-appearance: radio;
              display: inline-block;
              top: unset;
              right: unset;
              position: relative !important;
          }
  
          .seal-col:nth-child(2n) {
              width: 100%;
          }
  
          .seal-col,
          .seal-col:empty {
              display: flex;
              vertical-align: baseline;
          }
  
          .sealsubs-container .sls-option-container label {
              display: inline;
              width: auto;
          }
  
          .sealsubs-container label.sls-selling-plan-group-name,
          .sealsubs-container .sls-option-container label,
          .sealsubs-container label.sls-purchase-options-label {
              color: rgb(77, 77, 77);
              color: #4d4d4d;
          }
  
          .sealsubs-container label {
              vertical-align: middle;
              font-size: 1em;
              margin: 0;
              padding: 0;
              text-transform: none;
              cursor: pointer;
              text-align: left;
              letter-spacing: initial;
              line-height: 1.6;
              float: none !important;
              width: auto !important;
          }
  
          /* .sealsubs-target-element .sls-option[type="radio"]:checked + .sls-custom-radio:after {
      transform: scale(1);
  }
  
  .sealsubs-target-element .sls-option[type="radio"] + .sls-custom-radio:after {
      width: 10px;
      height: 10px;
      transform: scale(0);
      transition: 150ms transform ease-in-out;
  }
  .sealsubs-target-element .sls-option[type="radio"]:checked + .sls-custom-radio:after {
      width: 10px;
      height: 10px;
  } */
          .sealsubs-target-element .sls-option[type="radio"]+.sls-custom-radio:after {
              display: block;
              content: "";
              width: 0px;
              height: 0px;
              box-shadow: inset 1em 1em #4d4d4d;
              box-shadow: inset 1em 1em #4d4d4d;
              border-radius: 50%;
              transition: 150ms width ease-in-out, 150ms height ease-in-out;
              border: none;
              background: none;
              position: relative;
              margin: 0;
          }
  
          .sealsubs-container .sls-option-container.sls-active {
              border: 1px solid rgba(198, 198, 198, 0.55);
              border: 1px solid rgba(198, 198, 198, 0.55);
          }
  
          .sealsubs-container .sls-option-container {
              padding: 10px;
              border-radius: 2px;
              cursor: pointer;
              border: 1px solid rgba(255, 255, 255, 0);
              align-items: center;
          }
  
          .seal-table {
              display: table;
              width: 100%;
              box-sizing: border-box;
          }
  
          .seal-table.sls-active .sls-custom-radio:after {
              width: 10px !important;
              height: 10px !important;
          }
  .sealsubs-container input[type="radio"]:focus, .sls-description-button:focus {
      outline: 1px dotted rgb(134, 134, 134);
      outline-offset: 1px;
  }
  .sls-description-button {
      margin-top: 10px;
      font-weight: 600;
      width: auto;
      display: inline-block;
      cursor: pointer;
      padding: 5px 5px 5px 0;
  }
  .sls-description-container.seal-col {
      display: block;
  }
  .sls-description-content {
      display: none;
  }
  .sls-label-container.seal-col {
    display: flex;
    justify-content: flex-start;
    align-items: center;
}
span.choose__interval__days {
    margin-top: 15px;
    display: block;
    font-size: 20px;
    font-weight: 900;
    color: deeppink;
}
      </style>
  </head>
  
  <body>
      <div id="shopify-block-20acde69-ef8a-44cd-93c2-5ffc493726e5" class="shopify-block shopify-app-block"
          data-block-handle="subscription-widget">
          <div class="sealsubs-target-element sealsubs-full" data-seal-extension="" data-product-id="8401481072922"
              data-handle="immediate-effects-2" data-product="" data-seal-key="zhf8u" data-seal-in="">
              <div class="sealsubs-container">
                  <div class="sls-option-container One_time_purchase seal-table ">
                      <div class="seal-row">
                          <div class="seal-col seal-col-radio"><input type="radio" tabindex="0" class="sls-option"
                                  name="subs_type_zhf8u" value="one_time"><span class="sls-custom-radio"></span></div>
                          <div class="sls-label-container seal-col"><label>One-time purchase</label></div>
                      </div>
                  </div>
                  <div class="sls-option-container subscribe_30days seal-table sls-active">
                      <div class="seal-row">
                          <div class="seal-col seal-col-radio">
                               <input type="radio" tabindex="0" class="sls-option"id="sls_option"name="subs_type_zhf8u" value="subscription">
                              <span class="sls-custom-radio"></span></div>
                                <div class="sls-label-container  seal-col"><label>Subscribe and deliver every&nbsp;</label>
                              <div class="sls-select-container">
                              <span class="number_0f_days"></span>
                              <select id="intervalSelect" class="check" fdprocessedid="0yzs69">
                             </select>
                              </div>
                          </div>
                      </div>
                      <div class="sls-description seal-row">
                          <div class="seal-col"></div>
                          <div class="sls-description-container seal-col">
                              <div class="sls-description-button" tabindex="0">See details</div>
                              <div class="sls-description-content">You will receive a payment link and won't be charged
                                  automatically.</div>
                          </div>
                      </div>
                  <span class="choose__interval__days"></span>
                  </div>
              </div>
          </div>
  
      </div>
  </body>  
  </html>`;

let div1 = document.querySelector(".product__description_data");    
insertAfter(div1, elem1);

$(document).ready(function () {
  setInterval(function () {
    var interval_days_value = $("select#intervalSelect").val();
    $(".choose__interval__days").html(`This text for ${interval_days_value}`);
    $(".number_0f_days").html(interval_days_value);
    $("input.sls-hidden.sls-extension-added-attribute").attr("value",interval_days_value);
  }, 1000);
  $("#sls_option").attr("checked", true);

  $(".One_time_purchase").click(function () {
    $(".sls-option").attr("checked", false);
    $(".choose__interval__days").hide();
    $(this).addClass("sls-active");
    $(this).find(".sls-option").attr("checked", true);
    $(".subscribe_30days").removeClass("sls-active");
    $(".sls-extension-added-attribute").attr("name", "");
    $(".sls-extension-added-attribute").attr("value", "");
  });

  $(".subscribe_30days").click(function () {
    var select_value = $(".check").val();
    $(".choose__interval__days").show();
    console.log("select_valuenadjkahhgdhagd:", select_value);
    $(".sls-option").attr("checked", false);
    $(this).addClass("sls-active");
    $(this).find(".sls-option").attr("checked", true);
    $(".One_time_purchase").removeClass("sls-active");
    $(".sls-extension-added-attribute").attr(
      "name",
      "properties[Subscription interval]"
    );
    $(".sls-extension-added-attribute").attr("value", select_value);
    $(".number_0f_days").html(select_value);
    $(".choose__interval__days").html(`This text for ${select_value}`);
  });
  $(".sls-description-button").click(function () {
    $(".sls-description-content").toggle("active");
  });
});
