
if (window.location.pathname === '/pages/portalsubscription') {
  const fetchData = async () => {

    try {
      const response = await fetch('https://auto-shipped.onrender.com/subscriptionPortal/order');
      const data = await response.json();

      const MainContent = document.querySelector('#MainContent');
      MainContent.innerHTML = ''; // Clear existing table rows

      data.forEach((entry) => {
        MainContent.innerHTML = `
 
      <!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>customer portal</title>
    <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
    <style>
        .seal-mb-1 {
            margin-bottom: 1em !important;
        }

        .seal-mb-075 {
            margin-bottom: 0.75em;
        }

        .seal-mr-05 {
            margin-right: .5em;
        }

        .seal-ml-05 {
            margin-left: .5em;
        }

        .seal-mb-05 {
            margin-bottom: .5em;
        }

        .seal-mr-02 {
            margin-right: .2em;
        }

        .seal-mr-1 {
            margin-right: 1em;
        }

        .seal-pr-1 {
            padding-right: 1em;
        }

        /*
	* The desired layout structure is:
	* - parent div
	* 	- .seal-layour
	* 		- .seal-full || .seal-twoThirds || .seal-oneThird || .seal-oneQuarter, etc.
	*/

        .seal-subscription-page {
            max-width: 1090px;
            margin: 0 auto;
            font-size: 16px;
            line-height: 1.6;
            color: rgb(33, 43, 54);
            color: rgb(66, 75, 85);
            color: #424b55;
            display: flex;
            padding-top: 1em;
            flex-wrap: wrap;
            clear: both;
            text-align: left;
        }

        .seal-subscription-page a {
            color: rgb(66, 75, 85);
            color: #424b55;
        }

        .seal-layout {
            margin: -1em -1em 0 -1em;
            display: flex;
            flex-direction: row;
            flex: 1 1 100%;
            padding-right: 1em;
            position: relative;
        }

        @media screen and (max-width: 768px) {
            .seal-layout {
                flex-wrap: wrap;
            }

            .seal-dynamic-sectioned {
                padding: 1em;
            }
        }

        .seal-full {
            flex: 1 1 99em;
            flex: 1 1 calc(100% - 1em);
            margin: 1em 0 0 1em;
        }

        .seal-twoThirds {
            flex: 1 1 calc(66% - 1em);
            margin: 1em 0 0 1em;
        }

        .seal-oneThird {
            flex: 1 1 calc(33% - 1em);
            margin: 1em 0 0 1em;
        }

        .seal-oneQuarter {
            flex: 1 1 25em;
            margin: 1em 0 0 1em;
        }

        .seal-oneHalf {
            flex: 1 1 32em;
            /*flex:1 1 calc(50% - 1em);*/
            margin: 1em 0 0 1em;
        }

        .seal-half {
            flex: 1 1 32em;
            flex: 1 1 calc(50% - 1em);
            margin: 1em 0 0 1em;
        }

        .seal-auto {
            flex: 1 1 auto;
            margin: 1em 0 0 1em;
        }

        .seal-auto-min {
            flex: 0 1 auto;
            margin: 1em 0 0 1em;
        }

        .seal-container {
            box-shadow: 0 0 0 1px rgba(63, 63, 68, 0.05), 0 1px 3px 0 rgba(63, 63, 68, 0.15);
            background: white;
            background: #FFFFFF;
            margin-bottom: 1em;
            position: relative;
        }

        .active [data-show-on-edit] {
            display: block;
        }

        .active [data-hide-on-edit] {
            display: none;
        }

        .seal-sectioned {
            padding: 1em;
        }

        .seal-container-subdued {
            margin-bottom: 0;
        }

        .seal-justify {
            justify-content: center;
        }

        .seal-flex-column {
            display: flex;
            flex-direction: column;
        }

        .seal-flex-align-end {
            display: flex;
            align-items: flex-end;
        }

        .seal-subscription-page h1 {
            font-size: 2em;
            margin: 0 0 1em 0;
            color: rgb(66, 75, 85);
            color: #424b55;
            text-align: left;
            border-bottom: none;
            padding: 0;
            line-height: 1.4;
        }

        .seal-subscription-page h2 {
            font-size: 1.5em;
            margin: 0 0 0.5em 0;
            text-transform: none;
            color: rgb(66, 75, 85);
            color: #424b55;
            text-align: left;
            line-height: 1.4;
            padding: 0;
        }

        .seal-subscription-page h3 {
            font-size: 1.1em;
            margin: 0 0 0.5em 0;
            text-transform: none;
            font-weight: 700;
            color: rgb(66, 75, 85);
            color: #424b55;
            text-align: left;
            padding: 0;
        }

        .seal-subscription-page .seal-container.seal-sectioned[data-editable-container] h3 {
            max-width: 80%;
        }

        .seal-subscription-page ul,
        .seal-subscription-page li {
            list-style-type: none;
            margin: 0;
            padding: 0;
            font-size: inherit;
        }

        .seal-subscription-page li {
            padding: 1em 0;
            border-bottom: 1px solid rgba(63, 63, 68, 0.08);
        }

        .seal-subscription-page li:last-of-type {
            border-bottom: none;
        }

        .seal-flex {
            display: flex;
        }

        .seal-tal {
            text-align: left;
        }

        .seal-tac {
            text-align: center;
        }

        .seal-tar {
            text-align: right;
        }

        .seal-flex-right {
            align-items: center;
            display: flex;
            justify-content: flex-end;
        }

        .seal-flex-vertical-right {
            align-items: flex-end;
            display: flex;
            justify-content: flex-end;
            flex-direction: column;
        }

        .seal-flex-center-vertical {
            align-self: center;
        }

        .seal-flex-space-between {
            display: flex;
            flex-direction: row;
            justify-content: space-between;
        }

        .seal-flex-wrap {
            flex-wrap: wrap;
        }


        .seal-flex-right a,
        .seal-flex-right span {
            display: flex;
        }

        .seal-subdued,
        a.seal-subdued {
            color: rgb(153, 153, 153);
            color: #999999;
        }

        .seal-small {
            font-size: 0.75em;
        }

        .seal-medium {
            font-size: 0.9em;
        }

        .seal-t-strong,
        .seal-strong {
            font-weight: 700;
        }

        .seal-line-through {
            text-decoration: line-through;
        }

        .seal-t-underline {
            text-decoration: underline;
        }

        .seal-italic {
            font-style: italic;
        }

        .seal-pointer {
            cursor: pointer;
        }

        .seal-success {
            color: #108043;
        }

        .seal-warning {
            color: RGB(244, 147, 66);
        }

        .seal-button {
            text-decoration: none;
            display: inline-block;
            border-radius: 4px;
            color: rgb(255, 255, 255);
            color: #FFFFFF;
            padding: 20.0px 25.0px;
            background: #1990C6;
            background: #1990C6;
            cursor: pointer;
            margin: 0 1em 1em 0;
        }

        .seal-button-small {
            padding: 0.2em 0.5em;
            margin: 0.2em;
            border-radius: 2px;
        }

        .seal-button-plain {
            background: none;
            color: #1990C6;
            color: #1990C6;
            text-shadow: 1px 1px rgba(128, 128, 128, 0.08);
            /* Added shadow so that if merchants set white text on white background they can see it there. */
        }

        .seal-button-plain-red {
            background: none;
            text-shadow: 1px 1px rgba(128, 128, 128, 0.08);
            color: #DE3618;
            color: #DE3618;
        }

        .seal-button-red,
        #seal-unsubscribe-button {
            background: #DE3618;
            background: #DE3618;
            color: rgb(255, 255, 255);
            color: #FFFFFF;
        }

        .seal-button-next-to-input {
            padding: 0.725em;
            width: 100%;
            margin: 0.25em 0;
            font-size: 1em;
            line-height: 1.6;
            text-align: center;
            border: 1px solid #1990C6;
            border: 1px solid #1990C6;
        }

        .seal-notification-success {
            background: #1990C6;
            color: rgb(255, 255, 255);
        }

        .seal-notification-error {
            background: #DE3618;
            color: rgb(255, 255, 255);
        }

        .seal-notification-success-plain {
            color: #1990C6;
        }

        .seal-notification-error-plain {
            color: #DE3618;
        }

        #seal-reactivate-button {
            color: rgb(255, 255, 255);
            color: #FFFFFF;
            background: #1990C6;
            background: #1990C6;
        }


        #seal-pause-button {
            background: rgb(236, 142, 63);
            background: #ec8e3f;
            color: rgb(255, 255, 255);
            color: #FFFFFF;
        }

        #seal-resume-button {
            color: rgb(255, 255, 255);
            color: #FFFFFF;
            background: #1990C6;
            background: #1990C6;
        }


        /* Confirmation overlay */
        #seal-confirmation-overlay {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            bottom: 0;
            right: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.2);
            z-index: 9999999;
            font-size: 16px;
        }

        #seal-confirmation-overlay .question {
            font-size: 1.2em;
            margin-bottom: .5em;
        }

        #seal-confirmation-overlay .description {
            font-size: 0.9em;
            margin-bottom: 1em;
        }

        #seal-confirmation-box {
            background: white;
            background: #FFFFFF;
            color: #424b55;
            border-radius: 4px;
            box-shadow: 0 0 0 1px rgba(63, 63, 68, 0.05), 0 1px 3px 0 rgba(63, 63, 68, 0.15);
            position: absolute;
            top: 50%;
            left: 50%;
            padding: 1em 1em 0 1em;
            transform: translate(-50%, -50%);
        }

        @media screen and (max-width: 768px) {
            #seal-confirmation-box {
                width: 90%;
            }
        }

        /* Cancellation flow overlay */
        #seal-cancellation-flow-overlay {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            bottom: 0;
            right: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.2);
            z-index: 9999999;
            font-size: 16px;
        }

        #seal-cancellation-flow-overlay .question {
            font-size: 1.2em;
            margin-bottom: .5em;
        }

        #seal-cancellation-flow-overlay .description {
            font-size: 0.9em;
            margin-bottom: 1em;
        }

        #seal-cancellation-flow-box {
            max-width: 1000px;
            width: 90%;
            background: white;
            background: #FFFFFF;
            color: #424b55;
            border-radius: 4px;
            box-shadow: 0 0 0 1px rgba(63, 63, 68, 0.05), 0 1px 3px 0 rgba(63, 63, 68, 0.15);
            position: absolute;
            top: 50%;
            left: 50%;
            padding: 1em 1em 0 1em;
            transform: translate(-50%, -50%);
            overflow: auto;
            max-height: 99%;
        }

        .seal-cancellation-reason-description {
            background: #ffffdd;
            padding: 0.5em;
        }

        .cancellation-reason-label {
            font-weight: bold;
        }

        @media screen and (max-width: 768px) {
            #seal-cancellation-flow-box {
                width: 90%;
            }
        }

        /* Alert box overlay */
        #seal-alert-overlay {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            bottom: 0;
            right: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.2);
            z-index: 9999999;
            font-size: 16px;
            text-align: center;
        }

        #seal-alert-overlay .title {
            font-size: 1.2em;
            margin-bottom: .5em;
            margin-top: 0;
            margin-bottom: 0.5em;
        }

        #seal-alert-overlay .message {
            font-size: 1em;
            margin-bottom: 1em;
        }

        #seal-alert-box {
            background: white;
            background: #FFFFFF;
            color: #424b55;
            border-radius: 4px;
            box-shadow: 0 0 0 1px rgba(63, 63, 68, 0.05), 0 1px 3px 0 rgba(63, 63, 68, 0.15);
            position: absolute;
            top: 50%;
            left: 50%;
            padding: 1em 1em 0 1em;
            transform: translate(-50%, -50%);
        }

        @media screen and (max-width: 768px) {
            #seal-alert-box {
                width: 90%;
            }
        }

        /* Editable modal */
        #seal-editable-modal-overlay,
        .seal-modal-overlay {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            bottom: 0;
            right: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.2);
            z-index: 9999999;
            font-size: 16px;
            text-align: center;
        }

        #seal-editable-modal,
        .seal-modal {
            background: white;
            border-radius: 4px;
            box-shadow: 0 0 0 1px rgba(63, 63, 68, 0.05), 0 1px 3px 0 rgba(63, 63, 68, 0.15);
            position: absolute;
            top: 50%;
            left: 50%;
            padding: 1em 1em 0 1em;
            transform: translate(-50%, -50%);
            max-width: 100%;
            max-height: 90%;
            overflow-y: auto;
            color: rgb(11, 21, 43);
            z-index: 9999999999999;
        }

        .close_model {
            position: fixed;
            top: 0;
            left: 0;
            bottom: 0;
            right: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.2);
            z-index: 9999999;
            font-size: 16px;
            text-align: center;
        }

        .seal-container.seal-sectioned.seal-customer-portal-shipping-card.active #seal-editable-modal-overlay {
            display: block;
        }

        .seal-modal h3 {
            color: rgb(11, 21, 43);
        }

        @media screen and (max-width: 768px) {

            #seal-editable-modal,
            .seal-modal {
                width: 90%;
            }
        }

        @media screen and (max-width: 375px) {

            #seal-editable-modal,
            .seal-modal {
                width: 100%;
            }
        }


        .seal-loading {
            color: rgba(0, 0, 0, 0) !important;
            position: relative;
            min-height: 1em;
        }

        .seal-loading::after {
            content: "";
            display: block;
            border-radius: 50%;
            border: 2px solid #fff;
            border-top: 2px solid transparent;
            animation: seal-spin 500ms infinite linear;
            height: 1em;
            width: 1em;
            position: absolute;
            left: 50%;
            top: 50%;
        }

        .seal-tar.seal-loading::after {
            left: unset;
            right: 0%;
        }

        .seal-button-plain.seal-loading::after {
            border: 2px solid #1990C6;
            border: 2px solid #1990C6;
            border-top: 2px solid transparent;
        }

        .seal-loading-gray::after {
            border: 2px solid #cdcdcd;
            border-top: 2px solid transparent;
        }

        .seal-loading-large {
            height: 2em;
        }

        .seal-loading-large::after {
            height: 2em;
            width: 2em;
        }

        @keyframes seal-spin {
            from {
                transform: translate(-50%, -50%) rotate(0deg);
            }

            to {
                transform: translate(-50%, -50%) rotate(360deg);
            }
        }

        .seal-red {
            color: #DE3618;
        }

        .seal-orange {
            color: RGB(244, 147, 66);
        }

        .seal-blue {
            color: #1990C6;
            color: #00848E;
        }

        span.seal-sm-hide {
            display: inline;
        }

        span.seal-sm-display {
            display: none;
        }

        @media screen and (max-width: 768px) {
            .seal-sm-tal {
                text-align: left;
            }
        }

        @media screen and (max-width: 768px) {
            .seal-subscription-page h1 {
                font-size: 2em;
                margin: 0 0 0 0;
            }

            /*
		.seal-tar {
			text-align:left;
		}*/

            /*
		.seal-tac {
			text-align:left;
		}
		*/
            /*
		.seal-flex-right {
			justify-content: start;
		}
		*/
            .seal-flex-sm-left {
                justify-content: start;
            }

            .seal-oneQuarter {
                margin-top: 0.5em;
            }

            .seal-layout {
                margin-bottom: 1em;
            }

            .seal-sm-mt-1 {
                margin-top: 1em;
            }

            span.seal-sm-hide {
                display: none;
            }

            span.seal-sm-display {
                display: inline;
            }
        }

        @media screen and (max-width: 375px) {
            .seal-xs-full {
                flex: 1 1 calc(100% - 1em);
            }
        }


        .seal-separator {
            border-bottom: 1px solid rgba(153, 153, 153, 0.5);
        }

        .seal-separator-top:not(:first-of-type) {
            border-top: 1px solid rgba(63, 63, 68, 0.1);
            margin-top: 1em;
        }

        .seal-separator-top-medium {
            border-top: 1px solid rgba(63, 63, 68, 0.1);
            margin-top: 0.5em;
            padding-top: 0.5em;
        }

        [data-editable-container] {
            position: relative;
        }

        [data-show-on-edit],
        [data-show-on-edit-flex] {
            display: none;
        }

        [data-edit-modal-content] {
            display: none;
        }

        // [data-seal-country-dependent] {
        //     display: none;
        // }

        .seal-editing [data-show-on-edit] {
            display: inline-block;
        }

        .seal-editing [data-show-on-edit-flex] {
            display: flex;
        }

        .seal-editing [data-hide-on-edit] {
            display: none;
        }

        [data-seal-items-count="0"] [data-remove-item],
        [data-seal-items-count="1"] [data-remove-item] {
            display: none;
        }

        .seal-input,
        input.seal-input[type="text"],
        input.seal-input[type="number"] {
            -webkit-appearance: none;
            -moz-appearance: none;
            appearance: none;

            width: auto;
            color: inherit;
            background: inherit;
            padding: 0.5em;
            border: 1px solid rgb(144, 144, 144);
            border: 1px solid rgb(217, 217, 217);
            font-size: inherit;
            margin: 0;
            border-radius: 3px;
            line-height: 1.6;
            box-shadow: none;
            box-sizing: border-box;
            height: auto;
        }

        .seal-input:focus {
            border-color: rgb(118, 118, 118);
        }

        textarea.seal-input {
            width: 100%;
        }

        .seal-label {
            margin: 0.25em 0;
        }

        .seal-input-form,
        input.seal-input-form[type="text"],
        input.seal-input-form[type="number"] {
            margin: 0.25em 0;
        }

        .seal-input-small,
        input.seal-input-small[type="text"],
        input.seal-input-small[type="number"] {
            width: 4em;
            height: auto !important;
        }

        .seal-edit-buttons-wrapper {
            position: absolute;
            top: 0;
            right: 0;
        }

        .seal-edit-button[data-action="cancel"] {
            margin-right: -0.2em;
        }

        .seal-edit-mode-by-default .seal-edit-button[data-action="cancel"] {
            display: none;
        }

        .sls-select,
        select.sls-select {
            margin-top: 10px;
            font-family: inherit;
            font-weight: inherit;
            font-style: inherit;
            -webkit-font-smoothing: antialiased;
            -webkit-text-size-adjust: 100%;
            border-radius: 2px;
            max-width: 100%;
            font-size: 1em;
            padding: .445em 10px;
            line-height: 1.6;
            border: 1px solid #E3E3E3 !important;
            border: 1px solid rgb(217, 217, 217) !important;
            display: inline-block;
            margin: 0;
            -webkit-appearance: none;
            -moz-appearance: none;
            appearance: none;
            background-image: url(https://cdn-app.sealsubscriptions.com/shopify/public/img/app/dwn.svg);
            background-repeat: no-repeat;
            background-position: right 10px center;
            background-color: #FFFFFF;
            padding-right: 28px;
            text-indent: 0.01px;
            text-overflow: "";
            cursor: pointer;
            background-size: auto;
            min-height: unset !important;
            height: auto;
            color: rgb(77, 77, 77);
            font-size: inherit;
            width: auto;
        }

        .sls-select.seal-tight {
            padding: 0.2em 8px;
            padding-right: 28px;
        }

        select.sls-select::-ms-expand {
            display: none;
        }

        @media screen and (max-width: 554px) {
            .sls-select {
                font-size: 1em;
                font-size: 16px;
            }
        }

        /** Floating label CSS **/
        .seal-floating-label {
            position: relative;
        }

        .seal-floating-label .seal-input,
        .seal-floating-label input.seal-input[type="text"],
        .seal-floating-label input.seal-input[type="number"] {
            font-size: 1em;
            padding: 1.2em 0 0.25em 0.5em;
            width: 100%;
        }

        .seal-floating-label select.seal-input {
            max-width: 100% !important;
        }

        .seal-floating-label label {
            position: absolute;
            transition: all .3s ease;
            font-size: 0.95em !important;
            top: 0.25em;
            left: 0.5em;
            pointer-events: none;
            margin: 0;
            padding: 0;
            color: rgb(115, 115, 115);
            font-weight: normal !important;
            line-height: 1.6;
            text-transform: none;
            letter-spacing: inherit !important;
            text-transform: inherit !important;
            width: auto;
        }

        /** End of floating label CSS **/

        .seal-button-back,
        .seal-button-back:hover {
            margin: 0.5em 0.5em 0.5em 0;
            background: #1990C6 !important;
            background: #1990C6 !important;
            color: #FFFFFF !important;
            color: #FFFFFF !important;
        }

        @media screen and (max-width: 1090px) {

            .seal-button-back,
            .seal-button-back:hover {
                margin: 0.5em;
            }
        }

        .seal-subscription-page .card-icon {
            border-radius: 3px;
            height: 2.4em;
            width: 3.8em;
            border: .1rem solid rgb(223, 227, 232);
            background-size: cover;
            background-repeat: no-repeat;
            background-position: center center;
        }

        .seal-subscription-page div.card-icon:empty {
            display: block;
        }

        .seal-subscription-page .card-visa {
            background-image: url(https://cdn-app.sealsubscriptions.com/shopify/public/proxy/img/cards/visa.svg);
        }

        .seal-subscription-page .card-mastercard {
            background-image: url(https://cdn-app.sealsubscriptions.com/shopify/public/proxy/img/cards/mastercard.svg);
        }

        .seal-subscription-page .card-amex {
            background-image: url(https://cdn-app.sealsubscriptions.com/shopify/public/proxy/img/cards/american-express.svg);
        }

        .seal-subscription-page .card-jcb {
            background-image: url(https://cdn-app.sealsubscriptions.com/shopify/public/proxy/img/cards/jcb.svg);
        }

        .seal-subscription-page .card-discover {
            background-image: url(https://cdn-app.sealsubscriptions.com/shopify/public/proxy/img/cards/discover.svg);
        }

        .seal-subscription-page .card-diners-club {
            background-image: url(https://cdn-app.sealsubscriptions.com/shopify/public/proxy/img/cards/diners-club.svg);
        }

        .seal-subscription-page .seal-paypal {
            background-image: url(https://cdn-app.sealsubscriptions.com/shopify/public/proxy/img/paypal-v2.svg);
        }

        .seal-subscription-page .seal-card-shoppay {
            background-image: url(https://cdn-app.sealsubscriptions.com/shopify/public/proxy/img/cards/shoppay.svg);
        }


        div.seal-loading:empty {
            display: block;
        }

        /*
	.seal-x-button {
		position:absolute;
		width:1em;
		height:1em;
		top:-.75em;
		right:-.75em;
		background: transparent;
		border-radius: 50%;
		cursor:pointer;
	}
	
	.seal-x-button:before, .seal-x-button:after {
		position: absolute;
		left: 0;
		content: "";
		height: 100%;
		top: 0;
		width: 2px;
		background-color: rgb(66, 75, 85);
	}
	.seal-x-button:before {
		transform: rotate(45deg);
	}
	.seal-x-button:after {
		transform: rotate(-45deg);
	}
	*/

        .seal-add-item-content {
            /*max-width:90vw;*/
            width: auto;
            max-height: 90vh;
        }

        @media screen and (min-width: 560px) {
            #seal-add-item-modal {
                /*min-width:calc(500px + 1em + 1px);*/
                min-width: 500px;
            }

            .seal-add-item-content {
                /*min-width:500px;*/
            }
        }

        #seal-add-item-products-list {
            position: relative;
            min-height: 4em;
        }

        #seal-add-item-content .seal-loading {
            opacity: 0;
            position: absolute;
            left: 50%;
            top: 50%;
            transform: translateX(-50%) translateY(-50%);
        }

        #seal-add-item-content.seal-loading-active .seal-loading {
            opacity: 1;
        }

        #seal-add-item-content.seal-loading-active #seal-add-item-inner-products-list {
            opacity: 0;
        }

        .seal-close::after {
            transform: rotate(-45deg);
        }

        .seal-close::before,
        .seal-close::after {
            position: absolute;
            left: calc(16px - 1px);
            content: "";
            height: 20px;
            top: 8px;
            width: 2px;
            background-color: rgb(111, 111, 111);
        }

        .seal-close::before {
            transform: rotate(45deg);
        }

        .seal-close {
            position: absolute;
            width: 32px;
            height: 32px;
            top: 0px;
            right: 0px;
            cursor: pointer;
            border: none;
            box-sizing: border-box;
            display: block;
        }

        .seal-close:empty {
            display: block;
        }


        .seal-pl-0 {
            padding-left: 0;
        }

        .seal-mr-0 {
            margin-right: 0;
        }

        .seal-ml-0 {
            margin-right: 0;
        }

        .seal-pr-0 {
            padding-right: 0;
        }


        .seal-mb-0 {
            margin-bottom: 0;
        }

        .seal-pb-0 {
            padding-bottom: 0;
        }

        .seal-mt-15 {
            margin-top: 1.5em;
        }

        .seal-portal-hide {
            display: none;
        }

        .seal-flex-grow-2 {
            flex-grow: 2;
        }

        #seal-subscription-loyalty-discounts-list-container {
            background: rgb(254, 216, 63);
            background: rgb(254, 216, 63);
            border: 4px solid rgba(255, 255, 255, 0.4);
            color: rgb(66, 75, 85);
            color: rgb(66, 75, 85);
        }

        #seal-subscription-loyalty-discounts-list-container h3 {
            color: rgb(66, 75, 85);
            color: rgb(66, 75, 85);
        }

        .seal-loyalty-discount-savings-badge {
            background-color: rgb(254, 216, 63);
            background-color: rgb(254, 216, 63);
            background-color: rgb(254, 216, 63);
            color: rgb(0, 0, 0);
            color: rgb(0, 0, 0);
            color: rgb(0, 0, 0);
            width: auto;
            border-radius: 2px;
            border-top-right-radius: 3px;
            border-bottom-right-radius: 3px;
            text-transform: uppercase;
            font-size: 0.75em;
            letter-spacing: 1px;
            line-height: 2;
            padding: 0em 0.5em 0em 0.5em;
            margin-left: 1em;
            position: relative;
            display: inline-block;
            transform: rotate(5deg) translate(0, 2px);
            box-shadow: 1px 1px 1px 0px rgba(0, 0, 0, 0.4);
        }

        .seal-loyalty-discount-savings-badge::before {
            content: "";
            display: block;
            position: absolute;
            top: 0;
            height: 100%;
            width: 2em;
            left: calc(-2em + 1px);
            background: conic-gradient(transparent 45deg, rgb(254, 216, 63) 45deg 135deg, transparent 125deg 360deg);
            background: conic-gradient(transparent 45deg, rgb(254, 216, 63) 45deg 135deg, transparent 125deg 360deg);
            background-repeat: repeat;
            background-size: auto;
            background-size: 100% 51%;
            background-size: 100% 100%;
            background-repeat: no-repeat;
        }

        #seal-subscription-loyalty-discounts-list .seal-loyalty-discount-savings-badge {
            background: rgb(253, 224, 108);
            background: rgb(255, 231, 134);
            background: rgb(255, 231, 134);
            color: rgb(0, 0, 0);
        }

        #seal-subscription-loyalty-discounts-list .seal-loyalty-discount-savings-badge::before {
            background: conic-gradient(transparent 45deg, rgb(255, 231, 134) 45deg 135deg, transparent 125deg 360deg);
            background: conic-gradient(transparent 45deg, rgb(255, 231, 134) 45deg 135deg, transparent 125deg 360deg);
        }

        .seal-discount-applied-checkmark-overlay {
            position: absolute;
            right: 0;
            top: 0;
            width: auto;
            height: 1.5em;
            display: block;
            background: white;
        }

        .seal-checkmark {
            width: auto;
            height: 1.5em;
            display: block;
            stroke-width: 3;
            stroke: rgb(70, 103, 167);
            stroke: RGB(70, 103, 167);
            margin: 0 auto;
        }

        /*----- CALENDAR ----*/

        #mc-btn__clear {
            display: none;
        }

        .mc-calendar--modal {
            font-size: 16px;
            letter-spacing: initial;
        }

        .mc-calendar--modal .mc-display__day {
            font-size: clamp(1em, 8vw, 1.25em);
        }

        .mc-calendar--modal .mc-picker__header {
            font-size: clamp(1em, 8vw, 1.25em);
        }

        .mc-calendar--modal .mc-select__data {
            font-size: 1em;
        }

        .mc-calendar--modal .mc-select__data--month,
        .mc-calendar--modal .mc-select__data--month span {
            min-width: 5em;
            max-width: 6.25em;
        }

        .mc-calendar--modal .mc-select__data--year,
        .mc-calendar--modal .mc-select__data--year span {
            min-width: 3em;
            max-width: 3.5em;
        }

        .mc-calendar--modal .mc-select__data {
            height: calc(8vw + .25em);
            min-height: 1.75em;
            max-height: 2em;
        }

        .mc-calendar--modal .mc-display__date {
            font-size: clamp(5em, 40vw, 7em);
        }

        .mc-calendar--modal .mc-display__month {
            font-size: clamp(1.2em, 9vw, 1.5em);
        }

        .mc-calendar--modal .mc-display__year {
            font-size: clamp(2.4em, 18vw, 3em);
        }

        .mc-calendar--modal .mc-display h1,
        .mc-calendar--modal .mc-display h2,
        .mc-calendar--modal .mc-display h3,
        .mc-calendar--modal .mc-display h4 {
            font-family: inherit;
            font-weight: normal;
            letter-spacing: initial;
        }


        .seal-variant-image {
            max-width: 64px;
            object-fir: cover;
            object-fit: cover;
            border-radius: 3px;
            margin-right: 0.8em;
            border: 1px solid gray;
            min-width: 64px;
            background: rgba(128, 128, 128, 0.11);
        }

        .seal-one-time-purchase-label {
            background: rgb(255, 255, 0);
            color: rgb(80, 89, 98);
            padding: 0.5em;
            margin-top: 0.5em;
            display: inline-block;
        }

        .seal-button-disabled {
            cursor: not-allowed;
            opacity: 0.5;
        }

        @media screen and (max-width: 768px) {
            .seal-billing-attempts .seal-layout {
                margin-bottom: 0;
            }
        }

        .mc-btn {
            width: auto;
            height: auto;
        }

        .mc-picker button {
            width: auto;
        }
    </style>
</head>

<body>
    <div class="seal-subscription-page" style={{ paddingRight: "1rem" }} data-subscription-status="ACTIVE"
        data-subscription-interval="30 day">


        <div class="seal-layout" style={{ paddingRight: "0em" }}>
            <div class="seal-twoThirds">

                <div id="seal-notifications-container"></div>

                <div class="seal-container seal-sectioned">
                    <div class="seal-layout seal-sub-title-container">
                        <div class="seal-twoThirds seal-sub-title">
                            <h1 data-seal-t="overview_title">Subscription</h1>
                        </div>
                        <div class="seal-oneThird seal-tar seal-subdued seal-sub-id">
                           ${entry.subscription_order_name}
                        </div>
                    </div>

                    <div data-editable-container="">
                        <div class="seal-sub-order-placed-text">
                            <span class="seal-t-strong" data-seal-t="overview_created_at_label">Created at:</span> <span
                                data-convert-time="" data-wg-notranslate=""> ${entry.create_order_date}</span>
                        </div>

                        <div>
                            <span class="seal-t-strong" data-seal-t="overview_status_label">Status:</span>

                            <span class="seal-blue seal-active-status-label"
                                data-seal-t="overview_status_active">${entry.Status}</span>
                        </div>



                        <div data-hide-on-edit="">
                            <span data-seal-t="overview_interval_label">Repeats every </span>
                            <span data-seal-t-key="interval" data-seal-t-value="30 day">${entry.subscription_interval_days}</span>.
                        </div>
                        <div data-show-on-edit="">
                            <span data-seal-t="overview_interval_label">Repeats every </span>
                            <select class="sls-select replaced" name="interval" id="sls_select_value">
                               
                            </select>
                        </div>





                        <div class="seal-edit-buttons-wrapper" style={{ right: "-1em" }}>
                            <div class="seal-edit-button seal-button seal-button-small seal-button-plain"
                                data-hide-on-edit="" data-action="edit" data-seal-t="overview_edit_button">Edit</div>
                            <div class="seal-edit-button seal-button seal-button-small seal-button-plain-red"
                                data-show-on-edit="" data-action="cancel" data-seal-t="overview_cancel_editing_button">
                                Cancel</div>
                            <div class="seal-edit-button seal-button seal-button-small" data-show-on-edit=""
                                data-action="save" data-seal-t="overview_save_button">Save</div>
                        </div>
                    </div>

                </div>



                <div id="seal-subscription-items-list-container" class="seal-container seal-sectioned "
                    data-editable-container="">
                    <h2 data-seal-t="overview_items_title">Items</h2>

                    <div id="seal-subscription-items-list" data-seal-items-count="1">

                        <div class="seal-layout seal-separator-top" data-item-id="2324908">
                            <div class="seal-twoThirds seal-flex-grow-2">
                                <span class="seal-t-strong">
                                    <span class="seal-product-variant-name">${entry.subscription_product__title}</span> <span
                                        class="seal-x-icon">x </span>

                                    <span data-hide-on-edit="" class="seal-product-quantity">${entry.subscription_product_Quantity}</span>
                                    <span data-show-on-edit="">
                                        <input name="items[2324908][quantity]" class="seal-input seal-input-small"
                                            value="1" min="1" data-seal-quantity="" type="number">
                                    </span>
                                </span>

                            </div>
                            <div class="seal-oneThird seal-tar seal-sm-mt-1">

                                <div>
                                    <span data-seal-format-money="" data-locale="en" data-value="88.4"
                                        data-currency="USD">${entry.subscription_total_price}</span>
                                </div>


                                <div data-show-on-edit="" data-remove-item=""
                                    class="seal-strong seal-small seal-pointer seal-button-plain-red"
                                    style={{
                position: "absolute",
                right: "1em",
                bottom: "-1em",
              }}
                                    data-seal-t="overview_remove_product_button">Remove</div>
                            </div>
                        </div>
                    </div>


                    <div data-show-on-edit-flex="" class="seal-layout seal-separator-top">
                        <div class="seal-full seal-tac">
                            <div class="seal-button seal-button-small" data-seal-add-item=""
                                data-seal-t="overview_add_product_button">Add item</div>
                        </div>
                    </div>

                    <input name="deleted_items" style={{ display: "none" }} value="" autocomplete="off" type="hidden">

                    <div class="seal-edit-buttons-wrapper">
                        <div class="seal-edit-button seal-button seal-button-small seal-button-plain"
                            data-hide-on-edit="" data-action="edit" data-seal-t="overview_edit_button">Edit</div>
                        <div class="seal-edit-button seal-button seal-button-small seal-button-plain-red"
                            data-show-on-edit="" data-action="cancel" data-seal-t="overview_cancel_editing_button"
                            data-seal-cancel-editing-products="">Cancel</div>
                        <div class="seal-edit-button seal-button seal-button-small" data-show-on-edit=""
                            data-action="save" data-seal-t="overview_save_button">Save</div>
                    </div>
                </div>




                <div class="seal-container seal-sectioned">

                    <div class="seal-flex-space-between">
                        <h3 data-seal-t="overview_billing_schedule_title">Billing schedule</h3>

                        <div class="seal-place-order-now-button-wrapper seal-tac"
                            style={{ marginTop: "-0.5em", marginRight: "-0.5em" }}>
                            <div style={{ margin: 0, position: "relative", zIndex: 2 }}
                                class="seal-edit-button seal-button seal-button-small " title=""
                                data-action="create_charge_now" data-seal-t="overview_place_order_now_button">Place
                                 b now</div>
                        </div>
                    </div>

                    <div class="seal-layout">
                        <div class="seal-full seal-mt-15">
                            <ul class="seal-billing-attempts">


                                <li data-billing-attempt-status="" data-billing-attempt-skip="">
                                    <div class="seal-layout">
                                        <div class="seal-oneHalf">


                                            <span class="seal-sub-billing-num">#1</span>
                                            <div class="seal-edit-button seal-button seal-button-small seal-button-plain seal-mr-0 seal-pr-0 seal-mb-0 seal-pb-0 seal-tar seal-pl-0"
                                                data-action="reschedule" data-id="10037954"
                                                data-time="2023-10-21T10:00:00+00:00" data-type="billing_attempt">
                                                <span data-seal-t="overview_reschedule_button">Reschedule</span>
                                            </div>

                                            <div>
                                                <span class="seal-italic seal-subdued" data-convert-time=""
                                                    data-wg-notranslate="">${entry.Next_Shipment_Date}</span>



                                            </div>


                                        </div>
                                        <div
                                            class="seal-oneHalf seal-flex-vertical-right seal-italic seal-attempt-status-label seal-medium">

                                            <span class="seal-subdued"
                                                data-seal-t="overview_billing_schedule_scheduled_text">(scheduled)</span>



                                            <div class="seal-edit-button seal-button seal-button-small seal-button-plain seal-mr-0 seal-pr-0 seal-mb-0 seal-pb-0 seal-tar"
                                                data-action="skip" data-id="10037954">
                                                Skip payment </div>



                                        </div>
                                    </div>
                                </li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>

            <div class="seal-oneThird">
                <div class="seal-container seal-sectioned seal-container-subdued seal-sub-customer"
                    data-editable-container="">
                    <h3 data-seal-t="overview_customer_title">Customer</h3>

                    <div>
                        <span> ${entry.subscription_customer_name}</span>
                    </div>
                </div>

                <div class="seal-container seal-sectioned seal-container-subdued seal-sub-contact"
                    data-editable-container="">
                    <h3 data-seal-t="overview_contact_title">Contact</h3>

                    <div>
                        <div>
                            <span data-hide-on-edit="" id="email_value">${entry.subscription_customer_email}</span>
                        </div>
                        <span data-show-on-edit="">
                            <input name="email" class="seal-input" value="${entry.subscription_customer_email}" type="text">
                        </span>

                    </div>
                    <div class="seal-edit-buttons-wrapper">
                        <div class="seal-edit-button seal-button seal-button-small seal-button-plain"
                            data-hide-on-edit="" data-action="edit" data-seal-t="overview_edit_button">Edit</div>
                        <div class="seal-edit-button seal-button seal-button-small seal-button-plain-red"
                            data-show-on-edit="" data-action="cancel" data-seal-t="overview_cancel_editing_button">
                            Cancel</div>
                        <div class="seal-edit-button seal-button seal-button-small" data-show-on-edit=""
                            data-action="save" data-seal-t="overview_save_button">Save</div>
                    </div>
                </div>

                <div class="seal-container seal-sectioned seal-customer-portal-shipping-card"
                    data-editable-container="">
                    <h3 data-seal-t="overview_shipping_address_title">Shipping</h3>
                    <div class="seal-customer-portal-shipping-card_info" shipping-info>
                         <div>
                         ${entry.subscriptionshipping_address_first_name} ${entry.subscriptionshipping_shippingAddress_last_name}
                            </div>
                        <div>
                            ${entry.subscriptionshipping_shippingAddress_address1}</div>
                        <div>
                            ${entry.subscriptionshippingAddress_zip}</div>


                        <div>
                            ${entry.subscriptionshippingAddress_country} </div>
                    </div>
                    <div id="seal-editable-modal-overlay">
                        <div class="close_model"></div>
                        <div id="seal-editable-modal" class="seal-editing">
                            <div id="seal-editable-modal-content" style="margin-bottom:1em;">
                                <h3 data-seal-t="overview_shipping_address_title">Shipping</h3>
                                <div class="seal-layout">
                                    <div class="seal-oneHalf">
                                        <div class="seal-floating-label">
                                            <label for="addresses[shipping][first_name]" class="seal-label"
                                                data-seal-t="overviewaddress_first_name_label">First name</label>
                                            <input name="addresses[shipping][first_name]"
                                                class="seal-input seal-input-form" value="${entry.subscriptionshipping_address_first_name}" type="text">
                                        </div>
                                    </div>
                                    <div class="seal-oneHalf">
                                        <div class="seal-floating-label">
                                            <label for="addresses[shipping][last_name]" class="seal-label"
                                                data-seal-t="overviewaddress_last_name_label">Last name</label>
                                            <input name="addresses[shipping][last_name]"
                                                class="seal-input seal-input-form" value=" ${entry.subscriptionshipping_shippingAddress_last_name}" type="text">
                                        </div>
                                    </div>
                                </div>

                                <div class="seal-layout">
                                    <div class="seal-full">
                                        <div class="seal-floating-label">
                                            <label for="addresses[shipping][address1]" class="seal-label"
                                                data-seal-t="overviewaddress_address_label">Address</label>
                                            <input name="addresses[shipping][address1]"
                                                class="seal-input seal-input-form" value="${entry.subscriptionshipping_shippingAddress_address1}"
                                                type="text">
                                        </div>
                                    </div>
                                </div>

                                <div class="seal-layout">
                                    <div class="seal-full">
                                        <div class="seal-floating-label">
                                            <label for="addresses[shipping][address2]" class="seal-label"
                                                data-seal-t="overviewaddress_address_line_2_label">Apartment, suite,
                                                etc.</label>
                                            <input name="addresses[shipping][address2]"
                                                class="seal-input seal-input-form" value="${entry.subscriptionshipping_shippingAddress_address2}" type="text">
                                        </div>
                                    </div>
                                </div>

                                <div class="seal-layout">
                                    <div class="seal-oneHalf">
                                        <div class="seal-floating-label">
                                            <label for="addresses[shipping][zip]" class="seal-label"
                                                data-seal-t="overviewaddress_postal_code_label">Postal code</label>
                                            <input name="addresses[shipping][zip]" class="seal-input seal-input-form"
                                                value="${entry.subscriptionshippingAddress_zip}" type="text">
                                        </div>
                                    </div>
                                    <div class="seal-oneHalf">
                                        <div class="seal-floating-label">
                                            <label for="addresses[shipping][city]" class="seal-label"
                                                data-seal-t="overviewaddress_city_label">City</label>
                                            <input name="addresses[shipping][city]" class="seal-input seal-input-form"
                                                value="${entry.subscriptionshippingAddress_city}" type="text">
                                        </div>
                                    </div>
                                </div>


                                <div class="seal-layout">
                                    <div class="seal-oneHalf">
                                        <div class="seal-floating-label">
                                            <label for="addresses[shipping][country]" class="seal-label"
                                                data-seal-t="overviewaddress_country_label">Country/Region</label>

                                            <select name="addresses[shipping][country_code]"
                                                class="seal-input seal-input-form sls-select replaced"
                                                data-seal-country-selector="" data-default-value="US">
                                                <option value=""></option>
                                                <option value="United States" selected="">United States</option>
                                                <option value="Canada">Canada</option>
                                            </select>

                                            <input name="addresses[shipping][country]"
                                                class="seal-input seal-input-form" data-seal-country-input=""
                                                value="United States" type="hidden">


                                        </div>
                                    </div>

                                    <div class="seal-oneHalf" data-seal-hide-empty-province="">
                                        <div class="seal-floating-label">
                                            <label for="addresses[shipping][province]" class="seal-label"
                                                data-seal-t="overviewaddress_state_label">State/Province</label>


                                            <select name="addresses[shipping][province_code]"
                                                class="seal-input seal-input-form sls-select replaced"
                                                data-seal-province-selector="" data-default-value="VA">
                                                <option value=""></option>
                                                <option value="Alabama">Alabama</option>
                                                <option value="Alaska">Alaska</option>
                                                <option value="American Samoa">American Samoa</option>
                                                <option value="Arizona">Arizona</option>
                                                <option value="Arkansas">Arkansas</option>
                                                <option value="California">California</option>
                                                <option value="Colorado">Colorado</option>
                                                <option value="Connecticut">Connecticut</option>
                                                <option value="Delaware">Delaware</option>
                                                <option value="District of Columbia">District of Columbia</option>
                                                <option value="Federated States of Micronesia">Federated States of Micronesia</option>
                                                <option value="Florida">Florida</option>
                                                <option value="Georgia">Georgia</option>
                                                <option value="Guam">Guam</option>
                                                <option value="Hawaii">Hawaii</option>
                                                <option value="Idaho">Idaho</option>
                                                <option value="Illinois">Illinois</option>
                                                <option value="Indiana">Indiana</option>
                                                <option value="Iowa">Iowa</option>
                                                <option value="Kansas">Kansas</option>
                                                <option value="Kentucky">Kentucky</option>
                                                <option value="Louisiana">Louisiana</option>
                                                <option value="Maine">Maine</option>
                                                <option value="Marshall Islands">Marshall Islands</option>
                                                <option value="Maryland">Maryland</option>
                                                <option value="Massachusetts">Massachusetts</option>
                                                <option value="Michigan">Michigan</option>
                                                <option value="Minnesota">Minnesota</option>
                                                <option value="Mississippi">Mississippi</option>
                                                <option value="Missouri">Missouri</option>
                                                <option value="Montana">Montana</option>
                                                <option value="Nebraska">Nebraska</option>
                                                <option value="Nevada">Nevada</option>
                                                <option value="New Hampshire">New Hampshire</option>
                                                <option value="New Jersey">New Jersey</option>
                                                <option value="New Mexico">New Mexico</option>
                                                <option value="New York">New York</option>
                                                <option value="NC">North Carolina</option>
                                                <option value="ND">North Dakota</option>
                                                <option value="North Carolina">Northern Mariana Islands</option>
                                                <option value="Ohio">Ohio</option>
                                                <option value="Oklahoma">Oklahoma</option>
                                                <option value="Oregon">Oregon</option>
                                                <option value="Palau">Palau</option>
                                                <option value="Pennsylvania">Pennsylvania</option>
                                                <option value="Puerto Rico">Puerto Rico</option>
                                                <option value="Rhode Island">Rhode Island</option>
                                                <option value="South Carolina">South Carolina</option>
                                                <option value="South Dakota">South Dakota</option>
                                                <option value="Tennessee">Tennessee</option>
                                                <option value="Texas">Texas</option>
                                                <option value="Utah">Utah</option>
                                                <option value="Vermont">Vermont</option>
                                                <option value="Virgin Islands">Virgin Islands</option>
                                                <option value="Virginia" selected="">Virginia</option>
                                                <option value="Washington">Washington</option>
                                                <option value="West Virginia">West Virginia</option>
                                                <option value="Wisconsin">Wisconsin</option>
                                                <option value="Wyoming">Wyoming</option>
                                                <option value="Armed Forces Americas">Armed Forces Americas</option>
                                                <option value="Armed Forces Europe">Armed Forces Europe</option>
                                                <option value="Armed Forces Pacific">Armed Forces Pacific</option>
                                            </select>

                                            <input name="addresses[shipping][province]"
                                                class="seal-input seal-input-form" data-seal-province-input=""
                                                value="Virginia" type="hidden">

                                        </div>
                                    </div>
                                </div>

                                <div class="seal-layout">
                                    <div class="seal-oneHalf">
                                        <div class="seal-floating-label">
                                            <label for="addresses[shipping][phone]" class="seal-label"
                                                data-seal-t="overviewaddress_phone_label">Phone</label>
                                            <input name="addresses[shipping][phone]" class="seal-input seal-input-form"
                                                value="(301) 366-1805" type="text">
                                        </div>
                                    </div>

                                    <div class="seal-oneHalf">
                                        <div class="seal-floating-label">
                                            <label for="addresses[shipping][company]" class="seal-label"
                                                data-seal-t="overviewaddress_company_label">Company</label>
                                            <input name="addresses[shipping][company]"
                                                class="seal-input seal-input-form" value="" type="text">
                                        </div>
                                    </div>
                                </div>

                            </div>
                            <div class="seal-layout">
                                <div class="seal-full">
                                    <div id="seal-editable-modal-save" class="seal-button seal-edit-button"
                                        data-action="save">Save</div>
                                    <div id="seal-editable-modal-cancel"
                                        class="seal-button seal-button-red seal-edit-button" data-action="cancel">Cancel
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="seal-edit-buttons-wrapper" data-seal-country-dependent="" style={{ display: "block" }}>
                        <div class="seal-edit-button seal-button seal-button-small seal-button-plain"
                            data-hide-on-edit="" data-action="edit" data-seal-t="overview_edit_button">Edit</div>
                        <!-- <div class="seal-edit-button seal-button seal-button-small seal-button-plain-red"
                            data-show-on-edit="" data-action="cancel" data-seal-t="overview_cancel_editing_button">
                            Cancel</div> -->
                        <!-- <div class="seal-edit-button seal-button seal-button-small" data-show-on-edit=""
                            data-action="save" data-seal-t="overview_save_button">Save</div>
                    </div> -->
                    </div>



                    <div class="seal-container seal-sectioned" data-discount-code-container="">
                        <div class="seal-layout">
                            <div class="seal-twoThirds seal-tar seal-sm-mt-1">
                                <div class="seal-floating-label">
                                    <label for="discount_code" class="seal-label"
                                        data-seal-t="overview_discount_code_label">Discount code</label>
                                    <input name="discount_code" class="seal-input seal-input-form" value="" type="text">
                                </div>
                            </div>

                            <div class="seal-auto seal-tar seal-sm-mt-1">
                                <div class="seal-button seal-button-next-to-input seal-edit-button"
                                    data-action="apply_discount_code" data-seal-t="overview_discount_code_apply_button">
                                    Apply</div>
                            </div>


                        </div>
                        <div class="seal-layout" style={{ display: "none" }} data-notifications-parent="">
                            <div class="seal-full seal-tac" data-notifications=""></div>
                        </div>
                    </div>


                    <div class="seal-container seal-sectioned" data-editable-container="">
                        <h3 data-seal-t="overview_payment_method_title">Payment method</h3>
                        <div class="seal-layout">
                            <div class="seal-auto">
                                <div class="card-icon card-visa"></div>
                            </div>
                            <div class="seal-full">
                                Visa <span data-seal-t="overview_payment_method_ending_in_text">ending in</span> 6940
                                <br>
                                <span data-seal-t="overview_payment_method_expires_on_text">Expires on</span> 6/2026
                            </div>
                        </div>

                        <div class="seal-edit-buttons-wrapper">
                            <div class="seal-edit-button seal-button seal-button-small seal-button-plain"
                                data-action="update-card" data-seal-t="overview_edit_button">Edit</div>
                        </div>
                    </div>


                    <div class="seal-dynamic-sectioned">


                        <div id="seal-pause-button" class="seal-button" data-seal-t="overview_pause_button">Pause my
                            subscription</div>


                        <div id="seal-unsubscribe-button" class="seal-button seal-button-red"
                            data-seal-t="overview_cancel_button">Cancel my subscription</div>


                    </div>
                </div>
            </div>

        </div>

</body>

</html>
      `;


        $(document).ready(function () {
          $(".seal-edit-button[data-action='edit']").on("click", function () {
            $(this).parents("[data-editable-container]").addClass("active");
            $(this).parents(".seal-customer-portal-shipping-card").find("#seal-editable-modal-overlay").show();
          });
          $(".seal-edit-button[data-action='cancel']").on("click", function () {
            $(this).parents("[data-editable-container]").removeClass("active");
          });
          $(".close_model").click(function () {
            $("#seal-editable-modal-overlay").hide();
            $(this).parents("[data-editable-container]").removeClass("active");
          })

          $(".seal-edit-button[data-action='save'] , .seal-edit-button[data-action='apply_discount_code']").on("click", function () {
            var selecte_value = $('#sls_select_value').val();
            var data_seal_quantity = $('[data-seal-quantity]').val();
            var data_seal_email = $('input[name="email"]').val();
            var shipping_first_name = $('input[name="addresses[shipping][first_name]"]').val();
            var shipping_last_name = $('input[name="addresses[shipping][last_name]"]').val();
            var shipping_address1 = $('input[name="addresses[shipping][address1]"]').val();
            var shipping_address2 = $('input[name="addresses[shipping][address2]"]').val();
            var shipping_zip = $('input[name="addresses[shipping][city]"]').val();
            var shipping_cuntry_code = $('select[name="addresses[shipping][country_code]"]').val();
            var shipping_province_code = $('select[name="addresses[shipping][province_code]"]').val();
            var shopping_phone = $('input[name="addresses[shipping][phone]"]').val();
            var shipping_company = $('input[name="addresses[shipping][company]"]').val();
            var discount_code = $('input[name="discount_code"]').val();
            console.log("selected value:", selecte_value, data_seal_quantity, data_seal_email, shipping_first_name, shipping_last_name, shipping_cuntry_code, shipping_province_code, shopping_phone, shipping_company, discount_code);
            $(this).parents("[data-editable-container]").find("[data-hide-on-edit]>[data-seal-t-key='interval']").html(selecte_value);
            $(this).parents("[data-editable-container]").find(".seal-product-quantity[data-hide-on-edit]").html(data_seal_quantity);
            $(this).parents("[data-editable-container]").find("#email_value").html(data_seal_email);
            $(this).parents("[data-editable-container]").find('.seal-customer-portal-shipping-card_info[shipping-info]').html(`
                       <div>
                            ${shipping_first_name} ${shipping_last_name}
                       </div>
                        <div>
                           ${shipping_address1}
                        </div>
                        <div>
                           ${shipping_zip} ${shipping_province_code}
                          </div>
                        <div>
                            ${shipping_cuntry_code} 
                        </div>
                     `);
            $(this).parents("[data-editable-container]").removeClass("active");

            var varString = selecte_value;
            var daysToAdd = parseInt(varString);
            var next_shippment_date = entry.Next_Shipment_Date; 
            var next_shippment_date_originalDate = new Date(next_shippment_date);
            var next_shippment_date_newDate = new Date(next_shippment_date_originalDate.getTime() + (daysToAdd * 24 * 60 * 60 * 1000));
            
            var year = next_shippment_date_newDate.getFullYear();
            var month = String(next_shippment_date_newDate.getMonth() + 1).padStart(2, '0');
            var day = String(next_shippment_date_newDate.getDate()).padStart(2, '0');
            
            var next_shippment_formattedDate = `${year}-${month}-${day}`;
            
            console.log(next_shippment_formattedDate);
            var data_portal = {
              next_shippment_formattedDate:next_shippment_formattedDate,
              subscription_order_id:entry.portalToken,
              selecte_value: selecte_value,
              data_seal_quantity: data_seal_quantity,
              data_seal_email: data_seal_email,
              shipping_first_name: shipping_first_name,
              shipping_last_name: shipping_last_name,
              shipping_address1: shipping_address1,
              shipping_address2: shipping_address2,
              shipping_zip: shipping_zip,
              shopping_phone: shopping_phone,
              shipping_company: shipping_company,
              discount_code: discount_code
            }
            saveSendDataToServer(data_portal);
          });
          function saveSendDataToServer(data) {
            console.log("data:-", data);
            const xhr = new XMLHttpRequest();
            const url = 'https://auto-shipped.onrender.com/send/portal/data'; // Replace with your server's endpoint URL

            xhr.open('POST', url, true);
            xhr.setRequestHeader('Content-Type', 'application/json');

            xhr.onreadystatechange = function () {
              if (xhr.readyState === XMLHttpRequest.DONE) {
                if (xhr.status === 200) {
                  console.log('Data sent successfully.');
                } else {
                  console.error('Failed to send data.');
                }
              }
            };

            xhr.send(JSON.stringify(data));
          }

        });
        fetch('https://auto-shipped.onrender.com/getadd/addIntervalDays')
          .then(response => response.json())
          .then(data => {
            console.log(data.subscription_interval_days); // Log the response to see its structure

            // const intervalSelect1 = document.getElementById('sls_select_value');
           var interval__days_value = data.subscription_interval_days;
            const intervalSelect1 = document.getElementById('sls_select_value');

            for (const interval of interval__days_value) {
              const option = document.createElement('option');
              option.value = interval;
              option.textContent = interval;
              intervalSelect1.appendChild(option);
            }
          })
          .catch(error => console.error('Error fetching data:', error));
      });

    } catch (error) {
      console.error('Error fetching data:', error);
    }
  };

  // Fetch data immediately when the script is executed
  fetchData();

}

