import React, { useState, useRef } from 'react'
import copy from "copy-to-clipboard";
import { Heading, Input1, Input2, Container, Button } from './Styles'

const Clipboard = ({ Copyportal, SubscriptionOrderId,SubscriptionPortalToken }) => {
	//  alert("data:-",subscription_order_id);

	// console.log("copyportal::::::::", Copyportal, SubscriptionOrderId)
	const [copyText, setCopyText] = useState('');
	const inputRef = useRef(null);
	const portalCustomerUrl = `https://genucel105.myshopify.com/pages/portalsubscription?${SubscriptionPortalToken}`
	const handleCopyText = (e) => {
		setCopyText(e.target.value);
	}

	const copyToClipboard = () => {
		Copyportal();
		const inputValue = inputRef.current.value;
		console.log('Input Value:', inputValue);
		copy(inputValue);
		// alert(`You have copied "${copyText}"`);
	}

	return (
		<>
			<div className='Clipboard'>
				<Container>
					<Input1
						className='copy__To__CLip__board'
						type="text"
						ref={inputRef}
						value={portalCustomerUrl}
						onChange={handleCopyText}
						placeholder='Enter the text you want to copy' />

					<Button onClick={copyToClipboard}>
						Copy to Clipboard
					</Button>
				</Container>

			</div>
		</>
	)
}

export default Clipboard;
