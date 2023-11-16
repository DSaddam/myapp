
function callSealSubscription(Customer_Email,orderId){
    console.log("Customer_Email,orderId",Customer_Email,orderId);
    var orderId = orderId;
const nodemailer = require('nodemailer');
const email = "saddam@priorware.com";
const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
        user: 'webdeveloper@unimedint.com',
        pass: 'usadhsdasaoribpl'
    }
});

// Define the email options
const mailOptions = {
    from: 'webdeveloper@unimedint.com',
    to: Customer_Email,
    subject: 'Test Email',
    text: 'This is a test email from Node.js',
    html: `<table style="width:100%;border-spacing:0;border-collapse:collapse">
<tbody><tr>
  <td style="font-family:-apple-system,BlinkMacSystemFont,&quot;Segoe UI&quot;,&quot;Roboto&quot;,&quot;Oxygen&quot;,&quot;Ubuntu&quot;,&quot;Cantarell&quot;,&quot;Fira Sans&quot;,&quot;Droid Sans&quot;,&quot;Helvetica Neue&quot;,sans-serif;padding-bottom:40px;border-width:0">
    <center>
      <table class="m_1614253222095114876container" style="width:560px;text-align:left;border-spacing:0;border-collapse:collapse;margin:0 auto">
        <tbody><tr>
          <td style="font-family:-apple-system,BlinkMacSystemFont,&quot;Segoe UI&quot;,&quot;Roboto&quot;,&quot;Oxygen&quot;,&quot;Ubuntu&quot;,&quot;Cantarell&quot;,&quot;Fira Sans&quot;,&quot;Droid Sans&quot;,&quot;Helvetica Neue&quot;,sans-serif">
            
          <h2 style="font-weight:normal;font-size:24px;margin:0 0 10px">Seal Subscription</h2>
          <p style="color:#777;line-height:150%;font-size:16px;margin:0">Follow this link to cancel or update your subscriptiion order at <a href="https://hswholesale.net" style="font-size:16px;text-decoration:none;color:#8b1d40" target="_blank" data-saferedirecturl="https://www.google.com/url?q=https://hswholesale.net;source=gmail&amp;ust=1686513959341000&amp;usg=AOvVaw24pG4sQNQnDRZdKzGSCldM">hswholesale.net.</p>
          <table style="width:100%;border-spacing:0;border-collapse:collapse;margin-top:20px">
<tbody><tr>
  <td style="font-family:-apple-system,BlinkMacSystemFont,&quot;Segoe UI&quot;,&quot;Roboto&quot;,&quot;Oxygen&quot;,&quot;Ubuntu&quot;,&quot;Cantarell&quot;,&quot;Fira Sans&quot;,&quot;Droid Sans&quot;,&quot;Helvetica Neue&quot;,sans-serif;line-height:0em">&nbsp;</td>
</tr>
<tr>
  <td style="font-family:-apple-system,BlinkMacSystemFont,&quot;Segoe UI&quot;,&quot;Roboto&quot;,&quot;Oxygen&quot;,&quot;Ubuntu&quot;,&quot;Cantarell&quot;,&quot;Fira Sans&quot;,&quot;Droid Sans&quot;,&quot;Helvetica Neue&quot;,sans-serif">
    <table class="m_1614253222095114876button m_1614253222095114876main-action-cell" style="border-spacing:0;border-collapse:collapse;float:left;margin-right:15px">
      <tbody><tr>
        <td style="font-family:-apple-system,BlinkMacSystemFont,&quot;Segoe UI&quot;,&quot;Roboto&quot;,&quot;Oxygen&quot;,&quot;Ubuntu&quot;,&quot;Cantarell&quot;,&quot;Fira Sans&quot;,&quot;Droid Sans&quot;,&quot;Helvetica Neue&quot;,sans-serif;border-radius:4px" align="center" bgcolor="#8b1d40"><a pppp onclick = "uniqueSubscription(event);" href=https://hswholesale.net/pages/portalsubscription?${orderId} class="m_1614253222095114876button__text" style="font-size:16px;text-decoration:none;display:block;color:#fff;padding:20px 25px" target="_blank" data-saferedirecturl="https://www.google.com/url?q=https://hswholesale.net/account/reset/6698695721144/a5492a64cd07417ecc5ac430b69fd0aa-1686419748&amp;source=gmail&amp;ust=1686513959341000&amp;usg=AOvVaw05ZLrm7dmCjQCRYyXYvS9-">Seal Subscription ppp</a></td>
      </tr>
    </tbody>
    </table>
  <table class="m_1614253222095114876secondary-action-cell" style="border-spacing:0;border-collapse:collapse;margin-top:19px">
    <tbody><tr>
      <td style="font-family:-apple-system,BlinkMacSystemFont,&quot;Segoe UI&quot;,&quot;Roboto&quot;,&quot;Oxygen&quot;,&quot;Ubuntu&quot;,&quot;Cantarell&quot;,&quot;Fira Sans&quot;,&quot;Droid Sans&quot;,&quot;Helvetica Neue&quot;,sans-serif;border-radius:4px" align="center">or <a href="https://hswholesale.net" style="font-size:16px;text-decoration:none;color:#8b1d40" target="_blank" data-saferedirecturl="https://www.google.com/url?q=https://hswholesale.net&amp;source=gmail&amp;ust=1686513959341000&amp;usg=AOvVaw24pG4sQNQnDRZdKzGSCldM">Visit our store</a>
</td>
    </tr>
  </tbody>
  </table>
  </td>
</tr>
</tbody>
</table>
          </td>
        </tr>
      </tbody>
      </table>
    </center>
  </td>
</tr>
</tbody>
<script>function uniqueSubscription(e){
    e.preventDefault();
    console.log("working fine")
}</script>
</table>`
};

// Send the email
transporter.sendMail(mailOptions, function (error, info) {
    if (error) {
        console.log('Error occurred:');
        console.log(error.message);
    } else {
        // res.send({ message: "Successful... check email!" });
        console.log('Email sent successfully!');
        res.send({ message: "Successfull... check email!" });
        console.log('Message ID: ' + info.messageId);
    }
});

}
module.exports = {callSealSubscription}