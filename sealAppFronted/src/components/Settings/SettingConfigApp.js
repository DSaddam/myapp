import React, { useState } from 'react';
import "./SettingConfigApp.css";
import SealSubscriptionImage1 from './SealSubscriptionImage/SealsubscriptionApp-01.png';
import SealSubscriptionImage2 from './SealSubscriptionImage/SealsubscriptionApp-02.png';
import SealSubscriptionImage3 from './SealSubscriptionImage/SealsubscriptionApp-03.png';
import SealSubscriptionImage4 from './SealSubscriptionImage/SealsubscriptionApp-04.png';
import SealSubscriptionImage5 from './SealSubscriptionImage/SealsubscriptionApp-05.png';
import SealSubscriptionImage6 from './SealSubscriptionImage/SealsubscriptionApp-06.png';
import SealSubscriptionImage7 from './SealSubscriptionImage/SealsubscriptionApp-07.png';
import SealSubscriptionImage8 from './SealSubscriptionImage/SealsubscriptionApp-08.png';
import SealSubscriptionImage9 from './SealSubscriptionImage/SealsubscriptionApp-09.png';
import SealSubscriptionImage10 from './SealSubscriptionImage/SealsubscriptionApp-10.png';
import SealSubscriptionImage11 from './SealSubscriptionImage/SealsubscriptionApp-11.png';
import SealSubscriptionImage12 from './SealSubscriptionImage/SealsubscriptionApp-12.png';

export const SettingConfigApp = () => {
  //  const imageUrl  = SealSubscriptionImage;
  // console.log(" seal subscription settings image:-",SealSubscriptionImage)
  const [activeSlideIndex, setActiveSlideIndex] = useState(0);
   
  const changeSlide = (direction) => {
    const sliderHeight = document.querySelector('.slider-container').clientHeight;

    if (direction === 'up') {
      setActiveSlideIndex((prevIndex) =>
        prevIndex < slidesLength - 1 ? prevIndex + 1 : 0
      );
    } else if (direction === 'down') {
      setActiveSlideIndex((prevIndex) =>
        prevIndex > 0 ? prevIndex - 1 : slidesLength - 1
      );
    }
    document.querySelector('.right-slide').style.transform = `translateY(-${
      activeSlideIndex * sliderHeight
    }px)`;
    document.querySelector('.left-slide').style.transform = `translateY(-${
      activeSlideIndex * sliderHeight
    }px)`;
  };

  const slidesLength = document.querySelectorAll('.right-slide div').length;

  return (
    <div className="slider-container">
      <div className="left-slide">
        <div style={{ backgroundColor: '#000' }}>
          <h1>Dashboard</h1>
          <p>Seal Subscription App</p>
        </div>
        <div style={{ backgroundColor: '#000' }}>
          <h1>Subscription Tab</h1>
          {/* <p>Seal Subscription App</p> */}
        </div>
        <div style={{ backgroundColor: '#000' }}>
          <h1>Subscription Tab</h1>
          <p>When click on view Button Open the Order detalis</p>
        </div>
        <div style={{ backgroundColor: '#000' }}>
          <h1>Subscription Tab</h1>
          <p>view Order detalis</p>
        </div>
        <div style={{ backgroundColor: '#000' }}>
          <h1>Subscription Tab</h1>
          <p>When click on copy to clipboard and create a portal link and past the in browser url</p>
        </div>
        <div style={{ backgroundColor: '#000' }}>
          <h1>Upcomming Subscription Tab</h1>
          {/* <p>view Order detalis</p> */}
        </div>
        <div style={{ backgroundColor: '#000' }}>
          <h1>Cancelled Subscription Tab</h1>
          {/* <p>view Order detalis</p> */}
        </div>
        <div style={{ backgroundColor: '#000' }}>
          <h1>AddInterval Days</h1>
          <p>Add interval days and effect on the website.</p>
        </div>
        <div style={{ backgroundColor: '#000' }}>
          <h1>AddInterval Days</h1>
          <p>When add interval days and show on the website.</p>
        </div>
        <div style={{ backgroundColor: '#000' }}>
          <h1>Add Page</h1>
          <p>When click on create page button and redirect to the  shopify create page.</p>
          <h4 style={{fontSize:'20px',marginTop:'15px'}}>Name of the page is <span style={{color:'skyblue'}}>Portalsubscription</span></h4>
        </div>
        <div style={{ backgroundColor: '#000' }}>
          <h1>Add Page</h1>
          <p>Create shopify page</p>
        </div>
        <div style={{ backgroundColor: '#000' }}>
          <h1>Thank you</h1>
          {/* <p>view Order detalis</p> */}
        </div>
        {/* Add other slides here */}
      </div>
      <div className="right-slide">
        <div
          style={{
            backgroundImage: `url(${SealSubscriptionImage1})`
          }}
        ></div>
              <div
          style={{
            backgroundImage: `url(${SealSubscriptionImage2})`
          }}
        ></div>
              <div
          style={{
            backgroundImage: `url(${SealSubscriptionImage3})`
          }}
        ></div>
              <div
          style={{
            backgroundImage: `url(${SealSubscriptionImage4})`
          }}
        ></div>
              <div
          style={{
            backgroundImage: `url(${SealSubscriptionImage5})`
          }}
        ></div>
              <div
          style={{
            backgroundImage: `url(${SealSubscriptionImage6})`
          }}
        ></div>
              <div
          style={{
            backgroundImage: `url(${SealSubscriptionImage7})`
          }}
        ></div>
              <div
          style={{
            backgroundImage: `url(${SealSubscriptionImage8})`
          }}
        ></div>
              <div
          style={{
            backgroundImage: `url(${SealSubscriptionImage9})`
          }}
        ></div>
              <div
          style={{
            backgroundImage: `url(${SealSubscriptionImage10})`
          }}
        ></div>
              <div
          style={{
            backgroundImage: `url(${SealSubscriptionImage11})`
          }}
        ></div>
              <div
          style={{
            backgroundImage: `url(${SealSubscriptionImage12})`
          }}
        ></div>
        {/* Add other slides here */}
      </div>
      <div className="action-buttons">
        <button className="down-button" onClick={() => changeSlide('down')}>
          <i className="fas fa-arrow-down"></i>
        </button>
        <button className="up-button" onClick={() => changeSlide('up')}>
          <i className="fas fa-arrow-up"></i>
        </button>
      </div>
    </div>
  );
};

