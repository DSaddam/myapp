import React, { useState } from "react";

import {
  Children,
  SidebarContainer,
  SidebarWrapper,
  SidebarLogoWrapper,
  SidebarLogo,
  SidebarToggler,
} from "./SidebarStyles";
// import BrandLogo from "./BrandLogo.svg";

import { SidebarItems } from "..";

const MOBILE_VIEW = window.innerWidth < 468;

export default function Sidebar({ children }) {
  const [displaySidebar, setDisplaySidebar] = useState(!MOBILE_VIEW);

  const handleSidebarDisplay = (e) => {
    e.preventDefault();
    if (window.innerWidth > 468) {
      setDisplaySidebar(!displaySidebar);
    } else {
      setDisplaySidebar(false);
    }
  };

  return (
    <React.Fragment>
      <SidebarContainer displaySidebar={displaySidebar} className="slide__baar_bgColor">
        <SidebarWrapper>
          <SidebarLogoWrapper displaySidebar={displaySidebar} className="slide__baar_bgColor_img">
            <SidebarLogo href="#">
              <span className="app-brand-logo demo">
                <img src="https://betterskintoday.com/cdn/shop/files/logo.png?v=1614317304&width=200" alt="Brand logo" />
              </span>
              {/* <SidebarBrand
                displaySidebar={displaySidebar}
                className="app__brand__text"
              >
                Frest
              </SidebarBrand> */}
            </SidebarLogo>
            {/* <SidebarToggler
              displaySidebar={displaySidebar}
              onClick={handleSidebarDisplay}
            >
            </SidebarToggler> */}
          </SidebarLogoWrapper>
          <SidebarItems displaySidebar={displaySidebar} />
        </SidebarWrapper>
      </SidebarContainer>
      <Children displaySidebar={displaySidebar}>{children}</Children>
    </React.Fragment>
  );
}
