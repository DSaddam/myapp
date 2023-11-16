import {
  HomeIcon,
  LayoutIcon,
  UserIcon,
  PagesIcon,
  AddCircleIcon,
  LogoutIcon ,
} from "./Icons";

export const SIDEBAR_DATA = [
  {
    id: 1,
    name: "dashboard",
    path: "dashboards",
    icon: <HomeIcon />,
  },
  {
    id: 2,
    name: "Subscriptions",
    path: "Subscriptions",
    icon: <LayoutIcon />,
  },
  {
    id: 3,
    name: "Add Interval",
    path: "AddInterval",
    icon: <AddCircleIcon />,
  },
  {
    id: 4,
    name: "Add Page",
    path: "AddPage",
    icon: <AddCircleIcon />,
  },
  {
    id: 5,
    name: "Integrate  Auto Shipped",
    path: "Settings",
    icon: <PagesIcon />,
  },
  // {
  //   id: 6,
  //   name: "Order Details",
  //   path: "orderdetails",
  //   icon: <PagesIcon />,
  // }
];
