import { useState, useEffect } from "react";
import "./AddIntervalDays.css";
import axios from "axios";
import { Dna } from "react-loader-spinner";
import { ToastContainer, toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";

function TagsInput() {
  // const [tags, setTags] = useState([]);
  const [inputValue, setInputValue] = useState("");
  const [isLoading, setIsLoading] = useState(true);
  const [currentURL, setCurrentURL] = useState("");
  const [data, setData] = useState([]);

  // console.log("tags",tags,data)
  const removeLastTag = () => {
    console.log("click.......");
    if (data.length > 0) {
      const updatedTags = [...data];
      updatedTags.pop();
      setData(updatedTags);
    }
  };
  useEffect(() => {
    setCurrentURL(window.location.hostname);
    // localStorage.setItem("tempStoreName", window.location.hostname);

    fetch("https://dynamic-auto-shipp-app.onrender.com/getadd/addIntervalDays")
      .then((response) => response.json())
      .then((data) => {
        setData(data.subscription_interval_days);
        setIsLoading(false);
      })
      .catch((error) => {
        setIsLoading(false);
        console.error("Error fetching data:", error);
      });
  }, []);

  function handleKeyDown(e) {
    if (e.key === "Enter") {
      e.preventDefault();
      addTag();
    }
  }
  const removeTag = (tag, index) => {
    console.log(tag, index);
    axios
      .post("https://dynamic-auto-shipp-app.onrender.com/remove/addIntervaldays", {
        tag: tag,
        url: currentURL,
      })
      .then((response) => {
        console.log("Tag remove successfully:", response.data, currentURL);
        // const updatedTags = [...data];
        // const removeUpdateData = updatedTags.splice(index, 1);
        // setTags(updatedTags);
        toast.success("Deleted successfully...", {
          position: "top-right",
          autoClose: 5000,
          hideProgressBar: false,
          closeOnClick: true,
          pauseOnHover: true,
          draggable: true,
          progress: undefined,
          theme: "dark",
        });
        // console.log('Tag update successfully:', removeUpdateData);
        removeLastTag();
      })
      .catch((error) => {
        console.error("Error adding tag:", error);
      });
    // removeLastTag();
  };

  const addTag = () => {
    if (!inputValue.trim()) {
      toast.error("Please enter the interval days.", {
        position: "top-right",
        autoClose: 5000,
        hideProgressBar: false,
        closeOnClick: true,
        pauseOnHover: true,
        draggable: true,
        progress: undefined,
        theme: "dark",
      });
      return;
    }

    axios
      .post("https://dynamic-auto-shipp-app.onrender.com/add/addIntervalDays", {
        tag: inputValue,
        url: currentURL,
      })
      .then((response) => {
        console.log("Tag added successfully:", response.data, currentURL);
        setData([...data, inputValue]);
        setInputValue("");
        toast.success("added successfully...", {
          position: "top-right",
          autoClose: 5000,
          hideProgressBar: false,
          closeOnClick: true,
          pauseOnHover: true,
          draggable: true,
          progress: undefined,
          theme: "dark",
        });
      })
      .catch((error) => {
        console.error("Error adding tag:", error);
      });
  };

  const allTags = [...data];

  return (
    <>
      <div className="interval_days__content">
        <h2 className="interval__days">Add Interval Days</h2>
        <div className="ineterval__days__content">
          <input
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            onKeyDown={handleKeyDown}
            type="text"
            className="tags-input"
            placeholder="Enter the interval days...."
          />
          <button onClick={addTag} className="add-button">
            Add
          </button>
        </div>
        <div className="tags-input-container">
          {isLoading && (
            <Dna
              visible={true}
              height={80}
              width={80}
              ariaLabel="dna-loading"
              wrapperStyle={{}}
              wrapperClass="dna-wrapper"
            />
          )}
          {!isLoading && (
            <>
              {allTags.map((tag, index) => (
                <div className="tag-item" key={index}>
                  <span className="text">{tag}</span>
                  <span className="close" onClick={() => removeTag(tag, index)}>
                    &times;
                  </span>
                </div>
              ))}
            </>
          )}
        </div>
      </div>
      <ToastContainer
        position="top-right"
        autoClose={5000}
        hideProgressBar={false}
        newestOnTop={false}
        closeOnClick
        rtl={false}
        pauseOnFocusLoss
        draggable
        pauseOnHover
        theme="dark"
      />
    </>
  );
}

export default TagsInput;
