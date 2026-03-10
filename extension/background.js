chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {

fetch("http://127.0.0.1:5000/api/scan", {

method: "POST",

headers: {
"Content-Type": "application/json"
},

body: JSON.stringify({
url: request.url
})

})
.then(res => res.json())
.then(data => sendResponse(data))
.catch(err => sendResponse({error:true}))

return true

})