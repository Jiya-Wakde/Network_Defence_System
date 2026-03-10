chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {

if(request.action === "scan"){

fetch("http://127.0.0.1:5000/api/scan",{
method:"POST",
headers:{
"Content-Type":"application/json"
},
body:JSON.stringify({
url: request.url
})
})
.then(res => res.json())
.then(data => {

sendResponse(data)

})
.catch(err => {

console.error("API Error:",err)

})

return true

}

})