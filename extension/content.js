function checkURL(){

let url = window.location.href;

chrome.runtime.sendMessage(
{action:"scan", url:url},

function(response){

console.log("Web-Rakshak result:", response);

if(!response) return;

if(response.status === "Phishing"){

chrome.runtime.sendMessage({action:"playAlert"});

showWarning(response);

}

});

}

checkURL();



function showWarning(data){

let overlay = document.createElement("div");

overlay.innerHTML = `
<div style="
position:fixed;
top:0;
left:0;
width:100%;
height:100%;
background:#0b1026;
display:flex;
justify-content:center;
align-items:center;
z-index:999999;
font-family:Arial;
">

<div style="
background:#141f4d;
padding:40px;
border-radius:12px;
text-align:center;
color:white;
width:420px;
box-shadow:0 0 40px rgba(0,0,0,.7);
">

<h1 style="color:#ff4c4c">⚠ PHISHING WEBSITE</h1>

<p><b>Risk Score:</b> ${data.risk_score}%</p>

<p>This website may steal your credentials.</p>

<div style="margin-top:25px">

<button id="leaveSite"
style="
padding:10px 20px;
background:#ff4c4c;
border:none;
color:white;
border-radius:6px;
cursor:pointer;
">
Leave Site
</button>

<button id="continueSite"
style="
margin-left:10px;
padding:10px 20px;
background:#356cff;
border:none;
color:white;
border-radius:6px;
cursor:pointer;
">
Continue Anyway
</button>

</div>

</div>
</div>
`;

document.documentElement.appendChild(overlay);

document.getElementById("leaveSite").onclick = () => {
window.location.href = "https://google.com";
};

document.getElementById("continueSite").onclick = () => {
overlay.remove();
};

}