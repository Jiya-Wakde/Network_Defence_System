async function checkURL() {

    let url = window.location.href;

    try {

        let response = await fetch("http://127.0.0.1:5000/api/scan", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                url: url
            })
        });

        let data = await response.json();

        console.log("SentinelAI Scan Result:", data);

        // Show popup if risk >= 50
        if (data.risk_score >= 50) {
            showWarning(data);
        }

    } catch (e) {
        console.log("SentinelAI backend not reachable");
    }
}


function showWarning(data) {

    // Prevent duplicate popup
    if (document.getElementById("sentinel-overlay")) {
        return;
    }

    let overlay = document.createElement("div");
    overlay.id = "sentinel-overlay";

    overlay.innerHTML = `
        <div class="sentinel-popup">
            <h2>⚠ POTENTIAL PHISHING DETECTED</h2>
            <p>This website may be unsafe.</p>

            <div class="risk">
                Risk Score: ${data.risk_score}%
            </div>

            <p>Status: ${data.status}</p>

            <div class="buttons">
                <button id="leave">Leave Site</button>
                <button id="continue">Proceed Anyway</button>
            </div>
        </div>
    `;

    document.body.appendChild(overlay);

    document.getElementById("leave").onclick = () => {
        window.location.href = "https://google.com";
    };

    document.getElementById("continue").onclick = () => {
        overlay.remove();
    };
}


// Run scan
checkURL();