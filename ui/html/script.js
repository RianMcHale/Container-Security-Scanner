// script.js
// --------------------
// File handles everything on the browser side (front end)
// Talks to the FLask backend API (via Nginx using /api prefix)
// Uses the above to start new scans & show scan results on the web
// ---------------------

// gets a list of previous scans when site loads
document.addEventListener('DOMContentLoaded', () => {
    fetchScans();
});

// get references to html elements in use
const scanBtn = document.getElementById('scan-btn');
const refreshBtn = document.getElementById('refresh-btn');
const imageInput = document.getElementById('image-input');
const messageDiv = document.getElementById('message');
const scansTableBody = document.querySelector('#scans-table tbody');
const detailsDiv = document.getElementById('details');
const detailsContent = document.getElementById('details-content');

// start a new scan when user presses "Scan"
scanBtn.addEventListener('click', async () => {
    const image = imageInput.value.trim();
    if (!image) {
        alert('Please enter a container image name');
        return;
    }
    // show message while the scan runs
    messageDiv.textContent = 'Scanning image... this may take a moment.';
    try {
    	// send a post request to the API to start the scan
        const resp = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ image })
        });
        
        // error handler
        if (!resp.ok) {
            const err = await resp.json();
            throw new Error(err.message || 'Scan failed');
        }
        
        // get back the scan result summary
        const data = await resp.json();
        // shows the amount of vulnerabilities found
        messageDiv.textContent = `Scan complete. Found ${countTotal(data.summary)} vulnerabilities.`;
        // clear the input box
        imageInput.value = '';
        // update the list of scans to show the new one
        fetchScans();
    } catch (err) {
        console.error(err);
        messageDiv.textContent = `Error: ${err.message}`;
    }
});

// Refresh the scan list when user presses "Refresh"
refreshBtn.addEventListener('click', () => {
    fetchScans();
});

// Helper function to count total vulnerabilities from a summary object
// High: 3, Low: 2 -> returns 5
function countTotal(summary) {
    return Object.values(summary).reduce((acc, v) => acc + v, 0);
}

// Fetch the list of scans from the API and shows in the table
async function fetchScans() {
    try {
        const resp = await fetch('/api/scans');
        if (!resp.ok) {
            throw new Error('Failed to fetch scans');
        }
        const scans = await resp.json();
        
        // Clear the table first
        scansTableBody.innerHTML = '';
        
        // If there are no scans, shows a message row
        if (scans.length === 0) {
            scansTableBody.innerHTML = '<tr><td colspan="9">No scans found</td></tr>';
            return;
        }
        
	// add a table row for each scan
        scans.forEach(scan => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${scan.id}</td>
                <td>${scan.image}</td>
                <td>${new Date(scan.created_at).toLocaleString()}</td>
                <td>${scan.summary.CRITICAL || 0}</td>
                <td>${scan.summary.HIGH || 0}</td>
                <td>${scan.summary.MEDIUM || 0}</td>
                <td>${scan.summary.LOW || 0}</td>
                <td>${scan.summary.UNKNOWN || 0}</td>
                <td><button data-id="${scan.id}">View</button></td>
            `;
            
            // adda a click event for the "view" button to show details
            row.querySelector('button').addEventListener('click', () => {
                fetchScanDetails(scan.id);
            });
            
            // add this row to the table
            scansTableBody.appendChild(row);
        });
    } catch (err) {
        console.error(err);
        messageDiv.textContent = `Error: ${err.message}`;
    }
}

// get and display the details for specific scans
async function fetchScanDetails(id) {
    try {
        const resp = await fetch(`/api/scans/${id}`);
        if (!resp.ok) {
            throw new Error('Failed to fetch scan details');
        }
        const scan = await resp.json();
        
        // build some html showing the scan info and results
        let html = `<p><strong>Image:</strong> ${scan.image}</p>`;
        html += `<p><strong>Scanned at:</strong> ${new Date(scan.created_at).toLocaleString()}</p>`;
        html += '<h3>Severity Summary</h3>';
        html += '<ul>';
        
        // list each severity (critical, high, etc)
        for (const [sev, count] of Object.entries(scan.summary)) {
            html += `<li>${sev}: ${count}</li>`;
        }
        html += '</ul>';
        html += '<h3>Full Report (JSON)</h3>';
        html += `<pre>${JSON.stringify(scan.report, null, 2)}</pre>`;
        
        // show the details in the detail box
        detailsContent.innerHTML = html;
        detailsDiv.style.display = 'block';
        
        // scroll down to the details section smoothly
        detailsDiv.scrollIntoView({ behavior: 'smooth' });
    } catch (err) {
        console.error(err);
        messageDiv.textContent = `Error: ${err.message}`;
    }
}
