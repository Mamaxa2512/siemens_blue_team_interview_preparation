document.addEventListener('DOMContentLoaded', () => {
    const targetUrlInput = document.getElementById('targetUrl');
    const scanBtn = document.getElementById('scanBtn');
    
    const statusPanel = document.getElementById('statusPanel');
    const statusBadge = document.getElementById('statusBadge');
    const statusText = document.getElementById('statusText');
    const progressBar = document.getElementById('progressBar');
    
    const resultsPanel = document.getElementById('resultsPanel');
    const vulnCountBadge = document.getElementById('vulnCountBadge');
    const vulnTableBody = document.getElementById('vulnTableBody');
    
    const statCritical = document.getElementById('statCritical');
    const statHigh = document.getElementById('statHigh');
    const statMedium = document.getElementById('statMedium');
    const statLow = document.getElementById('statLow');

    let pollInterval;

    scanBtn.addEventListener('click', async () => {
        const url = targetUrlInput.value.trim();
        if (!url) {
            alert("Please enter a valid URL.");
            return;
        }

        // UI Updates for starting scan
        scanBtn.disabled = true;
        scanBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Initializing...';
        
        statusPanel.style.display = 'block';
        resultsPanel.style.display = 'none';
        
        statusBadge.className = 'badge badge-scanning';
        statusBadge.textContent = 'Scanning';
        progressBar.style.display = 'block';
        statusText.textContent = `Initiating DAST engine against ${url}...`;

        try {
            const response = await fetch('/api/scan/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target_url: url })
            });

            if (!response.ok) {
                const data = await response.json();
                throw new Error(data.error || 'Failed to start scan');
            }

            // Start polling for status
            scanBtn.innerHTML = '<i class="fa-solid fa-shield-halved"></i> Scan in Progress';
            pollInterval = setInterval(checkStatus, 2000);

        } catch (error) {
            handleError(error.message);
        }
    });

    async function checkStatus() {
        try {
            const response = await fetch('/api/scan/status');
            const data = await response.json();

            if (data.status === 'completed') {
                clearInterval(pollInterval);
                renderResults(data.results);
            } else if (data.status === 'error') {
                clearInterval(pollInterval);
                handleError(data.error_message);
            } else if (data.status === 'scanning') {
                // cycle through some fun text
                const messages = [
                    "Crawling javascript files...",
                    "Extracting API routes...",
                    "Injecting SQL payloads...",
                    "Fuzzing POST JSON endpoints...",
                    "Analyzing HTTP headers...",
                    "Bypassing authentication..."
                ];
                statusText.textContent = messages[Math.floor(Math.random() * messages.length)];
            }
        } catch (error) {
            console.error("Error polling status:", error);
        }
    }

    function renderResults(results) {
        // UI Updates for completion
        scanBtn.disabled = false;
        scanBtn.innerHTML = '<i class="fa-solid fa-bolt"></i> Launch New Scan';
        
        statusBadge.className = 'badge badge-completed';
        statusBadge.textContent = 'Completed';
        progressBar.style.display = 'none';
        statusText.textContent = `Scan finished successfully. Found ${results.length} vulnerabilities.`;
        
        resultsPanel.style.display = 'block';
        vulnCountBadge.textContent = `${results.length} Found`;

        // Calculate Stats
        let critical = 0, high = 0, medium = 0, low = 0;
        
        vulnTableBody.innerHTML = '';
        
        results.forEach(finding => {
            if (finding.severity === 'CRITICAL') critical++;
            else if (finding.severity === 'HIGH') high++;
            else if (finding.severity === 'MEDIUM') medium++;
            else if (finding.severity === 'LOW') low++;

            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><span class="tag ${finding.severity}">${finding.severity}</span></td>
                <td><strong>${finding.name}</strong><br><small style="color:var(--text-muted)">${finding.description}</small></td>
                <td><div class="code-endpoint">${finding.endpoint}</div></td>
            `;
            vulnTableBody.appendChild(tr);
        });

        // Update Stat Cards
        statCritical.textContent = critical;
        statHigh.textContent = high;
        statMedium.textContent = medium;
        statLow.textContent = low;
        
        // Scroll to results
        resultsPanel.scrollIntoView({ behavior: 'smooth' });
    }

    function handleError(message) {
        scanBtn.disabled = false;
        scanBtn.innerHTML = '<i class="fa-solid fa-bolt"></i> Launch Scan';
        
        statusBadge.className = 'badge badge-error';
        statusBadge.textContent = 'Error';
        progressBar.style.display = 'none';
        statusText.textContent = `Error: ${message}`;
        statusText.style.color = '#f87171';
    }
});
