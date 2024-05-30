const apiUrl = 'http://localhost:5000/api/cves';
const recordsPerPage = 10;
let currentPage = 1;
let totalRecords = 0;

document.addEventListener('DOMContentLoaded', () => {
    fetchCveData();

    document.getElementById('prev-page').addEventListener('click', () => {
        if (currentPage > 1) {
            currentPage--;
            fetchCveData();
        }
    });

    document.getElementById('next-page').addEventListener('click', () => {
        if (currentPage < Math.ceil(totalRecords / recordsPerPage)) {
            currentPage++;
            fetchCveData();
        }
    });
});

async function fetchCveData() {
    try {
        const response = await fetch(apiUrl);
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }

        const data = await response.json();
        console.log('Fetched data:', data);  // Log the data
        totalRecords = data.length;
        displayCveData(data.slice((currentPage - 1) * recordsPerPage, currentPage * recordsPerPage));
        updatePaginationInfo();
    } catch (error) {
        console.error('Fetch error:', error);
    }
}

function displayCveData(cveData) {
    const tableBody = document.getElementById('cve-table-body');
    tableBody.innerHTML = '';

    cveData.forEach(cve => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${cve.id}</td>
            <td>${cve.sourceIdentifier}</td>
            <td>${formatDate(cve.published)}</td>
            <td>${formatDate(cve.lastModified)}</td>
            <td>${cve.vulnstatus}</td>
        `;
        tableBody.appendChild(row);
    });

    document.getElementById('total-records').textContent = totalRecords;
}

function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-GB', {
        day: '2-digit',
        month: 'short',
        year: 'numeric',
    });
}

function updatePaginationInfo() {
    document.getElementById('page-info').textContent = `${currentPage}`;
    document.getElementById('prev-page').disabled = currentPage === 1;
    document.getElementById('next-page').disabled = currentPage === Math.ceil(totalRecords / recordsPerPage);
}
