import { CONFIG } from './config.js';
import { state } from './state.js';
import { showToast, escapeHtml, phoneTelHref, showScreen } from './utils.js';
import { logout, fetchWithAuth } from './auth.js';
import { openLeadForm, copyFormToClipboard, addProductRow } from './form.js';

let performanceChart = null;

export function initializeApp() {
    document.getElementById('searchInput').addEventListener('input', (e) => performSearch(e.target.value));
    document.getElementById('nextBtn').addEventListener('click', nextRow);
    document.getElementById('prevBtn').addEventListener('click', prevRow);

    document.getElementById('exportSummaryBtn').addEventListener('click', exportSummaryTXT);
    document.getElementById('clearHistoryBtn').addEventListener('click', clearHistory);
    document.getElementById('goToRowBtn').addEventListener('click', goToRow);
    document.getElementById('clearDispositionBtn').addEventListener('click', clearDispositionData);
    document.getElementById('logoutBtn').addEventListener('click', logout);

    document.getElementById('toggleFilterBtn').addEventListener('click', toggleFilterPanel);
    document.getElementById('applyFilterBtn').addEventListener('click', applyFilter);
    document.getElementById('selectAllBtn').addEventListener('click', selectAllDispositions);
    document.getElementById('clearFilterBtn').addEventListener('click', clearFilter);
    document.getElementById('hideFilterBtn').addEventListener('click', hideFilterPanel);
    document.getElementById('toggleCallbacksBtn').addEventListener('click', toggleCallbacksPanel);
    document.getElementById('exportCallbacksBtn').addEventListener('click', exportCallbacks);
    document.getElementById('viewHistoryBtn').addEventListener('click', () => {
        const currentLead = state.isFilterActive ? state.filteredData[state.currentIndex] : state.data[state.currentIndex];
        if (currentLead && currentLead._id) {
            showHistory(currentLead._id);
        } else {
            showToast('No lead selected');
        }
    });

    document.getElementById('navigationContainer').style.display = 'block';
    document.getElementById('counterContainer').style.display = 'block';
    document.getElementById('clearDispositionBtn').style.display = 'block';
    document.getElementById('controls').style.display = 'flex';

    loadAgentData();
    loadUserData();
    loadCallbacks();

    // Export Summary Modal Listeners
    document.getElementById('closeExportSummaryModalBtn').addEventListener('click', () => {
        document.getElementById('exportSummaryModal').style.display = 'none';
    });

    document.getElementById('copySummaryBtn').addEventListener('click', () => {
        const content = document.getElementById('exportSummaryContent').textContent;
        navigator.clipboard.writeText(content).then(() => {
            showToast('Summary copied to clipboard', 'success');
        }).catch(err => {
            console.error('Copy error:', err);
            showToast('Failed to copy summary', 'error');
        });
    });

    // Lead Form Modal Listeners
    const openFormBtn = document.getElementById('openFormBtn');
    if (openFormBtn) openFormBtn.addEventListener('click', openLeadForm);

    const closeFormModalBtn = document.getElementById('closeFormModalBtn');
    if (closeFormModalBtn) closeFormModalBtn.addEventListener('click', () => {
        document.getElementById('leadFormModal').style.display = 'none';
    });

    const addProductBtn = document.getElementById('addProductBtn');
    if (addProductBtn) addProductBtn.addEventListener('click', addProductRow);

    const copyFormBtn = document.getElementById('copyFormBtn');
    if (copyFormBtn) copyFormBtn.addEventListener('click', copyFormToClipboard);

    const closeHistoryModalBtn = document.getElementById('closeHistoryModalBtn');
    if (closeHistoryModalBtn) closeHistoryModalBtn.onclick = () => {
        document.getElementById('leadHistoryModal').style.display = 'none';
    };
}

async function loadAgentData() {
    try {
        const resp = await fetchWithAuth(`${CONFIG.API_BASE_URL}/agent/data`);
        if (!resp.ok) {
            showToast('Error loading agent data');
            return;
        }
        const result = await resp.json();
        state.data = result.data;
        state.currentIndex = result.currentIndex || 0;
        state.lastSavedIndex = -1;
        state.isFilterActive = false;
        state.filteredData = [];
        state.selectedDispositions = [];
        state.availableDispositions = [];
        state.availableLists = [];
        state.availableCustomIds = [];
        extractFilterData();
        loadSavedFilters();
        updateFilterStats();
        showRow(state.currentIndex);
        updateCounters();
        updateCurrentPosition();
    } catch (err) {
        showToast('Connection error while loading data');
    }
}

function loadSavedFilters() {
    try {
        const userData = JSON.parse(localStorage.getItem(`userData_${state.currentUser.id}`) || '{}');
        const filters = userData.filters;
        if (!filters) return;

        let hasActiveFilter = false;

        // Restore Dispositions
        if (filters.dispositions && Array.isArray(filters.dispositions)) {
            filters.dispositions.forEach(d => {
                const cb = document.getElementById(`filter-${d}`);
                if (cb) {
                    cb.checked = true;
                    hasActiveFilter = true;
                }
            });
        }

        // Restore List
        const listSelect = document.getElementById('filterList');
        if (filters.list && listSelect) {
            listSelect.value = filters.list;
            // Verify if value was actually set (it might not exist in options anymore)
            if (listSelect.value) hasActiveFilter = true;
        }

        // Restore Custom ID
        const customSelect = document.getElementById('filterCustomId');
        if (filters.customId && customSelect) {
            customSelect.value = filters.customId;
            if (customSelect.value) hasActiveFilter = true;
        }

        if (hasActiveFilter) {
            applyFilter();
        }
    } catch (e) {
        console.error("Error loading saved filters", e);
    }
}

function loadUserData() {
    const userData = JSON.parse(localStorage.getItem(`userData_${state.currentUser.id}`) || '{}');
    state.historyLog = userData.history || [];
    state.sessionDispositions = userData.dispositions || {};
    updateHistory();
    updateCounters();
}

function extractFilterData() {
    const dispositionSet = new Set();
    const listSet = new Set();
    const customIdSet = new Set();

    state.data.forEach((row) => {
        // Dispositions
        const d = (row['DISPOSITION'] || '').toString().trim();
        if (d) dispositionSet.add(d);

        // List Name
        const l = (row['listName'] || '').toString().trim();
        if (l) listSet.add(l);

        // Custom ID
        const c = (row['customId'] || '').toString().trim();
        if (c) customIdSet.add(c);
    });

    state.availableDispositions = Array.from(dispositionSet).sort();
    state.availableLists = Array.from(listSet).sort();
    state.availableCustomIds = Array.from(customIdSet).sort();

    updateFilterOptions();
}

function updateFilterOptions() {
    const el = document.getElementById('filterOptions');
    const listSelect = document.getElementById('filterList');
    const customIdSelect = document.getElementById('filterCustomId');

    // Populate List Dropdown
    if (listSelect) {
        const currentList = listSelect.value;
        listSelect.innerHTML = '<option value="">All Lists</option>' +
            state.availableLists.map(l => `<option value="${escapeHtml(l)}">${escapeHtml(l)}</option>`).join('');
        listSelect.value = currentList; // Restore selection if valid
    }

    // Populate Custom ID Dropdown
    if (customIdSelect) {
        const currentId = customIdSelect.value;
        customIdSelect.innerHTML = '<option value="">All Custom IDs</option>' +
            state.availableCustomIds.map(c => `<option value="${escapeHtml(c)}">${escapeHtml(c)}</option>`).join('');
        customIdSelect.value = currentId; // Restore selection
    }

    // Populate Dispositions
    if (!state.availableDispositions.length) {
        el.innerHTML = '<p style="text-align:center;color:var(--subtext);">No dispositions in data</p>';
        return;
    }

    // Add N/A at the beginning for "Not Called" leads
    const uniqueDispos = [...new Set(state.availableDispositions)].filter(d => d && d !== 'N/A');
    const allDispositions = ['N/A', ...uniqueDispos.sort()];

    el.innerHTML = allDispositions.map(d => {
        const label = d === 'N/A' ? 'N/A (Not Called)' : d;
        return `
    <div class="filter-option">
      <input type="checkbox" id="filter-${d}" value="${d}">
      <label for="filter-${d}">${label}</label>
    </div>`;
    }).join('');
}

function toggleFilterPanel() {
    const right = document.getElementById('rightPanel');
    const callbacksList = right.querySelector('#callbacksList').parentElement;
    const filterSection = right.querySelector('.filter-section');
    const filteredContacts = right.querySelector('#filteredContactsList').parentElement;

    if (right.style.display === 'flex') {
        right.style.display = 'none';
        document.getElementById('toggleFilterBtn').textContent = '🔍 Show Filters';
    } else {
        right.style.display = 'flex';
        document.getElementById('toggleFilterBtn').textContent = '🔍 Hide Filters';
        if (state.data.length) extractFilterData();
        callbacksList.style.display = 'none';
        filterSection.style.display = 'block';
        filteredContacts.style.display = 'block';
    }
}

function selectAllDispositions() { document.querySelectorAll('#filterOptions input[type="checkbox"]').forEach(cb => cb.checked = true); }

function clearFilter() {
    document.querySelectorAll('#filterOptions input[type="checkbox"]').forEach(cb => cb.checked = false);
    document.getElementById('filterList').value = "";
    document.getElementById('filterCustomId').value = "";
    state.selectedDispositions = [];
    state.isFilterActive = false;
    state.filteredData = [];
    state.currentIndex = 0;

    // Clear from storage
    const userData = JSON.parse(localStorage.getItem(`userData_${state.currentUser.id}`) || '{}');
    delete userData.filters;
    localStorage.setItem(`userData_${state.currentUser.id}`, JSON.stringify(userData));

    updateFilterStats();
    showRow(state.currentIndex);
    updateCurrentPosition();
}

function hideFilterPanel() {
    document.getElementById('rightPanel').style.display = 'none';
    document.getElementById('toggleFilterBtn').textContent = '🔍 Show Filters';
}

function applyFilter() {
    const checked = Array.from(document.querySelectorAll('#filterOptions input[type="checkbox"]:checked')).map(cb => cb.value);
    state.selectedDispositions = checked;

    const selectedList = document.getElementById('filterList').value;
    const selectedCustomId = document.getElementById('filterCustomId').value;

    if (!state.selectedDispositions.length && !selectedList && !selectedCustomId) {
        showToast('Please select at least one filter criterion');
        return;
    }

    state.filteredData = state.data.filter(row => {
        const d = (row['DISPOSITION'] || '').toString();
        const l = (row['listName'] || '').toString();
        const c = (row['customId'] || '').toString();

        // Handle disposition matching: N/A means null/empty disposition
        let matchDisposition = state.selectedDispositions.length === 0;
        if (!matchDisposition) {
            matchDisposition = state.selectedDispositions.some(selectedDisp => {
                if (selectedDisp === 'N/A') {
                    // N/A matches empty or null dispositions
                    return !d || d === '' || d === 'null';
                } else {
                    return d === selectedDisp;
                }
            });
        }

        const matchList = !selectedList || l === selectedList;
        const matchCustomId = !selectedCustomId || c === selectedCustomId;

        return matchDisposition && matchList && matchCustomId;
    });

    // Save to storage
    const userData = JSON.parse(localStorage.getItem(`userData_${state.currentUser.id}`) || '{}');
    userData.filters = {
        dispositions: state.selectedDispositions,
        list: selectedList,
        customId: selectedCustomId
    };
    localStorage.setItem(`userData_${state.currentUser.id}`, JSON.stringify(userData));

    state.isFilterActive = true;
    state.currentIndex = 0;
    updateFilterStats();
    updateFilteredContactsList();
    showRow(state.currentIndex);
    updateCurrentPosition();
}

function updateFilterStats() {
    const stats = document.getElementById('filterStats');
    const currentData = state.isFilterActive ? state.filteredData.map(f => f.row) : state.data;
    stats.textContent = `Showing: ${currentData.length} of ${state.data.length} contacts`;
    if (state.isFilterActive) {
        const listVal = document.getElementById('filterList').value;
        const customIdVal = document.getElementById('filterCustomId').value;
        let info = [];
        if (state.selectedDispositions.length) info.push(`Disp: ${state.selectedDispositions.join(', ')}`);
        if (listVal) info.push(`List: ${listVal}`);
        if (customIdVal) info.push(`ID: ${customIdVal}`);

        stats.innerHTML += `<br><small>Filter: ${info.join(' | ')}</small>`;
    }
}

function updateFilteredContactsList() {
    const list = document.getElementById('filteredContactsList');
    if (!state.filteredData.length) {
        list.innerHTML = '<p style="text-align:center;color:var(--subtext);">No contacts match the filter</p>';
        return;
    }
    list.innerHTML = state.filteredData.map((row, i) => {
        const name = row['Name'] || 'No name';
        const phone = row['Phone'] || 'No phone';
        const dispo = row['DISPOSITION'] || 'No disposition';
        return `
      <div class="filter-option" style="cursor:pointer;padding:8px;margin:2px 0;border-radius:4px;border:1px solid var(--border);" onclick="goToFilteredContact(${i})">
        <strong>${escapeHtml(name)}</strong><br><small>📞 ${escapeHtml(phone)}</small><br><small>🟦 ${escapeHtml(dispo)}</small>
      </div>`;
    }).join('');
    if (window.feather) feather.replace();
}

export function goToFilteredContact(i) {
    if (!state.isFilterActive) return;
    state.currentIndex = i;
    showRow(state.currentIndex);
    updateCurrentPosition();
}

function performSearch(searchTerm) {
    const lowerCaseSearchTerm = searchTerm.toLowerCase();
    if (!lowerCaseSearchTerm) {
        state.isFilterActive = false;
        state.filteredData = [];
        showRow(state.currentIndex);
        updateCurrentPosition();
        updateFilterStats();
        return;
    }

    state.isFilterActive = true;
    state.filteredData = state.data.filter((row) => {
        return Object.values(row).some(val => String(val).toLowerCase().includes(lowerCaseSearchTerm));
    });

    state.currentIndex = 0;
    showRow(state.currentIndex);
    updateCurrentPosition();
    updateFilterStats();
    updateFilteredContactsList();
}

function showRow(index) {
    const container = document.getElementById('dataContainer');
    const currentData = state.isFilterActive ? state.filteredData : state.data;
    if (!currentData || !currentData[index]) {
        container.style.display = 'none';
        return;
    }
    const row = currentData[index];

    let dateSent = row['Date Sent'] || row['Date'] || '';
    if (typeof dateSent === 'number') {
        const excelEpoch = new Date(1899, 11, 30);
        const jsDate = new Date(excelEpoch.getTime() + dateSent * 24 * 60 * 60 * 1000);
        dateSent = jsDate.toLocaleDateString();
    }

    container.style.display = 'block';
    container.innerHTML = `
    ${state.isFilterActive ? '<div style="background:var(--accent);color:white;padding:8px;border-radius:6px;margin-bottom:12px;text-align:center;">🔍 Filtered View</div>' : ''}
    <div class="row-item"><span class="label">Date Sent:</span><span>${escapeHtml(dateSent)}</span></div>
    <div class="row-item"><span class="label">Prev. Company:</span><span>${escapeHtml(row['Prev. Company'] || '')}</span></div>
    <div class="row-item"><span class="label">Name:</span><span>${escapeHtml(row['Name'] || '')}</span></div>
    <div class="row-item"><span class="label">Address:</span><span>${escapeHtml(row['Address'] || '')}</span></div>
    <div class="row-item"><span class="label">Phone:</span><span><a href="${phoneTelHref(row['Phone'] || '')}" id="phoneLink">Call: ${escapeHtml(row['Phone'] || '')}</a></span></div>
    <div class="row-item"><span class="label">Email or Second Phone:</span><span>${escapeHtml(row['Email or Second Phone'] || '')}</span></div>
    <div class="row-item"><span class="label">Product:</span><span>${escapeHtml(row['Product'] || '')}</span></div>
    <div class="row-item"><span class="label">Prev. Status:</span><span>${escapeHtml(row['Prev. Status'] || '')}</span></div>
    <div class="row-item"><span class="label">Call Log:</span><span>${escapeHtml(row['Call Log'] || '')}</span></div>
    <hr>
    <div id="agent-actions">
        <div class="row-item">
          <span class="label">Disposition:</span>
          <select id="dispositionSelect">
            <option value="">Select...</option>
            <option value="NA">NA</option>
            <option value="DNC">DNC</option>
            <option value="ADP">ADP</option>
            <option value="WN">WN</option>
            <option value="VM">VM</option>
            <option value="DC">DC</option>
            <option value="ND/SD">ND/SD</option>
            <option value="FUTURE">FUTURE</option>
            <option value="KICKED">KICKED</option>
            <option value="NI">NI</option>
            <option value="HU">HU</option>
            <option value="Callback">Callback</option>
          </select>
        </div>
        <div id="callback-section" class="row-item" style="display: none;">
            <span class="label">Callback Date:</span>
            <div>
                <input type="date" id="callbackDate" class="form-input" style="margin-right: 8px; width: auto;">
                <input type="time" id="callbackTime" class="form-input" style="width: auto;">
            </div>
        </div>
        <div class="row-item">
          <span class="label">Language: <span style="color:var(--danger)">*</span></span>
          <div style="display:flex;gap:15px;">
            <label style="display:flex;align-items:center;gap:5px;cursor:pointer;">
              <input type="radio" name="language" value="English" id="languageEnglish">
              <span>English</span>
            </label>
            <label style="display:flex;align-items:center;gap:5px;cursor:pointer;">
              <input type="radio" name="language" value="Spanish" id="languageSpanish">
              <span>Spanish</span>
            </label>
            <label style="display:flex;align-items:center;gap:5px;cursor:pointer;">
              <input type="radio" name="language" value="Bilingual" id="languageBilingual">
              <span>Bilingual</span>
            </label>
          </div>
        </div>
        <div class="row-item"><span class="label">Notes:</span><textarea id="notesTextarea" class="form-input" rows="4" placeholder="Write your notes here...">${escapeHtml(row.notes || '')}</textarea></div>
        <div class="row-item"><span class="label">Timestamp:</span><span id="timestamp">${escapeHtml(row['Timestamp'] || '-')}</span></div>
    </div>
  `;

    const select = document.getElementById('dispositionSelect');
    select.value = (row['DISPOSITION'] || '');
    select.addEventListener('change', handleDispositionChange);

    const callbackSection = document.getElementById('callback-section');
    const specialDispositions = ['Callback', 'FUTURE', 'ND/SD'];

    if (specialDispositions.includes(row.DISPOSITION)) {
        callbackSection.style.display = 'grid';
        if (row.callback) {
            const [date, time] = row.callback.split('T');
            document.getElementById('callbackDate').value = date;
            document.getElementById('callbackTime').value = time.substring(0, 5);
        }
    } else {
        callbackSection.style.display = 'none';
    }

    // Pre-select language if saved
    if (row.language === 'English') {
        document.getElementById('languageEnglish').checked = true;
    } else if (row.language === 'Spanish') {
        document.getElementById('languageSpanish').checked = true;
    } else if (row.language === 'Bilingual') {
        document.getElementById('languageBilingual').checked = true;
    }

    if (window.feather) feather.replace();
}

function handleDispositionChange() {
    const select = document.getElementById('dispositionSelect');
    const callbackSection = document.getElementById('callback-section');
    const disposition = select.value;
    const specialDispositions = ['Callback', 'FUTURE', 'ND/SD'];

    if (specialDispositions.includes(disposition)) {
        callbackSection.style.display = 'grid';
    } else {
        callbackSection.style.display = 'none';
    }

    saveDisposition();

    if (!specialDispositions.includes(disposition)) {
        const autoNext = document.getElementById('autoNextCheckbox');
        if (autoNext && autoNext.checked) {
            // Validate language selection before auto-advancing
            const selectedLanguage = document.querySelector('input[name="language"]:checked');
            if (!selectedLanguage) {
                showToast('Please select a language (English or Spanish) before advancing', 'error');
                return;
            }

            const currentData = state.isFilterActive ? state.filteredData : state.data;
            if (state.currentIndex < currentData.length - 1) setTimeout(() => nextRow(), 300);
        }
    }
}

function saveDisposition() {
    const select = document.getElementById('dispositionSelect');
    if (!select) return;

    const currentData = state.isFilterActive ? state.filteredData : state.data;
    const entry = currentData[state.currentIndex];
    if (!entry) return;

    const originalIndex = entry._id;
    if (originalIndex === undefined) return;

    const disposition = select.value;
    const notes = document.getElementById('notesTextarea').value;
    const callbackDate = document.getElementById('callbackDate').value;
    const callbackTime = document.getElementById('callbackTime').value;
    const selectedLanguage = document.querySelector('input[name="language"]:checked');
    const language = selectedLanguage ? selectedLanguage.value : null;

    let callback = null;
    const specialDispositions = ['Callback', 'FUTURE', 'ND/SD'];

    if (specialDispositions.includes(disposition) && callbackDate && callbackTime) {
        callback = `${callbackDate}T${callbackTime}`;
    }

    const updatedRow = {
        DISPOSITION: disposition,
        Timestamp: new Date().toISOString(),
        notes: notes,
        callback: callback,
        language: language
    };

    Object.assign(state.data.find(d => d._id === originalIndex), updatedRow);

    document.getElementById('timestamp').textContent = updatedRow.Timestamp;

    const row = state.data.find(d => d._id === originalIndex);
    const key = `${row.Name || 'unknown'}_${row.Phone || 'unknown'}`;
    const histEntry = { key, name: row.Name || '(No name)', address: row.Address || '(No address)', phone: row.Phone || '(No phone)', disposition, timestamp: updatedRow.Timestamp, rowNumber: state.currentIndex + 1, currentSession: true };

    const exIdx = state.historyLog.findIndex(h => h.key === key);

    if (disposition) {
        if (exIdx !== -1) {
            const prevDisp = state.historyLog[exIdx].disposition;
            if (prevDisp !== disposition) {
                if (state.sessionDispositions[prevDisp]) state.sessionDispositions[prevDisp]--;
                state.sessionDispositions[disposition] = (state.sessionDispositions[disposition] || 0) + 1;
            }
        } else {
            state.sessionDispositions[disposition] = (state.sessionDispositions[disposition] || 0) + 1;
        }
    }

    if (exIdx !== -1) state.historyLog[exIdx] = histEntry;
    else state.historyLog.push(histEntry);

    localStorage.setItem(`userData_${state.currentUser.id}`, JSON.stringify({ history: state.historyLog, dispositions: state.sessionDispositions }));

    state.lastSavedIndex = state.currentIndex;
    updateHistory();
    updateCounters();
    updateStatsOnBackend();
    saveProgressOnBackend(state.currentIndex, updatedRow, originalIndex);

    if (disposition && !state.availableDispositions.includes(disposition)) {
        // If a new disposition appears, refresh all filters to ensure consistency
        extractFilterData();
    }

    if (state.isFilterActive) updateFilteredContactsList();

    loadCallbacks();
}

async function updateStatsOnBackend() {
    try {
        await fetchWithAuth(`${CONFIG.API_BASE_URL}/agent/stats`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ stats: state.sessionDispositions })
        });
    } catch (err) {
        console.error('Error updating stats on backend:', err);
    }
}

async function saveProgressOnBackend(currentIndex, updatedRow, originalIndex) {
    try {
        await fetchWithAuth(`${CONFIG.API_BASE_URL}/agent/progress`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ currentIndex, updatedRow, originalIndex })
        });
    } catch (err) {
        console.error('Error saving progress on backend:', err);
    }
}

function nextRow() {
    // Validate language selection before advancing
    const selectedLanguage = document.querySelector('input[name="language"]:checked');
    if (!selectedLanguage) {
        showToast('Please select a language (English or Spanish) before advancing', 'error');
        return;
    }

    saveDisposition();
    const currentData = state.isFilterActive ? state.filteredData : state.data;
    if (state.currentIndex < currentData.length - 1) {
        state.currentIndex++;
        showRow(state.currentIndex);
        updateCurrentPosition();
        const autoCall = document.getElementById('autoCallCheckbox');
        if (autoCall && autoCall.checked) {
            setTimeout(() => {
                const link = document.getElementById('phoneLink');
                if (link) link.click();
            }, 500);
        }
    } else {
        showToast('End of list.');
    }
}

function prevRow() {
    saveDisposition();
    if (state.currentIndex > 0) {
        state.currentIndex--;
        showRow(state.currentIndex);
        updateCurrentPosition();
    } else {
        showToast('You are at the first row.');
    }
}

function goToRow() {
    const val = parseInt(document.getElementById('rowInput').value);
    const currentData = state.isFilterActive ? state.filteredData : state.data;
    if (isNaN(val) || val < 1 || val > currentData.length) {
        showToast(`Please enter a valid number between 1 and ${currentData.length}`);
        return;
    }
    saveDisposition();
    state.currentIndex = val - 1;
    showRow(state.currentIndex);
    updateCurrentPosition();
}

function updateCurrentPosition() {
    const el = document.getElementById('currentPosition');
    if (!el) return;
    const currentData = state.isFilterActive ? state.filteredData : state.data;
    el.textContent = `Contact ${state.currentIndex + 1} of ${currentData.length}`;
}

function updateHistory() {
    const h = document.getElementById('history');
    if (!h) return;
    if (!state.historyLog.length) {
        h.innerHTML = 'No records yet.';
        return;
    }
    const sorted = [...state.historyLog].reverse();
    h.innerHTML = sorted.map(hc => `
    <div class="history-entry" style="${hc.currentSession ? 'border-left:3px solid var(--accent);padding-left:8px;background:rgba(59,130,246,0.06);' : ''}">
      <strong>${escapeHtml(hc.name)}</strong><br>${escapeHtml(hc.address)}<br>📞 ${escapeHtml(hc.phone)}<br>🟦 ${escapeHtml(hc.disposition)} <small>(${escapeHtml(hc.timestamp)})</small>${hc.rowNumber ? `<br><small style="color:var(--accent);">Row: ${hc.rowNumber}</small>` : ''}${hc.currentSession ? `<br><small style="color:var(--accent);">✓ Current session</small>` : ''}
    </div>`).join('');
    if (window.feather) feather.replace();
}

function updateCounters() {
    const c = document.getElementById('counters');
    if (!c) return;
    const noAnswerDispositions = ['NA', 'VM', 'DC'];
    let totalNoAnswer = 0;
    noAnswerDispositions.forEach(d => { if (state.sessionDispositions[d]) totalNoAnswer += state.sessionDispositions[d]; });
    const totalSession = Object.values(state.sessionDispositions).reduce((s, v) => s + (v || 0), 0);
    const noAnswerPercentage = totalSession > 0 ? ((totalNoAnswer / totalSession) * 100).toFixed(1) : 0;
    c.innerHTML = `
    <div class="percentage-container">
      <div class="counter-row"><span class="counter-label">No answer (NA, VM, DC):</span><span class="counter-value">${noAnswerPercentage}%</span></div>
      <div class="counter-row"><span class="counter-label">Total in session:</span><span class="counter-value">${totalSession}</span></div>
      <div class="counter-row"><span class="counter-label">No answer:</span><span class="counter-value">${totalNoAnswer}</span></div>
    </div>`;
}

function loadCallbacks() {

    // I will just implement the fetch here.
    fetchCallbacks();
}

async function fetchCallbacks() {
    try {
        const resp = await fetchWithAuth(`${CONFIG.API_BASE_URL}/agent/callbacks`);
        if (!resp.ok) return;
        const callbacks = await resp.json();
        const list = document.getElementById('callbacksList');
        if (!list) return;

        if (!callbacks.length) {
            list.innerHTML = '<p style="text-align:center;color:var(--subtext);">No pending callbacks.</p>';
            return;
        }

        list.innerHTML = callbacks.map(cb => `
      <div class="history-entry" style="border-left: 3px solid var(--warning);">
        <div style="display:flex;justify-content:space-between;">
          <strong>${escapeHtml(cb.Name)}</strong>
          <small>${new Date(cb.callback).toLocaleString()}</small>
        </div>
        <div style="margin-top:4px;">📞 <a href="${phoneTelHref(cb.Phone)}">${escapeHtml(cb.Phone)}</a></div>
        ${cb.notes ? `<div style="margin-top:4px;font-style:italic;color:var(--subtext);">${escapeHtml(cb.notes)}</div>` : ''}
      </div>
    `).join('');
        if (window.feather) feather.replace();
    } catch (err) {
        console.error('Error loading callbacks:', err);
    }
}

async function exportCallbacks() {
    try {
        const resp = await fetchWithAuth(`${CONFIG.API_BASE_URL}/agent/callbacks`);
        if (!resp.ok) { showToast('Error exporting callbacks.'); return; }
        const callbacks = await resp.json();
        if (!callbacks.length) { showToast('No callbacks to export.'); return; }
        const dataToExport = callbacks.map(cb => ({ Name: cb.Name || '', Phone: cb.Phone || '', Callback: cb.callback ? new Date(cb.callback).toLocaleString() : '', Notes: cb.notes || '' }));
        if (window.XLSX) {
            const worksheet = XLSX.utils.json_to_sheet(dataToExport);
            const workbook = XLSX.utils.book_new();
            XLSX.utils.book_append_sheet(workbook, worksheet, "Callbacks");
            const fecha = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
            XLSX.writeFile(workbook, `callbacks_${fecha}.xlsx`);
        } else {
            showToast("XLSX library not loaded", "error");
        }
    } catch (err) { showToast('Connection error'); }
}

async function showHistory(leadId) {
    try {
        const resp = await fetchWithAuth(`${CONFIG.API_BASE_URL}/agent/leads/${leadId}/history`);
        if (!resp.ok) { showToast('Error fetching history'); return; }
        const history = await resp.json();
        const list = document.getElementById('leadHistoryList');
        if (!history.length) {
            list.innerHTML = '<p style="text-align:center;color:var(--subtext);">No history available</p>';
        } else {
            list.innerHTML = history.map(h => `
          <div class="history-entry">
            <strong>${escapeHtml(h.action)}</strong>
            <div style="font-size:0.9em;margin-top:4px;">Disposition: ${escapeHtml(h.disposition || 'N/A')}</div>
            ${h.note ? `<div style="font-size:0.9em;margin-top:4px;color:var(--text);">${escapeHtml(h.note)}</div>` : ''}
            <small style="display:block;margin-top:8px;">${new Date(h.timestamp).toLocaleString()}</small>
          </div>`).join('');
        }
        document.getElementById('leadHistoryModal').style.display = 'flex';
        if (window.feather) feather.replace();
    } catch (err) { showToast('Connection error'); }
}

function exportSummaryTXT() {
    let text = state.isFilterActive ? 'DISPOSITION Summary (Filtered Contacts)\n\n' : 'DISPOSITION Summary (Current Session)\n\n';
    if (!Object.keys(state.sessionDispositions).length) {
        text += 'No dispositions recorded in this session.\n';
    } else {
        for (const [k, v] of Object.entries(state.sessionDispositions)) text += `${k}: ${v}\n`;
        const noAnswerDispositions = ['NA', 'VM', 'DC'];
        let totalNoAnswer = 0;
        noAnswerDispositions.forEach(d => { if (state.sessionDispositions[d]) totalNoAnswer += state.sessionDispositions[d]; });
        const totalSession = Object.values(state.sessionDispositions).reduce((s, v) => s + (v || 0), 0);
        const noAnswerPercentage = totalSession > 0 ? ((totalNoAnswer / totalSession) * 100).toFixed(1) : 0;
        text += `\nNo answer (NA, VM, DC): ${totalNoAnswer} (${noAnswerPercentage}%)`;
        const nonContacts = ['NA', 'VM', 'DC'];
        let totalContacts = 0;
        Object.keys(state.sessionDispositions).forEach(d => { if (!nonContacts.includes(d)) totalContacts += state.sessionDispositions[d]; });
        text += `\nContacts: ${totalContacts}`;
        if (state.isFilterActive) {
            const listVal = document.getElementById('filterList').value;
            const customIdVal = document.getElementById('filterCustomId').value;
            let filterInfo = [];
            if (state.selectedDispositions.length) filterInfo.push(`Dispositions: ${state.selectedDispositions.join(', ')}`);
            if (listVal) filterInfo.push(`List: ${listVal}`);
            if (customIdVal) filterInfo.push(`Custom ID: ${customIdVal}`);

            text += `\n\n--- FILTER APPLIED ---\n${filterInfo.join('\n')}\nContacts shown: ${state.filteredData.length} of ${state.data.length}`;
        }
    }
    const contentEl = document.getElementById('exportSummaryContent');
    contentEl.textContent = text;
    document.getElementById('exportSummaryModal').style.display = 'flex';
}

function clearDispositionData() {
    if (!confirm('Are you sure you want to delete all saved disposition data?')) return;
    state.sessionDispositions = {};
    const userData = JSON.parse(localStorage.getItem(`userData_${state.currentUser.id}`) || '{}');
    userData.dispositions = {};
    localStorage.setItem(`userData_${state.currentUser.id}`, JSON.stringify(userData));
    updateCounters();
    showToast('Disposition data cleared successfully.');
}

function clearHistory() {
    if (!confirm('Are you sure you want to clear the history?')) return;
    state.historyLog = [];
    const userData = JSON.parse(localStorage.getItem(`userData_${state.currentUser.id}`) || '{}');
    userData.history = [];
    localStorage.setItem(`userData_${state.currentUser.id}`, JSON.stringify(userData));
    updateHistory();
}

function toggleCallbacksPanel() {
    const rightPanel = document.getElementById('rightPanel');
    rightPanel.style.display = 'flex'; // Ensure the panel is visible

    const callbacksList = rightPanel.querySelector('#callbacksList')
    const callbacksSection = callbacksList ? callbacksList.parentElement : null;
    const filterDispositionSection = rightPanel.querySelector('.filter-section'); // This gets the first one
    const filteredContactsList = rightPanel.querySelector('#filteredContactsList');
    const filterContactsSection = filteredContactsList ? filteredContactsList.parentElement : null;

    if (!callbacksSection || !filterDispositionSection || !filterContactsSection) return;

    const isCallbacksVisible = callbacksSection.style.display !== 'none';

    if (isCallbacksVisible && filterDispositionSection.style.display === 'none') {
        // Callbacks are visible, filters are hidden. Show filters, hide callbacks.
        callbacksSection.style.display = 'none';
        filterDispositionSection.style.display = 'block';
        filterContactsSection.style.display = 'block';
    } else {
        // Filters are visible, callbacks are hidden (or all are visible). Show callbacks, hide filters.
        callbacksSection.style.display = 'block';
        filterDispositionSection.style.display = 'none';
        filterContactsSection.style.display = 'none';
    }
}

// Global exports
window.goToFilteredContact = goToFilteredContact; 
