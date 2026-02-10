import { CONFIG } from './config.js';
import { state } from './state.js';
import { showToast, showLoader, hideLoader, escapeHtml } from './utils.js';
import { logout, createUser, fetchWithAuth } from './auth.js';

// let allLeadsTable = null; // Removed DataTable
let currentPage = 1;
let itemsPerPage = 50;
let unassignedLeadsTable = null;
let agentChart = null;
let adminLeadsData = [];
let performanceChart = null;

export function initializeAdminHub() {
    document.getElementById('adminRefreshBtn').addEventListener('click', async () => {
        try {
            showToast('Refreshing dashboard...', 'info');
            await Promise.all([
                loadUsersSummary(),
                loadAnalyticsDashboard(),
                loadFilterOptions()
            ]);
            showToast('Dashboard updated', 'success');
        } catch (err) {
            console.error("Refresh failed", err);
            showToast('Failed to refresh', 'error');
        }
    });

    const logoutBtn = document.getElementById('adminLogoutBtn');
    if (logoutBtn) logoutBtn.addEventListener('click', logout);

    const createBtn = document.getElementById('createUserBtn');
    if (createBtn) createBtn.addEventListener('click', createNewUser);

    const saveUserBtn = document.getElementById('saveUserChangesBtn');
    if (saveUserBtn) saveUserBtn.addEventListener('click', handleUpdateUser);

    const closeModalBtn = document.getElementById('closeModalBtn');
    if (closeModalBtn) closeModalBtn.addEventListener('click', closeEditModal);

    // New Admin Listeners
    document.getElementById('saveLeadChangesBtn').addEventListener('click', saveLeadChanges);
    document.getElementById('closeAdminEditModalBtn').addEventListener('click', () => document.getElementById('adminEditLeadModal').style.display = 'none');
    document.getElementById('confirmDeleteDuplicatesBtn').addEventListener('click', confirmDeleteDuplicates);
    document.getElementById('closeDuplicateModalBtn').addEventListener('click', () => document.getElementById('duplicatePreviewModal').style.display = 'none');

    document.getElementById('upload-leads-btn').addEventListener('click', uploadLeads);
    document.getElementById('getAgentStatsBtn').addEventListener('click', getAgentStats);
    document.getElementById('closeProfileModalBtn').addEventListener('click', () => document.getElementById('agentProfileModal').style.display = 'none');

    // Upload Info Modal Listeners
    document.getElementById('upload-info-btn').addEventListener('click', () => {
        document.getElementById('uploadInfoModal').style.display = 'flex';
        feather.replace();
    });
    document.getElementById('closeInfoModalBtn').addEventListener('click', () => {
        document.getElementById('uploadInfoModal').style.display = 'none';
    });


    // Load Initial Data
    loadUsersSummary();
    loadAnalyticsDashboard();
    loadFilterOptions();

    initializeLeadManagement();

    // Set default view
    showAdminView('dashboard');
}

export function showAdminView(viewId) {
    document.querySelectorAll('.admin-view').forEach(el => el.style.display = 'none');
    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));

    const viewEl = document.getElementById(`admin-view-${viewId}`);
    if (viewEl) viewEl.style.display = 'block';

    const navEl = document.getElementById(`nav-${viewId}`);
    if (navEl) navEl.classList.add('active');

    if (viewId === 'dashboard') {
        loadAnalyticsDashboard();
        loadUsersSummary();
        loadFilterOptions();
    } else if (viewId === 'leads') {
        loadFilterOptions();
        loadAllLeads();
    } else if (viewId === 'users') {
        loadUsersSummary();
    }
}

export async function loadUsersSummary() {
    const usersSummaryDiv = document.getElementById('usersSummary');
    if (usersSummaryDiv) showLoader('usersSummary');

    try {
        const users = await getUsersSummary();
        const lastUpdateDiv = document.getElementById('lastUpdate');
        if (lastUpdateDiv) lastUpdateDiv.textContent = `Last update: ${new Date().toLocaleString()}`;

        if (!users.length) {
            usersSummaryDiv.innerHTML = '<p>No users registered.</p>';
            return;
        }
        usersSummaryDiv.innerHTML = users.map(user => {
            const stats = user.stats || {};
            const sinRespuesta = (stats.NA || 0) + (stats.VM || 0) + (stats.DC || 0);
            const leads = (stats.FUTURE || 0) + (stats['ND/SD'] || 0);
            const contactos = Object.keys(stats).reduce((acc, key) => {
                if (key !== 'NA' && key !== 'VM' && key !== 'DC') {
                    return acc + stats[key];
                }
                return acc;
            }, 0);
            const progress = user.progress || { currentIndex: 0, total: 0 };
            const progressPercentage = progress.total > 0 ? (((progress.currentIndex + 1) / progress.total) * 100).toFixed(1) : 0;

            return `
    <div style="background:var(--bg);border:1px solid var(--border);padding:12px;border-radius:8px;">
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <div style="font-weight:700;color:var(--accent);">${escapeHtml(user.username)} ${user.role === 'admin' ? '(Admin)' : ''}</div>
        <small>ID: ${escapeHtml(user.email)}</small>
      </div>
      <div style="margin-top:10px;">
        <div style="font-weight:600;margin-bottom:5px;">Assigned List:</div>
        <div style="font-size:0.9em;color:var(--subtext);">${user.filename ? escapeHtml(user.filename) : 'None'}</div>
      </div>
      <div style="margin-top:10px;">
        <div style="font-weight:600;margin-bottom:5px;">List Progress:</div>
        <div style="background:var(--border);border-radius:4px;overflow:hidden;">
          <div style="background:var(--accent);width:${progressPercentage}%;padding:4px;text-align:center;color:white;font-size:0.8em;">${progressPercentage}%</div>
        </div>
        <div style="text-align:right;font-size:0.8em;color:var(--subtext);">${progress.currentIndex + 1} / ${progress.total}</div>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-top:10px;">
        <div style="background:rgba(239, 68, 68, 0.1);padding:8px;border-radius:6px;text-align:center;"><div style="font-size:1.1em;font-weight:700;color:var(--danger);">${sinRespuesta}</div><div style="color:var(--subtext);font-size:0.9em;">No answer</div></div>
        <div style="background:rgba(16, 185, 129, 0.1);padding:8px;border-radius:6px;text-align:center;"><div style="font-size:1.1em;font-weight:700;color:var(--success);">${contactos}</div><div style="color:var(--subtext);font-size:0.9em;">Contacts</div></div>
        <div style="background:rgba(245, 158, 11, 0.1);padding:8px;border-radius:6px;text-align:center;"><div style="font-size:1.1em;font-weight:700;color:var(--warning);">${leads}</div><div style="color:var(--subtext);font-size:0.9em;">Leads</div></div>
      </div>
      <div style="margin-top:10px;font-size:0.8em;color:var(--subtext);">Last activity: ${new Date(user.lastActivity).toLocaleDateString()}</div>
      <div class="user-card-actions">
        <button class="small-btn" onclick="openAgentProfile('${user.id}', '${escapeHtml(user.username)}')"><i data-feather="bar-chart-2"></i> Profile</button>
        ${user.role !== 'admin' ?
                    `<button class="small-btn secondary" onclick='openEditModal(${JSON.stringify(user)})'><i data-feather="edit"></i> Edit</button>
         <button class="small-btn danger-btn" onclick="handleDeleteUser('${user.id}')"><i data-feather="trash-2"></i> Delete</button>` : ''}
      </div>
    </div>`;
        }).join('');
        if (window.feather) feather.replace();

        // Leaderboard
        const agents = users.filter(u => u.role === 'agent');
        const sortedAgents = agents.sort((a, b) => {
            const statsA = a.stats || {};
            const statsB = b.stats || {};
            const leadsA = (statsA.FUTURE || 0) + (statsA['ND/SD'] || 0);
            const leadsB = (statsB.FUTURE || 0) + (statsB['ND/SD'] || 0);
            return leadsB - leadsA;
        }).slice(0, 3);

        const leaderboardDiv = document.getElementById('leaderboardContainer');
        if (!sortedAgents.length) {
            leaderboardDiv.innerHTML = '<p>No data for leaderboard yet.</p>';
        } else {
            leaderboardDiv.innerHTML = sortedAgents.map((agent, index) => {
                const stats = agent.stats || {};
                const leads = (stats.FUTURE || 0) + (stats['ND/SD'] || 0);
                const medals = ['🥇', '🥈', '🥉'];
                return `
      <div style="background:var(--card);border:1px solid var(--border);padding:16px;border-radius:8px;display:flex;align-items:center;gap:16px;box-shadow:var(--shadow);">
        <div style="font-size:2em;">${medals[index]}</div>
        <div>
          <div style="font-weight:700;font-size:1.1em;color:var(--text);">${escapeHtml(agent.username)}</div>
          <div style="color:var(--accent);font-weight:600;">${leads} Leads</div>
        </div>
      </div>`;
            }).join('');
        }
    } catch (err) {
        console.error('Error loading users summary:', err);
    } finally {
        hideLoader('usersSummary');
    }
}

export async function getUsersSummary() {
    try {
        const resp = await fetchWithAuth(`${CONFIG.API_BASE_URL}/admin/users`);
        if (!resp.ok) return [];
        return await resp.json();
    } catch (err) {
        console.error('Error getting user summary:', err);
        return [];
    }
}

export async function createNewUser() {
    const username = document.getElementById('newUsername').value;
    const password = document.getElementById('newPassword').value;
    const email = document.getElementById('newEmail').value;
    if (!username || !password) {
        showToast('Username and password are required');
        return;
    }
    const result = await createUser({ username, password, email });
    if (result.success) {
        showToast(result.message);
        document.getElementById('newUsername').value = '';
        document.getElementById('newPassword').value = '';
        document.getElementById('newEmail').value = '';
        loadUsersSummary();
    } else {
        showToast('Error: ' + result.error);
    }
}

export function openEditModal(user) {
    document.getElementById('editUserId').value = user.id;
    document.getElementById('editUserUsername').value = user.username;
    document.getElementById('editUserPassword').value = '';
    document.getElementById('editUserEmail').value = user.email;
    document.getElementById('editUserRcExtensionId').value = user.rcExtensionId || '';
    document.getElementById('editUserRole').value = user.role;
    document.getElementById('editUserModal').style.display = 'flex';
    if (window.feather) feather.replace();
}

function closeEditModal() {
    document.getElementById('editUserModal').style.display = 'none';
}

async function handleUpdateUser() {
    const userId = document.getElementById('editUserId').value;
    const username = document.getElementById('editUserUsername').value;
    const password = document.getElementById('editUserPassword').value;
    const email = document.getElementById('editUserEmail').value;
    const rcExtensionId = document.getElementById('editUserRcExtensionId').value;
    const role = document.getElementById('editUserRole').value;

    if (!role || !username) {
        showToast('Username and Role are required');
        return;
    }

    try {
        const resp = await fetchWithAuth(`${CONFIG.API_BASE_URL}/admin/users/${userId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, role, username, password, rcExtensionId })
        });

        const result = await resp.json();
        if (resp.ok && result.success) {
            showToast(result.message);
            closeEditModal();
            loadUsersSummary();
        } else {
            showToast(`Error: ${result.error || 'Could not update user.'}`);
        }
    } catch (err) {
        showToast('Connection error while updating user.');
    }
}

export async function handleDeleteUser(userId) {
    if (!confirm(`Are you sure you want to delete user with ID ${userId}? This action cannot be undone.`)) {
        return;
    }
    try {
        const resp = await fetchWithAuth(`${CONFIG.API_BASE_URL}/admin/users/${userId}`, { method: 'DELETE' });
        const result = await resp.json();
        if (resp.ok && result.success) {
            showToast(result.message);
            loadUsersSummary();
        } else {
            showToast(`Error: ${result.error || 'Could not delete user.'}`);
        }
    } catch (err) {
        showToast('Connection error while deleting user.');
    }
}

function initializeLeadManagement() {
    const filterBtn = document.getElementById('filter-leads-btn');
    if (filterBtn) {
        filterBtn.onclick = () => loadAllLeads(1);
    }
    document.getElementById('reassign-selected-leads-btn').addEventListener('click', reassignSelectedLeads);

    document.getElementById('deduplicate-leads-btn').addEventListener('click', () => {
        document.getElementById('deleteOptionsModal').style.display = 'flex';
        feather.replace();
    });
    document.getElementById('closeDeleteOptionsModalBtn').addEventListener('click', () => {
        document.getElementById('deleteOptionsModal').style.display = 'none';
    });
    document.getElementById('btnDeleteDuplicates').addEventListener('click', () => {
        document.getElementById('deleteOptionsModal').style.display = 'none';
        handleDeduplicateLeads();
    });
    document.getElementById('btnDeleteSelected').addEventListener('click', () => {
        document.getElementById('deleteOptionsModal').style.display = 'none';
        deleteSelectedLeads();
    });

    const dropdownContent = document.getElementById('disposition-dropdown-content');
    const dropdownBtn = document.getElementById('disposition-dropdown-btn');
    const dropdownBtnText = dropdownBtn.querySelector('span');

    dropdownBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        document.getElementById('disposition-dropdown-content').classList.toggle('show');
    });

    document.addEventListener('click', (e) => {
        if (!e.target.closest('.custom-dropdown')) {
            document.getElementById('disposition-dropdown-content').classList.remove('show');
        }
    });

    dropdownContent.addEventListener('change', () => {
        const selected = Array.from(document.querySelectorAll('.disposition-checkbox:checked')).map(cb => cb.value);
        if (selected.length === 0) {
            dropdownBtnText.textContent = 'All Dispositions';
        } else if (selected.length === 1) {
            dropdownBtnText.textContent = selected[0];
        } else {
            dropdownBtnText.textContent = `${selected.length} Selected`;
        }
    });

    document.getElementById('add-custom-list-btn').addEventListener('click', () => {
        const newListName = prompt("Enter the name for the new list:");
        if (newListName && newListName.trim() !== "") {
            const uploadSelect = document.getElementById('upload-list-name');
            const filterSelect = document.getElementById('lead-filter-list');
            const name = newListName.trim();

            const optUpload = document.createElement('option');
            optUpload.value = name;
            optUpload.textContent = name;
            optUpload.selected = true;
            uploadSelect.appendChild(optUpload);

            if (!Array.from(filterSelect.options).some(o => o.value === name)) {
                const optFilter = document.createElement('option');
                optFilter.value = name;
                optFilter.textContent = name;
                filterSelect.appendChild(optFilter);
            }
            showToast(`Custom list '${name}' added.`, 'success');
        }
    });
}

export async function loadFilterOptions() {
    try {
        const respOptions = await fetchWithAuth(`${CONFIG.API_BASE_URL}/admin/filters/options`);
        const data = await respOptions.json();
        const users = await getUsersSummary();
        const agentUsers = users.filter(u => u.role === 'agent');

        const productSelect = document.getElementById('lead-filter-product');
        const companySelect = document.getElementById('lead-filter-prev-company');
        const customIdSelect = document.getElementById('lead-filter-custom-id');
        const uploadListSelect = document.getElementById('upload-list-name');
        const filterListSelect = document.getElementById('lead-filter-list');
        const agentFilterSelect = document.getElementById('lead-filter-agent');
        const reassignAgentSelect = document.getElementById('reassign-lead-agent');

        const clearOptions = (select) => { while (select.options.length > 1) { select.remove(1); } };
        clearOptions(productSelect);
        clearOptions(companySelect);
        clearOptions(customIdSelect);
        clearOptions(filterListSelect);
        clearOptions(agentFilterSelect);
        agentFilterSelect.insertAdjacentHTML('beforeend', '<option value="unassigned">Unassigned</option>');
        reassignAgentSelect.innerHTML = `<option value="unassigned">Unassign (Back to Pool)</option>`;

        // Ensure Rows Per Page has a default listener if not already set
        const rowsPerPageSelect = document.getElementById('lead-rows-per-page');
        if (rowsPerPageSelect) {
            let previousValue = rowsPerPageSelect.value;
            rowsPerPageSelect.addEventListener('focus', () => { previousValue = rowsPerPageSelect.value; });

            rowsPerPageSelect.onchange = () => {
                const val = rowsPerPageSelect.value;
                if (val === 'custom') {
                    // Show Custom Rows Modal
                    const modal = document.getElementById('customRowsModal');
                    const input = document.getElementById('customRowsInput');
                    const confirmBtn = document.getElementById('btnConfirmCustomRows');
                    const cancelBtn = document.getElementById('btnCloseCustomRowsModal');

                    if (!modal) {
                        // Fallback just in case
                        console.error("Custom Rows Modal not found");
                        rowsPerPageSelect.value = previousValue;
                        return;
                    }

                    modal.style.display = 'flex';
                    input.value = '';
                    input.focus();

                    if (window.feather) feather.replace();

                    const cleanup = () => {
                        modal.style.display = 'none';
                        confirmBtn.removeEventListener('click', onConfirm);
                        cancelBtn.removeEventListener('click', onCancel);
                        // If no value was confirmed, revert to previous
                        if (rowsPerPageSelect.value === 'custom') {
                            rowsPerPageSelect.value = previousValue;
                        }
                    };

                    const onConfirm = () => {
                        const numStr = input.value;
                        if (!numStr) {
                            showToast("Please enter a number.", 'error');
                            return;
                        }
                        const num = parseInt(numStr);
                        if (isNaN(num) || num <= 0 || num > 5000) {
                            showToast("Please enter a valid number between 1 and 5000.", 'error');
                            return;
                        }

                        // Check if option already exists
                        let opt = Array.from(rowsPerPageSelect.options).find(o => o.value === String(num));
                        if (!opt) {
                            opt = document.createElement('option');
                            opt.value = num;
                            opt.textContent = num;
                            // Insert before 'Custom'
                            rowsPerPageSelect.insertBefore(opt, rowsPerPageSelect.querySelector('option[value="custom"]'));
                        }
                        rowsPerPageSelect.value = num;
                        previousValue = num; // Update previous value

                        // Clean up and load leads
                        modal.style.display = 'none';
                        confirmBtn.removeEventListener('click', onConfirm);
                        cancelBtn.removeEventListener('click', onCancel);

                        loadAllLeads(1);
                    };

                    const onCancel = () => {
                        cleanup();
                        // Revert is handled in cleanup if value is still custom, but cleaner to do explicitly
                        rowsPerPageSelect.value = previousValue;
                    };

                    confirmBtn.addEventListener('click', onConfirm);
                    cancelBtn.addEventListener('click', onCancel);

                    // Enter key support
                    input.onkeydown = (e) => {
                        if (e.key === 'Enter') onConfirm();
                        if (e.key === 'Escape') onCancel();
                    };

                } else {
                    previousValue = val;
                    loadAllLeads(1);
                }
            };
        }

        if (agentUsers && agentUsers.length) {
            const agentOpts = agentUsers.map(user => `<option value="${user.id}">${user.username} - ${user.email || 'No ID'}</option>`).join('');
            agentFilterSelect.insertAdjacentHTML('beforeend', agentOpts);
            reassignAgentSelect.insertAdjacentHTML('beforeend', agentOpts);
        }

        if (data.products) data.products.forEach(p => { const opt = document.createElement('option'); opt.value = p; opt.textContent = p; productSelect.appendChild(opt); });
        if (data.companies) data.companies.forEach(c => { const opt = document.createElement('option'); opt.value = c; opt.textContent = c; companySelect.appendChild(opt); });
        if (data.customIds) data.customIds.forEach(id => { const opt = document.createElement('option'); opt.value = id; opt.textContent = id; customIdSelect.appendChild(opt); });

        const uploadExistingOptions = Array.from(uploadListSelect.options).map(o => o.value);
        if (data.listNames) {
            data.listNames.forEach(name => {
                if (!uploadExistingOptions.includes(name)) {
                    const opt = document.createElement('option'); opt.value = name; opt.textContent = name; uploadListSelect.appendChild(opt);
                }
                const opt = document.createElement('option'); opt.value = name; opt.textContent = name; filterListSelect.appendChild(opt);
            });
        }

        const dispositions = data.dispositions || [];
        const uniqueDispos = [...new Set(['Sale', ...dispositions])].filter(d => d && d !== 'N/A');
        const allDispositions = ['N/A', ...uniqueDispos.sort()];
        const dropdownContent = document.getElementById('disposition-dropdown-content');
        dropdownContent.innerHTML = allDispositions.map(d => `
      <div class="dropdown-item">
        <input type="checkbox" id="dispo-${d}" value="${d}" class="disposition-checkbox">
        <label for="dispo-${d}">${d}</label>
      </div>`).join('');

        // Populate Language Filter
        const languageSelect = document.getElementById('lead-filter-language');
        if (languageSelect) {
            const currentLanguage = languageSelect.value;
            languageSelect.innerHTML = '<option value="">All Languages</option>';
            if (data.languages && data.languages.length) {
                data.languages.forEach(l => {
                    const opt = document.createElement('option');
                    opt.value = l;
                    opt.textContent = l;
                    languageSelect.appendChild(opt);
                });
            }
            languageSelect.value = currentLanguage; // Restore selection
        }
    } catch (err) {
        console.error('Error fetching filter options:', err);
    }
}

export async function loadAllLeads(page = 1) {
    currentPage = page;
    const selectedDispositions = Array.from(document.querySelectorAll('.disposition-checkbox:checked')).map(cb => cb.value);
    const agentId = document.getElementById('lead-filter-agent').value;
    const product = document.getElementById('lead-filter-product').value;
    const listName = document.getElementById('lead-filter-list').value;
    const prevCompany = document.getElementById('lead-filter-prev-company').value;
    const sortOrder = document.getElementById('lead-sort-order').value;
    const startDate = document.getElementById('lead-filter-start-date').value;
    const endDate = document.getElementById('lead-filter-end-date').value;
    const search = document.getElementById('lead-filter-search').value;
    const customId = document.getElementById('lead-filter-custom-id').value;
    const language = document.getElementById('lead-filter-language').value;

    let queryString = new URLSearchParams();
    if (selectedDispositions.length > 0) selectedDispositions.forEach(d => queryString.append('disposition', d));
    if (agentId) queryString.append('assignedTo', agentId);
    if (product) queryString.append('product', product);
    if (listName) queryString.append('listName', listName);
    if (prevCompany) queryString.append('prevCompany', prevCompany);
    if (startDate) queryString.append('startDate', startDate);
    if (endDate) queryString.append('endDate', endDate);
    if (search) queryString.append('search', search);
    if (customId) queryString.append('customId', customId);
    if (language) queryString.append('language', language);
    queryString.append('sortBy', 'date');
    queryString.append('sortOrder', sortOrder);

    // Pagination params
    queryString.append('page', currentPage);
    // Pagination params
    itemsPerPage = parseInt(document.getElementById('lead-rows-per-page').value) || 50;
    queryString.append('page', currentPage);
    queryString.append('limit', itemsPerPage);

    showLoader('all-leads-container');

    try {
        const resp = await fetchWithAuth(`${CONFIG.API_BASE_URL}/admin/leads?${queryString.toString()}`);
        if (!resp.ok) {
            showToast('Error loading leads');
            return;
        }

        const responseData = await resp.json();
        const leads = responseData.leads;
        adminLeadsData = leads; // Update global data for modals

        const list = document.getElementById('all-leads-list');
        list.innerHTML = '';

        if (!leads || !leads.length) {
            list.innerHTML = '<p style="text-align:center;color:var(--subtext);">No leads match the current filters.</p>';
            renderPagination(0, 1, 1); // Reset pagination
            return;
        }

        // Render Table Manually
        let tableHtml = `
        <div style="overflow-x:auto;">
        <table id="all-leads-table" style="width:100%; border-collapse: collapse;">
            <thead>
                <tr style="background:var(--card); text-align:left; border-bottom: 2px solid var(--border);">
                    <th style="padding:10px;"><input type="checkbox" id="select-all-filtered-leads"></th>
                    <th style="padding:10px;">List</th>
                    <th style="padding:10px;">Name</th>
                    <th style="padding:10px;">Phone</th>
                    <th style="padding:10px;">Disposition</th>
                    <th style="padding:10px;">Callback Date</th>
                    <th style="padding:10px;">Agent</th>
                    <th style="padding:10px;">Language</th>
                    <th style="padding:10px;">Product</th>
                    <th style="padding:10px;">Last Modified</th>
                    <th style="padding:10px;">Actions</th>
                </tr>
            </thead>
            <tbody>
        `;

        leads.forEach(lead => {
            tableHtml += `
            <tr style="border-bottom:1px solid var(--border);">
                <td style="padding:10px;"><input type="checkbox" class="filtered-lead-checkbox" value="${lead._id}"></td>
                <td style="padding:10px;">${escapeHtml(lead.listName || 'N/A')}</td>
                <td style="padding:10px;">${escapeHtml(lead.Name || 'No Name')}</td>
                <td style="padding:10px;">${escapeHtml(lead.Phone || 'No Phone')}</td>
                <td style="padding:10px;">${escapeHtml(lead.DISPOSITION || 'N/A')}</td>
                <td style="padding:10px;">${lead.callbackDate ? new Date(lead.callbackDate).toLocaleString() : 'N/A'}</td>
                <td style="padding:10px;">${lead.agent ? escapeHtml(lead.agent.username) : 'Unassigned'}</td>
                <td style="padding:10px;">${escapeHtml(lead.language || 'N/A')}</td>
                <td style="padding:10px;">${escapeHtml(lead.Product || 'N/A')}</td>
                <td style="padding:10px;">${lead.Timestamp ? new Date(lead.Timestamp).toLocaleString() : 'N/A'}</td>
                <td style="padding:10px;">
                    <div style="display:flex; gap:5px;">
                         <button class="small-btn" style="padding: 4px 8px; font-size: 0.75rem; color: var(--success); border-color: var(--success);" onclick="markAsSale('${lead._id}')" title="Mark as Sale">
                           <i data-feather="dollar-sign" style="width: 12px; height: 12px;"></i>
                         </button>
                         <button class="small-btn secondary" style="padding: 4px 8px; font-size: 0.75rem;" onclick="openAdminEditLeadModal('${lead._id}')" title="Edit Lead">
                           <i data-feather="edit-2" style="width: 12px; height: 12px;"></i>
                         </button>
                    </div>
                </td>
            </tr>`;
        });

        tableHtml += '</tbody></table></div>';

        // Append Pagination Controls Container
        tableHtml += `<div id="pagination-container" style="display:flex; justify-content:center; align-items:center; margin-top:20px; gap:15px;"></div>`;

        list.innerHTML = tableHtml;

        // Render Pagination Controls
        renderPagination(responseData.total, responseData.page, responseData.totalPages);

        if (window.feather) feather.replace();

        document.getElementById('select-all-filtered-leads').addEventListener('change', (e) => {
            document.querySelectorAll('.filtered-lead-checkbox').forEach(checkbox => { checkbox.checked = e.target.checked; });
        });

    } catch (err) {
        console.error('Error loading all leads:', err);
        showToast('Connection error while loading leads.');
    } finally {
        hideLoader('all-leads-container');
    }
}

function renderPagination(totalItems, currentPage, totalPages) {
    const container = document.getElementById('pagination-container');
    if (!container) return;

    if (totalItems === 0) {
        container.innerHTML = '';
        return;
    }

    let controlsHtml = `
        <button id="prev-page-btn" class="small-btn secondary" ${currentPage <= 1 ? 'disabled' : ''} style="opacity: ${currentPage <= 1 ? 0.5 : 1}">Previous</button>
        <span style="color:var(--text);">Page <strong>${currentPage}</strong> of ${totalPages} (${totalItems} items)</span>
        <button id="next-page-btn" class="small-btn secondary" ${currentPage >= totalPages ? 'disabled' : ''} style="opacity: ${currentPage >= totalPages ? 0.5 : 1}">Next</button>
    `;

    container.innerHTML = controlsHtml;

    document.getElementById('prev-page-btn').onclick = () => {
        if (currentPage > 1) loadAllLeads(currentPage - 1);
    };

    document.getElementById('next-page-btn').onclick = () => {
        if (currentPage < totalPages) loadAllLeads(currentPage + 1);
    };
}

export async function markAsSale(leadId) {
    if (!confirm('Are you sure you want to mark this lead as a Sale?')) return;
    try {
        const resp = await fetchWithAuth(`${CONFIG.API_BASE_URL}/admin/leads/${leadId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ DISPOSITION: 'Sale' })
        });
        const result = await resp.json();
        if (resp.ok && result.success) {
            showToast('Lead marked as Sale successfully', 'success');
            loadAllLeads();
        } else {
            showToast(`Error: ${result.error || 'Could not update lead'}`, 'error');
        }
    } catch (err) {
        showToast('Connection error while updating lead', 'error');
    }
}

export function openAdminEditLeadModal(leadId) {
    const lead = adminLeadsData.find(l => l._id === leadId);
    if (!lead) {
        showToast('Lead not found');
        return;
    }
    document.getElementById('editLeadId').value = lead._id;
    document.getElementById('editLeadName').value = lead.Name || '';
    document.getElementById('editLeadPhone').value = lead.Phone || '';
    document.getElementById('editLeadEmail').value = lead.Email || '';
    document.getElementById('editLeadProduct').value = lead.Product || '';
    document.getElementById('editLeadDisposition').value = lead.DISPOSITION || '';
    document.getElementById('editLeadPrevCompany').value = lead['Prev. Company'] || '';
    document.getElementById('editLeadListName').value = lead.listName || '';
    document.getElementById('editLeadAddress').value = lead.Address || '';

    const historyList = document.getElementById('adminLeadHistoryList');
    if (lead.history && lead.history.length > 0) {
        historyList.innerHTML = lead.history.slice().reverse().map(h => `
      <div style="border-bottom:1px solid var(--border); padding: 8px 0;">
        <div style="display:flex; justify-content:space-between; font-size:0.85em; color:var(--subtext);">
          <span>${new Date(h.timestamp).toLocaleString()}</span>
          <strong>${escapeHtml(h.disposition)}</strong>
        </div>
        <div style="font-size:0.9em; margin-top:2px;">${escapeHtml(h.note || h.action)}</div>
      </div>`).join('');
    } else {
        historyList.innerHTML = '<p style="text-align:center; color:var(--subtext);">No history available</p>';
    }
    document.getElementById('adminEditLeadModal').style.display = 'flex';
}

async function saveLeadChanges() {
    const id = document.getElementById('editLeadId').value;
    const Name = document.getElementById('editLeadName').value;
    const Phone = document.getElementById('editLeadPhone').value;
    const Email = document.getElementById('editLeadEmail').value;
    const Product = document.getElementById('editLeadProduct').value;
    const DISPOSITION = document.getElementById('editLeadDisposition').value;
    const prevCompany = document.getElementById('editLeadPrevCompany').value;
    const listName = document.getElementById('editLeadListName').value;
    const Address = document.getElementById('editLeadAddress').value;

    try {
        const resp = await fetchWithAuth(`${CONFIG.API_BASE_URL}/admin/leads/${id}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ Name, Phone, Email, Product, DISPOSITION, 'Prev. Company': prevCompany, listName, Address })
        });
        const result = await resp.json();
        if (resp.ok && result.success) {
            showToast('Lead updated successfully', 'success');
            document.getElementById('adminEditLeadModal').style.display = 'none';
            loadAllLeads();
        } else {
            showToast(`Error: ${result.error || 'Update failed'}`);
        }
    } catch (err) {
        showToast('Connection error');
    }
}

export async function reassignSelectedLeads() {
    const newUserId = document.getElementById('reassign-lead-agent').value;
    const selectedLeads = Array.from(document.querySelectorAll('.filtered-lead-checkbox:checked')).map(cb => cb.value);
    if (!newUserId) { showToast('Please select an agent to reassign the leads to.'); return; }
    if (!selectedLeads.length) { showToast('Please select at least one lead to reassign.'); return; }

    const action = newUserId === 'unassigned' ? 'unassign' : 'reassign';
    if (!confirm(`You are about to ${action} ${selectedLeads.length} leads. Are you sure?`)) return;

    try {
        const resp = await fetchWithAuth(`${CONFIG.API_BASE_URL}/admin/leads/reassign`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ leadIds: selectedLeads, newUserId })
        });
        const result = await resp.json();
        if (resp.ok && result.success) {
            showToast(result.message);
            loadAllLeads(); loadUsersSummary();
        } else {
            showToast(`Error: ${result.error || 'Could not reassign leads.'}`);
        }
    } catch (err) {
        showToast('Connection error while reassigning leads.');
    }
}

async function requestPasswordConfirmation() {
    return new Promise((resolve, reject) => {
        const modal = document.getElementById('passwordConfirmationModal');
        const input = document.getElementById('confirmActionPassword');
        const confirmBtn = document.getElementById('btnConfirmPassword');
        const cancelBtn = document.getElementById('btnClosePasswordModal');
        modal.style.display = 'flex';
        input.value = ''; input.focus();
        const cleanup = () => { modal.style.display = 'none'; confirmBtn.removeEventListener('click', onConfirm); cancelBtn.removeEventListener('click', onCancel); };
        const onConfirm = () => { const password = input.value; if (!password) { showToast('Password is required', 'error'); return; } cleanup(); resolve(password); };
        const onCancel = () => { cleanup(); reject(new Error('Password confirmation cancelled')); };
        confirmBtn.addEventListener('click', onConfirm);
        cancelBtn.addEventListener('click', onCancel);
    });
}

export async function deleteSelectedLeads() {
    const selectedLeads = Array.from(document.querySelectorAll('.filtered-lead-checkbox:checked')).map(cb => cb.value);
    if (!selectedLeads.length) { showToast('Please select at least one lead to delete.', 'error'); return; }
    if (!confirm(`Are you sure you want to PERMANENTLY DELETE ${selectedLeads.length} leads?`)) return;
    try {
        const password = await requestPasswordConfirmation();
        const resp = await fetchWithAuth(`${CONFIG.API_BASE_URL}/admin/leads/bulk`, {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ leadIds: selectedLeads, password })
        });
        const result = await resp.json();
        if (resp.ok && result.success) { showToast(result.message, 'success'); loadAllLeads(); loadUsersSummary(); }
        else { showToast(`Error: ${result.error || 'Delete failed'}`, 'error'); }
    } catch (err) {
        if (err.message !== 'Password confirmation cancelled') showToast('Action cancelled or failed.', 'error');
    }
}

export async function handleDeduplicateLeads() {
    try {
        const resp = await fetchWithAuth(`${CONFIG.API_BASE_URL}/admin/leads/deduplicate/preview`, { method: 'POST' });
        const result = await resp.json();
        if (resp.ok) {
            if (result.count === 0) { showToast("No duplicate leads found.", "success"); return; }
            const list = document.getElementById('duplicatePreviewList');
            document.getElementById('duplicateCountMsg').textContent = `Found ${result.count} duplicate leads to be removed.`;
            list.innerHTML = result.preview.map(item => `
         <div style="padding: 10px; border-bottom: 1px solid var(--border);">
            <div style="font-weight:bold; color:var(--accent);">Phone: ${item.phone}</div>
            <div style="font-size:0.9em; margin-top:5px;"><span style="color:var(--success);">Keep:</span> ${item.kept.Name}</div>
            <div style="font-size:0.9em; margin-top:5px; color:var(--danger);">Delete (${item.removed.length})</div>
         </div>`).join('');
            document.getElementById('duplicatePreviewModal').style.display = 'flex';
        } else { showToast(`Error: ${result.error || 'Could not preview duplicates.'}`, 'error'); }
    } catch (err) { showToast('Connection error.', 'error'); }
}

async function confirmDeleteDuplicates() {
    try {
        const password = await requestPasswordConfirmation();
        const resp = await fetchWithAuth(`${CONFIG.API_BASE_URL}/admin/leads/deduplicate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password })
        });
        const result = await resp.json();
        if (resp.ok && result.success) {
            showToast(result.message, 'success');
            document.getElementById('duplicatePreviewModal').style.display = 'none';
            loadAllLeads(); loadUsersSummary();
        } else { showToast(`Error: ${result.error || 'Could not deduplicate.'}`, 'error'); }
    } catch (err) { if (err.message !== 'Password confirmation cancelled') showToast('Error deduplicating.', 'error'); }
}

async function loadUnassignedLeads() {
    try {
        const resp = await fetchWithAuth(`${CONFIG.API_BASE_URL}/admin/leads/unassigned`);
        if (!resp.ok) return;
        const leads = await resp.json();
        // Implementation for loading into a different table (not used in current view but good to have)
    } catch (err) { }
    // NOTE: This function was in script.js is legacy  
    // 
    // But `uploadLeads` refreshes `loadAllLeads` too.
}

async function uploadLeads() {
    const listName = document.getElementById('upload-list-name').value;
    const customId = document.getElementById('upload-custom-id').value.trim();
    const fileInput = document.getElementById('upload-csv-file');
    const file = fileInput.files[0];
    if (!customId) { showToast('Custom ID is required.', 'error'); return; }
    if (!file) { showToast('Please select a CSV file.'); return; }

    const formData = new FormData();
    formData.append('listName', listName);
    formData.append('customId', customId);
    formData.append('file', file);

    try {
        const resp = await fetchWithAuth(`${CONFIG.API_BASE_URL}/admin/upload`, {
            method: 'POST',
            body: formData
        });
        const result = await resp.json();
        if (resp.ok) {
            showToast(result.message);
            fileInput.value = '';
            loadAllLeads(); loadFilterOptions();
        } else { showToast(`Error: ${result.error || 'Upload failed'}`); }
    } catch (err) { showToast('Connection error while uploading leads.'); }
}

async function loadAnalyticsDashboard() {
    try {
        const resp = await fetchWithAuth(`${CONFIG.API_BASE_URL}/admin/stats`);
        if (!resp.ok) return;
        const stats = await resp.json();

        const totalCalls = Object.values(stats).reduce((a, b) => a + b, 0);
        const nonContactDispos = ['NA', 'VM', 'DC', 'WN'];
        const leadDispos = ['FUTURE', 'ND/SD'];
        const totalContacts = Object.entries(stats).filter(([key]) => !nonContactDispos.includes(key)).reduce((sum, [, value]) => sum + value, 0);
        const totalLeads = Object.entries(stats).filter(([key]) => leadDispos.includes(key)).reduce((sum, [, value]) => sum + value, 0);
        const contactRate = totalCalls > 0 ? ((totalContacts / totalCalls) * 100).toFixed(1) : 0;
        const conversionRate = totalContacts > 0 ? ((totalLeads / totalContacts) * 100).toFixed(1) : 0;

        document.getElementById('globalTotalCalls').textContent = totalCalls;
        document.getElementById('globalContactRate').textContent = `${contactRate}%`;
        document.getElementById('globalConversionRate').textContent = `${conversionRate}%`;

        const statsList = document.getElementById('dispositionStatsList');
        statsList.innerHTML = '';
        Object.entries(stats).forEach(([disposition, count]) => {
            const card = document.createElement('div'); card.className = 'stat-card';
            card.innerHTML = `<h4 class="stat-title">${disposition}</h4><p class="stat-value">${count}</p>`;
            statsList.appendChild(card);
        });
        loadAgentPerformanceChart();
    } catch (err) { console.error('Error loading analytics dashboard:', err); }
}

async function loadAgentPerformanceChart() {
    try {
        const users = await getUsersSummary();
        const agents = users.filter(u => u.role === 'agent');
        const labels = agents.map(a => a.username);
        const conversionRates = agents.map(a => {
            const stats = a.stats || {};
            const nonContactDispos = ['NA', 'VM', 'DC', 'WN'];
            const leadDispos = ['FUTURE', 'ND/SD'];
            const totalContacts = Object.entries(stats).filter(([key]) => !nonContactDispos.includes(key)).reduce((sum, [, value]) => sum + value, 0);
            const totalLeads = Object.entries(stats).filter(([key]) => leadDispos.includes(key)).reduce((sum, [, value]) => sum + value, 0);
            return totalContacts > 0 ? ((totalLeads / totalContacts) * 100).toFixed(1) : 0;
        });

        const ctx = document.getElementById('agentPerformanceChart').getContext('2d');
        if (performanceChart) performanceChart.destroy();
        performanceChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{ label: 'Conversion Rate (%)', data: conversionRates, backgroundColor: '#651fff' }]
            },
            options: { responsive: true, scales: { y: { beginAtZero: true } } }
        });
    } catch (err) { }
}

// ==========================================
// RINGCENTRAL AGENT ACTIVITY FUNCTIONS
// ==========================================
async function loadRingCentralActivity() {
    const dateInput = document.getElementById('rcDateInput');
    const tableBody = document.getElementById('rcAgentActivityTable');

    if (!dateInput || !tableBody) return;

    // Show loading state
    tableBody.innerHTML = '<tr><td colspan="4" class="muted">Loading...</td></tr>';

    try {
        const date = dateInput.value;
        const url = `${CONFIG.API_BASE_URL}/api/ringcentral/activity${date ? `?date=${date}` : ''}`;

        const response = await fetchWithAuth(url);

        if (!response.ok) {
            const error = await response.json();
            tableBody.innerHTML = `<tr><td colspan="4" style="color: var(--danger); text-align: center;">${error.error || 'Error loading data'}</td></tr>`;
            return;
        }

        const data = await response.json();

        if (data.error) {
            tableBody.innerHTML = `<tr><td colspan="4" style="color: var(--danger); text-align: center;">${data.error}</td></tr>`;
            return;
        }

        if (!data.agents || data.agents.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="4" class="muted">No activity for this date</td></tr>';
            return;
        }

        // Populate table
        tableBody.innerHTML = data.agents.map(agent => `
            <tr>
                <td>${escapeHtml(agent.name || 'Unnamed')}</td>
                <td class="time">${formatTime(agent.first)}</td>
                <td class="time">${formatTime(agent.last)}</td>
                <td style="text-align: center; font-weight: 600;">${agent.count}</td>
            </tr>
        `).join('');

        if (window.feather) feather.replace();

    } catch (err) {
        console.error('Error loading RingCentral activity:', err);
        tableBody.innerHTML = '<tr><td colspan="4" style="color: var(--danger); text-align: center;">Connection error</td></tr>';
    }
}

function formatTime(isoString) {
    if (!isoString) return '--:--';
    try {
        return new Date(isoString).toLocaleTimeString([], {
            hour: '2-digit',
            minute: '2-digit'
        });
    } catch {
        return '--:--';
    }
}

function setRCDateToToday() {
    const input = document.getElementById('rcDateInput');
    if (!input) return;
    const today = new Date();
    const yyyy = today.getFullYear();
    const mm = String(today.getMonth() + 1).padStart(2, '0');
    const dd = String(today.getDate()).padStart(2, '0');
    input.value = `${yyyy}-${mm}-${dd}`;
}

// Initialize RingCentral activity on view load
document.addEventListener('DOMContentLoaded', () => {
    const rcUpdateBtn = document.getElementById('rcUpdateBtn');
    if (rcUpdateBtn) {
        rcUpdateBtn.addEventListener('click', loadRingCentralActivity);
        setRCDateToToday();
    }
});


export function openAgentProfile(userId, username) {
    document.getElementById('agentProfileId').value = userId;
    document.getElementById('agentProfileTitle').innerHTML = `<i data-feather="user"></i> Profile: ${escapeHtml(username)}`;
    if (window.feather) feather.replace();
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(endDate.getDate() - 7);
    document.getElementById('statsStartDate').value = startDate.toISOString().split('T')[0];
    document.getElementById('statsEndDate').value = endDate.toISOString().split('T')[0];
    document.getElementById('agentStatsContainer').style.display = 'none';
    document.getElementById('agentProfileModal').style.display = 'flex';
}

async function getAgentStats() {
    const userId = document.getElementById('agentProfileId').value;
    const startDate = document.getElementById('statsStartDate').value;
    const endDate = document.getElementById('statsEndDate').value;
    if (!startDate || !endDate) { showToast('Please select both dates.'); return; }
    try {
        const resp = await fetchWithAuth(`${CONFIG.API_BASE_URL}/admin/users/${userId}/stats?startDate=${startDate}&endDate=${endDate}`);
        if (!resp.ok) { showToast('Error fetching stats'); return; }
        const stats = await resp.json();
        document.getElementById('statsTotalCalls').textContent = stats.totalCalls;
        document.getElementById('statsContactRate').textContent = `${stats.contactRate.toFixed(1)}%`;
        document.getElementById('statsLeadConversion').textContent = `${stats.leadConversionRate.toFixed(1)}%`;
        const ctx = document.getElementById('agentDispositionChart').getContext('2d');
        if (agentChart) agentChart.destroy();
        agentChart = new Chart(ctx, { type: 'doughnut', data: { labels: Object.keys(stats.dispositions), datasets: [{ data: Object.values(stats.dispositions), backgroundColor: ['#2962ff', '#f50057', '#00e676', '#651fff', '#ffea00', '#ff3d00'] }] } });
        document.getElementById('agentStatsContainer').style.display = 'block';
        const statsList = document.getElementById('agentDispositionStatsList');
        statsList.innerHTML = '';
        Object.entries(stats.dispositions).forEach(([disposition, count]) => {
            const card = document.createElement('div'); card.className = 'stat-card';
            card.innerHTML = `<h4 class="stat-title">${disposition}</h4><p class="stat-value">${count}</p>`;
            statsList.appendChild(card);
        });
    } catch (err) { showToast('Connection error.'); }
}

// Expose globals for inline HTML handlers
window.showAdminView = showAdminView;
window.markAsSale = markAsSale;
window.reassignSelectedLeads = reassignSelectedLeads;
window.deleteSelectedLeads = deleteSelectedLeads;
window.handleDeduplicateLeads = handleDeduplicateLeads;
window.confirmDeleteDuplicates = confirmDeleteDuplicates;
window.openAdminEditLeadModal = openAdminEditLeadModal;
window.openAgentProfile = openAgentProfile;
window.openEditModal = openEditModal;
window.handleDeleteUser = handleDeleteUser;
window.loadAllLeads = loadAllLeads; // For filter button
