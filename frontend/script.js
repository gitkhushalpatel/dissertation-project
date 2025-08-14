// frontend/script.js

// --- Global Variables ---
const API_BASE_URL = 'http://127.0.0.1:5000/api';
let currentUser = null;
let selectedFileIdForDecryption = null;
let selectedFileStorageLocation = null;
let isGoogleDriveConnected = false;
let googleAuthWindow = null;
let driveConnectInterval = null;

// --- DOM Elements ---
const loginForm = document.getElementById('loginForm');
const registerForm = document.getElementById('registerForm');
const fileInput = document.getElementById('fileInput');
const recoveryPhraseInput = document.getElementById('recoveryPhrase');
const encryptButton = document.getElementById('encryptButton');
const encryptToDriveButton = document.getElementById('encryptToDriveButton');
const decryptButton = document.getElementById('decryptButton');
const statusMessageDiv = document.getElementById('statusMessage');
const downloadEncryptedArea = document.getElementById('downloadEncryptedArea');
const downloadEncryptedLink = document.getElementById('downloadEncryptedLink');
const downloadArea = document.getElementById('downloadArea');
const downloadLink = document.getElementById('downloadLink');
const clearFileButton = document.getElementById('clearFileButton');
const selectedFileNameSpan = document.getElementById('selectedFileName');

// Authentication UI elements
const authSection = document.getElementById('authSection');
const mainApp = document.getElementById('mainApp');
const navbar = document.getElementById('navbar');
const logoutButton = document.getElementById('logoutBtn');
const welcomeUserSpan = document.getElementById('welcomeUser');
const authMessageDiv = document.getElementById('authMessage');

// Auth tabs and forms
const authTabs = document.querySelectorAll('.auth-tab');
const authForms = document.querySelectorAll('.auth-form');

// Google Drive elements
const connectDriveBtn = document.getElementById('connectDriveBtn');
const disconnectDriveBtn = document.getElementById('disconnectDriveBtn');
const driveStatusText = document.getElementById('driveStatusText');
const driveNotConnected = document.getElementById('driveNotConnected');
const driveConnected = document.getElementById('driveConnected');

// File list elements
const userFilesListDiv = document.getElementById('userFilesList');
const noFilesMessage = document.getElementById('noFilesMessage');

// Modal Elements
const notificationModal = document.getElementById('notificationModal');
const modalTitle = document.getElementById('modalTitle');
const modalMessage = document.getElementById('modalMessage');
const modalCloseBtn = document.getElementById('modalCloseBtn');
const modalOkBtn = document.getElementById('modalOkBtn');

// --- Utility Functions ---

/**
 * Shows a notification modal.
 */
function showModal(title, message, isError = false) {
    if (!notificationModal) return;
    
    modalTitle.textContent = title;
    modalMessage.textContent = message;
    
    if (isError) {
        modalTitle.classList.add('text-red-600');
        modalTitle.classList.remove('text-green-600');
    } else {
        modalTitle.classList.remove('text-red-600');
        modalTitle.classList.add('text-green-600');
    }
    
    notificationModal.classList.remove('hidden');
}

/**
 * Hides the notification modal.
 */
function hideModal() {
    if (notificationModal) notificationModal.classList.add('hidden');
}

/**
 * Shows a status message to the user
 */
function showStatusMessage(text, type) {
    if (statusMessageDiv) {
        statusMessageDiv.textContent = text;
        let colorClass = 'text-gray-600';
        if (type === 'error') {
            colorClass = 'text-red-600';
        } else if (type === 'success') {
            colorClass = 'text-green-600';
        }
        statusMessageDiv.className = `text-center text-sm mt-4 ${colorClass}`;
        setTimeout(() => { if(statusMessageDiv.textContent === text) statusMessageDiv.textContent = ''}, 5000);
    }
}

/**
 * Shows authentication messages
 */
function showAuthMessage(message, type) {
    if (authMessageDiv) {
        authMessageDiv.textContent = message;
        authMessageDiv.className = `mt-4 p-3 rounded-lg text-center ${type === 'error' ? 'bg-red-100 text-red-700' : 'bg-green-100 text-green-700'}`;
        authMessageDiv.classList.remove('hidden');
    }
}

function clearAuthMessage() {
    if (authMessageDiv) {
        authMessageDiv.classList.add('hidden');
    }
}

/**
 * Generates a UUID for file identification
 */
function generateUUID() {
    return 'file_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
}

/**
 * Converts ArrayBuffer to Base64
 */
function bufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

/**
 * Converts Base64 to ArrayBuffer
 */
function base64ToBuffer(base64) {
    const binary_string = window.atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}

// --- Authentication Functions ---

function updateUIForLogin() {
    if (authSection) authSection.classList.add('hidden');
    if (mainApp) mainApp.classList.remove('hidden');
    if (navbar) navbar.classList.remove('hidden');
    if (welcomeUserSpan) welcomeUserSpan.textContent = `Welcome, ${currentUser.username}`;
    loadUserFiles();
    checkGoogleDriveStatus();
}

function updateUIForLogout() {
    if (authSection) authSection.classList.remove('hidden');
    if (mainApp) mainApp.classList.add('hidden');
    if (navbar) navbar.classList.add('hidden');
    if (welcomeUserSpan) welcomeUserSpan.textContent = '';
    if (userFilesListDiv) {
        userFilesListDiv.innerHTML = '<p class="text-gray-500 text-center" id="noFilesMessage">No files encrypted yet. Encrypt one above!</p>';
    }
    switchAuthTab('login');
}

function switchAuthTab(tabToActivate) {
    authTabs.forEach(tab => tab.classList.remove('active', 'bg-white', 'shadow-sm'));
    authForms.forEach(form => form.classList.add('hidden'));

    const activeTab = document.querySelector(`[data-tab="${tabToActivate}"]`);
    if (activeTab) {
        activeTab.classList.add('active', 'bg-white', 'shadow-sm');
    }

    const targetForm = document.getElementById(`${tabToActivate}Form`);
    if (targetForm) {
        targetForm.classList.remove('hidden');
    }
    clearAuthMessage();
}

function setButtonLoading(button, loading) {
    if (button) {
        const btnText = button.querySelector('.btn-text');
        const btnLoading = button.querySelector('.btn-loading');
        
        if (loading) {
            button.disabled = true;
            if (btnText) btnText.classList.add('hidden');
            if (btnLoading) btnLoading.classList.remove('hidden');
        } else {
            button.disabled = false;
            if (btnText) btnText.classList.remove('hidden');
            if (btnLoading) btnLoading.classList.add('hidden');
        }
    }
}

// --- Crypto Functions ---

async function deriveKey(password, salt) {
    const masterKey = await window.crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(password),
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );
    return window.crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256',
        },
        masterKey,
        { name: 'AES-GCM', length: 256 },
        true,
        ['wrapKey', 'unwrapKey']
    );
}

// --- Google Drive Functions ---

async function checkGoogleDriveStatus() {
    if (!currentUser || !currentUser.user_id) return;
    
    try {
        const response = await fetch(`${API_BASE_URL}/drive/status/${currentUser.user_id}`);
        const data = await response.json();
        
        isGoogleDriveConnected = data.connected;
        updateDriveUI();
    } catch (error) {
        console.error('Error checking Drive status:', error);
        if (driveStatusText) {
            driveStatusText.textContent = 'Connection check failed';
        }
    }
}

function updateDriveUI() {
    if (isGoogleDriveConnected) {
        driveStatusText.textContent = 'Connected';
        driveStatusText.className = 'text-sm text-green-600 font-semibold';
        driveNotConnected.classList.add('hidden');
        driveConnected.classList.remove('hidden');
        document.getElementById('encryptToDriveButton').disabled = false;
        document.getElementById('encryptToDriveButton').classList.remove('opacity-50');
    } else {
        driveStatusText.textContent = 'Not connected';
        driveStatusText.className = 'text-sm text-gray-600';
        driveNotConnected.classList.remove('hidden');
        driveConnected.classList.add('hidden');
        document.getElementById('encryptToDriveButton').disabled = true;
        document.getElementById('encryptToDriveButton').classList.add('opacity-50');
    }
}

async function connectGoogleDrive() {
    if (!currentUser || !currentUser.user_id) {
        showModal('Login Required', 'You must be logged in to connect to Google Drive.', true);
        return;
    }

    try {
        showStatusMessage('Initiating Google Drive connection...', 'info');
        
        // Pass user_id as a parameter
        const response = await fetch(`${API_BASE_URL}/auth/google?user_id=${currentUser.user_id}`);
        const data = await response.json();
        
        if (!response.ok) {
            let errorMessage = data.error || 'Failed to initiate Google Drive connection';
            if (errorMessage.includes('not configured')) {
                showModal('Configuration Error 🔧', 'Google Drive integration is not properly configured on the server. Please contact your administrator.');
            } else {
                showModal('Connection Error', `Failed to start Google Drive connection: ${errorMessage}`, true);
            }
            throw new Error(errorMessage);
        }
        
        console.log('Opening auth URL:', data.auth_url);
        
        googleAuthWindow = window.open(data.auth_url, 'google_auth', 'width=500,height=600');

        if (!googleAuthWindow || googleAuthWindow.closed) {
            showModal('Popup Blocked 🚫', 'Your browser blocked the Google authentication popup. Please allow popups for this site and try again.', true);
            return;
        }

        console.log('Auth window opened successfully');

        // Improved polling with better error handling
        let pollCount = 0;
        const maxPolls = 60; // 2 minutes (2 second intervals)
        
        const pollForCompletion = setInterval(async () => {
            pollCount++;
            console.log(`Polling attempt ${pollCount}/${maxPolls}`);
            
            try {
                // Check the new endpoint for temporary credentials
                const tempResponse = await fetch(`${API_BASE_URL}/auth/google/check/${currentUser.user_id}`);
                
                if (tempResponse.ok) {
                    const tempData = await tempResponse.json();
                    console.log('Temp check response:', tempData);
                    
                    if (tempData.success) {
                        console.log('Authentication completed successfully!');
                        clearInterval(pollForCompletion);
                        isGoogleDriveConnected = true;
                        updateDriveUI();
                        showModal('Google Drive Connected! 🎉', 'Your Google Drive has been successfully connected. You can now encrypt files directly to Google Drive!');
                        showStatusMessage('Google Drive connected successfully!', 'success');
                        
                        // Try to close the auth window
                        try {
                            if (googleAuthWindow && !googleAuthWindow.closed) {
                                googleAuthWindow.close();
                            }
                        } catch (e) {
                            console.log('Could not close auth window:', e);
                        }
                        return;
                    }
                }
                
                // Fallback: Check status via API
                const statusResponse = await fetch(`${API_BASE_URL}/drive/status/${currentUser.user_id}`);
                if (statusResponse.ok) {
                    const statusData = await statusResponse.json();
                    console.log('Status check result:', statusData);

                    if (statusData.connected && !isGoogleDriveConnected) {
                        console.log('Status polling detected connection!');
                        clearInterval(pollForCompletion);
                        isGoogleDriveConnected = true;
                        updateDriveUI();
                        showModal('Google Drive Connected! 🎉', 'Your Google Drive has been successfully connected. You can now encrypt files directly to Google Drive!');
                        showStatusMessage('Google Drive connected successfully!', 'success');
                        
                        // Try to close the auth window
                        try {
                            if (googleAuthWindow && !googleAuthWindow.closed) {
                                googleAuthWindow.close();
                            }
                        } catch (e) {
                            console.log('Could not close auth window:', e);
                        }
                        return;
                    }
                }
                
            } catch (error) {
                console.error('Polling error:', error);
                // Don't fail completely on individual polling errors
            }
            
            // Check if window is closed
            try {
                if (googleAuthWindow && googleAuthWindow.closed) {
                    console.log('Auth window was closed by user');
                    clearInterval(pollForCompletion);
                    
                    if (!isGoogleDriveConnected) {
                        showStatusMessage('Authentication window closed. Checking for completion...', 'info');
                        
                        // Give it a few more seconds to check for credentials
                        setTimeout(async () => {
                            try {
                                const tempResponse = await fetch(`${API_BASE_URL}/auth/google/check/${currentUser.user_id}`);
                                if (tempResponse.ok) {
                                    const tempData = await tempResponse.json();
                                    
                                    if (tempData.success) {
                                        console.log('Found delayed credentials!');
                                        isGoogleDriveConnected = true;
                                        updateDriveUI();
                                        showModal('Google Drive Connected! 🎉', 'Your Google Drive has been successfully connected. You can now encrypt files directly to Google Drive!');
                                        showStatusMessage('Google Drive connected successfully!', 'success');
                                        return;
                                    }
                                }
                                
                                // If we get here, auth was likely cancelled
                                showModal('Authentication Cancelled 🤔', 'Google Drive authentication was cancelled or incomplete. You can try connecting again, or use local file encryption instead.');
                                showStatusMessage('Google Drive authentication was cancelled.', 'error');
                            } catch (e) {
                                console.error('Final check error:', e);
                                showStatusMessage('Authentication cancelled or failed.', 'error');
                            }
                        }, 3000);
                    }
                    return;
                }
            } catch (e) {
                // This is expected due to CORS policy when checking window.closed
                console.log('Cannot access window.closed due to CORS policy (this is normal)');
            }
            
            // Timeout after max polls
            if (pollCount >= maxPolls) {
                console.log('Auth polling timed out');
                clearInterval(pollForCompletion);
                
                if (!isGoogleDriveConnected) {
                    showModal('Connection Timeout ⏰', 'The Google Drive connection took too long and timed out. Please try again. If the problem persists, check your internet connection.');
                    showStatusMessage('Google Drive connection timed out.', 'error');
                }
                
                try {
                    if (googleAuthWindow && !googleAuthWindow.closed) {
                        googleAuthWindow.close();
                    }
                } catch (e) {
                    console.log('Could not close auth window on timeout:', e);
                }
            }
        }, 2000); // Poll every 2 seconds

    } catch (error) {
        console.error('Error initiating Google Drive connection:', error);
        showStatusMessage('Failed to connect to Google Drive. Please try again.', 'error');
    }
}


async function disconnectGoogleDrive() {
    try {
        const response = await fetch(`${API_BASE_URL}/drive/disconnect/${currentUser.user_id}`, {
            method: 'POST'
        });
        if (response.ok) {
            isGoogleDriveConnected = false;
            updateDriveUI();
            showModal('Disconnected', 'Your Google Drive account has been disconnected.');
        } else {
            throw new Error('Failed to disconnect');
        }
    } catch (error) {
        showModal('Error', 'Failed to disconnect Google Drive.', true);
    }
}

// --- File Management Functions ---

async function loadUserFiles() {
    if (!currentUser || !currentUser.user_id || !userFilesListDiv) {
        if (userFilesListDiv) {
            userFilesListDiv.innerHTML = '<p class="text-gray-500 text-center">Please log in to see your files.</p>';
        }
        return;
    }

    userFilesListDiv.innerHTML = '<p class="text-gray-500 text-center">Loading files...</p>';

    try {
        const response = await fetch(`${API_BASE_URL}/keys/${currentUser.user_id}`);
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        const files = await response.json();
        console.log('Loaded files:', files); // Debug log

        userFilesListDiv.innerHTML = '';

        if (files.length === 0) {
            userFilesListDiv.innerHTML = '<p class="text-gray-500 text-center">No files encrypted yet. Encrypt one above!</p>';
            return;
        }

        files.forEach(file => {
            console.log('Processing file:', file); // Debug log
            
            // Handle different possible field names from the API
            const fileId = file.fileId || file.file_id;
            const originalFileName = file.originalFileName || file.original_file_name;
            const storageLocation = file.storageLocation || file.storage_location || 'local';
            const createdAt = file.createdAt || file.created_at;
            
            if (!fileId) {
                console.error('File missing ID:', file);
                return;
            }
            
            const storageIcon = storageLocation === 'google_drive' ? '📁' : '💾';
            const storageText = storageLocation === 'google_drive' ? 'Google Drive' : 'Local';
            
            const fileItem = document.createElement('div');
            fileItem.className = 'flex items-center justify-between bg-white p-3 rounded-lg shadow-sm hover:shadow-md transition-shadow duration-200';
            fileItem.innerHTML = `
                <div class="flex-1 overflow-hidden">
                    <p class="font-semibold text-gray-800 truncate">${escapeHtml(originalFileName || 'Unknown File')}</p>
                    <p class="text-xs text-gray-500">ID: <span class="font-mono text-blue-600">${fileId}</span></p>
                    <p class="text-xs text-gray-500">
                        <span class="mr-2">${storageIcon} ${storageText}</span>
                        | Encrypted: ${createdAt ? new Date(createdAt).toLocaleString() : 'Unknown'}
                    </p>
                </div>
                <div class="flex space-x-2 ml-4">
                    <button data-file-id="${fileId}" data-storage-location="${storageLocation}" 
                            class="select-file-btn bg-[#06D6A0] text-white text-sm py-1 px-3 rounded-md font-semibold
                                   hover:bg-[#118AB2] transition-colors duration-200 shadow-sm">
                        Select for Decrypt
                    </button>
                    <button data-file-id="${fileId}" 
                            class="delete-file-btn bg-[#FF6B6B] text-white text-sm py-1 px-3 rounded-md font-semibold
                                   hover:bg-[#FFD166] transition-colors duration-200 shadow-sm">
                        Delete
                    </button>
                </div>
            `;
            
            // Add event listeners using proper JavaScript instead of onclick
            const selectBtn = fileItem.querySelector('.select-file-btn');
            const deleteBtn = fileItem.querySelector('.delete-file-btn');
            
            selectBtn.addEventListener('click', () => {
                console.log('Selecting file for decryption:', fileId, storageLocation);
                selectFileForDecryption(fileId, storageLocation);
            });
            
            deleteBtn.addEventListener('click', () => {
                console.log('Deleting file:', fileId);
                deleteFile(fileId);
            });
            
            userFilesListDiv.appendChild(fileItem);
        });

    } catch (error) {
        console.error('Error loading files:', error);
        if (userFilesListDiv) {
            userFilesListDiv.innerHTML = `<p class="text-red-600 text-center">Failed to load files: ${error.message}</p>`;
        }
    }
}

function selectFileForDecryption(fileId, storageLocation) {
    console.log('selectFileForDecryption called with:', fileId, storageLocation);
    
    if (!fileId) {
        console.error('selectFileForDecryption: fileId is undefined or null');
        showStatusMessage('Error: Invalid file ID', 'error');
        return;
    }
    
    selectedFileIdForDecryption = fileId;
    selectedFileStorageLocation = storageLocation || 'local';
    
    console.log('Set selectedFileIdForDecryption to:', selectedFileIdForDecryption);
    console.log('Set selectedFileStorageLocation to:', selectedFileStorageLocation);
    
    if (decryptButton) {
        const shortId = fileId.substring(0, 8);
        const locationText = selectedFileStorageLocation === 'google_drive' ? 'Drive' : 'Local';
        decryptButton.textContent = `Decrypt Selected File (${shortId}... from ${locationText})`;
    }
    
    showStatusMessage(`File selected for decryption: ${fileId.substring(0, 8)}... from ${selectedFileStorageLocation === 'google_drive' ? 'Google Drive' : 'Local storage'}`, 'info');
    
    // Clear file input when selecting from list
    if (fileInput) fileInput.value = '';
    if (selectedFileNameSpan) selectedFileNameSpan.textContent = 'No file selected.';
}

async function deleteFile(fileId) {
    if (!confirm('Are you sure you want to delete this file metadata and encrypted content? This action cannot be undone.')) {
        return;
    }

    showStatusMessage('Deleting file...', 'info');
    try {
        const response = await fetch(`${API_BASE_URL}/keys/${currentUser.user_id}/${fileId}`, {
            method: 'DELETE',
        });

        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || `Server error: ${response.statusText}`);
        }

        showStatusMessage('File deleted successfully!', 'success');
        loadUserFiles();
    } catch (error) {
        console.error('Error deleting file:', error);
        showStatusMessage(`Failed to delete file: ${error.message}.`, 'error');
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// --- Event Handlers ---

function checkInitialAuthState() {
    const userData = sessionStorage.getItem('userData');
    if (userData) {
        currentUser = JSON.parse(userData);
        updateUIForLogin();
    } else {
        currentUser = null;
        updateUIForLogout();
    }
}

async function handleLogin(e) {
    e.preventDefault();
    const submitBtn = e.target.querySelector('button[type="submit"]');
    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value;

    if (!username || !password) {
        showAuthMessage('Please fill in all fields', 'error');
        return;
    }

    setButtonLoading(submitBtn, true);

    try {
        const response = await fetch(`${API_BASE_URL}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (response.ok) {
            currentUser = { user_id: data.user_id, username: username };
            sessionStorage.setItem('userData', JSON.stringify(currentUser));
            
            showAuthMessage('Login successful!', 'success');
            setTimeout(() => updateUIForLogin(), 1000);
        } else {
            showAuthMessage(data.error || 'Login failed', 'error');
        }
    } catch (error) {
        showAuthMessage('Network error. Please try again.', 'error');
    } finally {
        setButtonLoading(submitBtn, false);
    }
}

async function handleRegister(e) {
    e.preventDefault();
    const submitBtn = e.target.querySelector('button[type="submit"]');
    const username = document.getElementById('registerUsername').value.trim();
    const password = document.getElementById('registerPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;

    if (!username || !password || !confirmPassword) {
        showAuthMessage('Please fill in all fields', 'error');
        return;
    }

    if (password !== confirmPassword) {
        showAuthMessage('Passwords do not match', 'error');
        return;
    }

    if (password.length < 6) {
        showAuthMessage('Password must be at least 6 characters long', 'error');
        return;
    }

    setButtonLoading(submitBtn, true);

    try {
        const response = await fetch(`${API_BASE_URL}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (response.ok) {
            showAuthMessage('Registration successful! Please login.', 'success');
            setTimeout(() => {
                switchAuthTab('login');
                document.getElementById('loginUsername').value = username;
            }, 1500);
        } else {
            showAuthMessage(data.error || 'Registration failed', 'error');
        }
    } catch (error) {
        showAuthMessage('Network error. Please try again.', 'error');
    } finally {
        setButtonLoading(submitBtn, false);
    }
}

function handleLogout() {
    sessionStorage.removeItem('userData');
    currentUser = null;
    updateUIForLogout();
}

function handleFileChange() {
    if (downloadArea) downloadArea.classList.add('hidden');
    if (downloadEncryptedArea) downloadEncryptedArea.classList.add('hidden');
    if (statusMessageDiv) statusMessageDiv.textContent = '';
    selectedFileIdForDecryption = null;
    if (decryptButton) decryptButton.textContent = 'Decrypt Selected File';

    if (fileInput.files.length > 0) {
        if (selectedFileNameSpan) selectedFileNameSpan.textContent = fileInput.files[0].name;
        if (decryptButton) decryptButton.textContent = 'Decrypt Uploaded File';
    } else {
        if (selectedFileNameSpan) selectedFileNameSpan.textContent = 'No file selected.';
        if (decryptButton) decryptButton.textContent = 'Decrypt Selected File';
    }
}

function handleFileClear() {
    if (fileInput) fileInput.value = '';
    if (selectedFileNameSpan) selectedFileNameSpan.textContent = 'No file selected.';
    if (downloadArea) downloadArea.classList.add('hidden');
    if (downloadEncryptedArea) downloadEncryptedArea.classList.add('hidden');
    showStatusMessage('File selection cleared.', 'info');
    selectedFileIdForDecryption = null;
    selectedFileStorageLocation = null;
    if (decryptButton) decryptButton.textContent = 'Decrypt Selected File';
}

async function handleEncrypt() {
    if (!fileInput.files[0]) {
        showStatusMessage('Please select a file to encrypt.', 'error');
        return;
    }

    const recoveryPhrase = recoveryPhraseInput.value.trim();
    if (!recoveryPhrase) {
        showStatusMessage('Please enter a recovery phrase.', 'error');
        return;
    }

    showStatusMessage('Encrypting file...', 'info');
    encryptButton.disabled = true;

    try {
        const file = fileInput.files[0];
        const fileBuffer = await file.arrayBuffer();
        
        // Generate cryptographic parameters
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const keyWrappingIv = window.crypto.getRandomValues(new Uint8Array(12));
        
        // Generate and derive keys
        const fileKey = await window.crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
        
        const wrappingKey = await deriveKey(recoveryPhrase, salt);
        
        // Encrypt file
        const encryptedData = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            fileKey,
            fileBuffer
        );
        
        // Wrap the file key
        const wrappedKey = await window.crypto.subtle.wrapKey(
            'raw',
            fileKey,
            wrappingKey,
            { name: 'AES-GCM', iv: keyWrappingIv }
        );
        
        // Prepare data for server
        const fileId = generateUUID();
        const formData = new FormData();
        formData.append('userId', currentUser.user_id);
        formData.append('fileId', fileId);
        formData.append('wrappedKey', bufferToBase64(wrappedKey));
        formData.append('iv', bufferToBase64(iv));
        formData.append('salt', bufferToBase64(salt));
        formData.append('keyWrappingIv', bufferToBase64(keyWrappingIv));
        formData.append('originalFileName', file.name);
        formData.append('encryptedFile', new Blob([encryptedData]), `encrypted_${file.name}.enc`);
        
        // Send to server
        const response = await fetch(`${API_BASE_URL}/keys`, {
            method: 'POST',
            body: formData
        });
        
        const result = await response.json();
        
        if (response.ok) {
            showStatusMessage('File encrypted and saved successfully!', 'success');
            
            // Create download link
            const blob = new Blob([encryptedData]);
            const url = URL.createObjectURL(blob);
            downloadEncryptedLink.href = url;
            downloadEncryptedLink.download = `encrypted_${file.name}.enc`;
            downloadEncryptedArea.classList.remove('hidden');
            
            loadUserFiles();
        } else {
            throw new Error(result.error || 'Encryption failed');
        }
        
    } catch (error) {
        console.error('Encryption error:', error);
        showStatusMessage(`Encryption failed: ${error.message}`, 'error');
    } finally {
        encryptButton.disabled = false;
    }
}

async function handleEncryptToDrive() {
    if (!isGoogleDriveConnected) {
        showModal('Google Drive Not Connected', 'Please connect your Google Drive account first.', true);
        return;
    }

    if (!fileInput.files[0]) {
        showStatusMessage('Please select a file to encrypt.', 'error');
        return;
    }

    const recoveryPhrase = recoveryPhraseInput.value.trim();
    if (!recoveryPhrase) {
        showStatusMessage('Please enter a recovery phrase.', 'error');
        return;
    }

    showStatusMessage('Encrypting and uploading to Google Drive...', 'info');
    encryptToDriveButton.disabled = true;

    try {
        const file = fileInput.files[0];
        const fileBuffer = await file.arrayBuffer();
        
        // Generate cryptographic parameters
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const keyWrappingIv = window.crypto.getRandomValues(new Uint8Array(12));
        
        // Generate and derive keys
        const fileKey = await window.crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
        
        const wrappingKey = await deriveKey(recoveryPhrase, salt);
        
        // Encrypt file
        const encryptedData = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            fileKey,
            fileBuffer
        );
        
        // Wrap the file key
        const wrappedKey = await window.crypto.subtle.wrapKey(
            'raw',
            fileKey,
            wrappingKey,
            { name: 'AES-GCM', iv: keyWrappingIv }
        );
        
        // Prepare data for server
        const fileId = generateUUID();
        const formData = new FormData();
        formData.append('userId', currentUser.user_id);
        formData.append('fileId', fileId);
        formData.append('wrappedKey', bufferToBase64(wrappedKey));
        formData.append('iv', bufferToBase64(iv));
        formData.append('salt', bufferToBase64(salt));
        formData.append('keyWrappingIv', bufferToBase64(keyWrappingIv));
        formData.append('originalFileName', file.name);
        formData.append('encryptedFile', new Blob([encryptedData]), `encrypted_${file.name}.enc`);
        
        // Send to Google Drive via server
        const response = await fetch(`${API_BASE_URL}/drive/upload`, {
            method: 'POST',
            body: formData
        });
        
        const result = await response.json();
        
        if (response.ok) {
            showStatusMessage('File encrypted and uploaded to Google Drive successfully!', 'success');
            showModal('Upload Successful! 🎉', `Your file "${file.name}" has been encrypted and safely uploaded to Google Drive.`);
            loadUserFiles();
        } else {
            // Handle specific Google Drive errors with user-friendly messages
            let errorMessage = result.error || 'Upload to Google Drive failed';
            let modalTitle = 'Upload Error';
            let modalMessage = '';
            
            if (errorMessage.includes('storage quota') || errorMessage.includes('storageQuotaExceeded')) {
                modalTitle = 'Google Drive Storage Full 📦';
                modalMessage = `Your Google Drive storage is full! 
                
Here's what you can do:
• Delete some files from your Google Drive
• Empty your Google Drive trash
• Upgrade your Google storage plan
• Use "Encrypt File (Local)" instead

Your file encryption is working perfectly - this is just a storage limit issue.`;
            } else if (errorMessage.includes('authentication') || errorMessage.includes('unauthorized')) {
                modalTitle = 'Google Drive Access Issue 🔑';
                modalMessage = `There's an issue with your Google Drive connection.

Please try:
• Disconnecting and reconnecting Google Drive
• Make sure you granted all permissions
• Check if your Google account is still valid`;
            } else if (errorMessage.includes('network') || errorMessage.includes('timeout')) {
                modalTitle = 'Connection Problem 🌐';
                modalMessage = `There was a network issue uploading to Google Drive.

Please try:
• Check your internet connection
• Try again in a few moments
• Use "Encrypt File (Local)" as an alternative`;
            } else {
                modalTitle = 'Upload Failed ❌';
                modalMessage = `We couldn't upload your file to Google Drive.

Error: ${errorMessage}

You can still use "Encrypt File (Local)" to save your encrypted file locally.`;
            }
            
            showModal(modalTitle, modalMessage, true);
            throw new Error(errorMessage);
        }
        
    } catch (error) {
        console.error('Google Drive upload error:', error);
        // Only show generic error if we haven't already shown a specific modal
        if (!error.message.includes('storage quota') && 
            !error.message.includes('authentication') && 
            !error.message.includes('network')) {
            showStatusMessage(`Upload failed: ${error.message}`, 'error');
        }
    } finally {
        encryptToDriveButton.disabled = false;
    }
}

async function handleDecrypt() {
    const recoveryPhrase = recoveryPhraseInput.value.trim();
    if (!recoveryPhrase) {
        showStatusMessage('Please enter your recovery phrase.', 'error');
        return;
    }

    console.log('handleDecrypt called');
    console.log('selectedFileIdForDecryption:', selectedFileIdForDecryption);
    console.log('selectedFileStorageLocation:', selectedFileStorageLocation);
    console.log('fileInput.files:', fileInput.files);

    let encryptedData, keyData, originalFileName;

    try {
        if (selectedFileIdForDecryption && selectedFileStorageLocation) {
            // Decrypt from stored file list
            showStatusMessage('Retrieving file metadata...', 'info');
            
            console.log(`Fetching metadata for file: ${selectedFileIdForDecryption}`);
            
            // Get key metadata
            const keyResponse = await fetch(`${API_BASE_URL}/keys/${currentUser.user_id}/${selectedFileIdForDecryption}`);
            
            console.log('Key response status:', keyResponse.status);
            
            if (!keyResponse.ok) {
                const errorText = await keyResponse.text();
                console.error('Key fetch error:', errorText);
                throw new Error(`Failed to get file metadata: ${keyResponse.status} ${keyResponse.statusText}`);
            }
            
            keyData = await keyResponse.json();
            console.log('Retrieved key data:', keyData);
            
            originalFileName = keyData.original_file_name || keyData.originalFileName;
            
            // Get encrypted content
            console.log(`Fetching encrypted content from: ${selectedFileStorageLocation}`);
            
            let fileResponse;
            if (selectedFileStorageLocation === 'google_drive') {
                fileResponse = await fetch(`${API_BASE_URL}/drive/download/${currentUser.user_id}/${selectedFileIdForDecryption}`);
            } else {
                fileResponse = await fetch(`${API_BASE_URL}/files/${currentUser.user_id}/${selectedFileIdForDecryption}`);
            }
            
            console.log('File response status:', fileResponse.status);
            
            if (!fileResponse.ok) {
                const errorText = await fileResponse.text();
                console.error('File fetch error:', errorText);
                throw new Error(`Failed to get encrypted file content: ${fileResponse.status} ${fileResponse.statusText}`);
            }
            
            encryptedData = await fileResponse.arrayBuffer();
            console.log('Retrieved encrypted data, size:', encryptedData.byteLength);
            
        } else if (fileInput.files[0]) {
            // Decrypt uploaded file
            const file = fileInput.files[0];
            encryptedData = await file.arrayBuffer();
            originalFileName = file.name.replace(/^encrypted_/, '').replace(/\.enc$/, '');
            
            // For uploaded files, we need to prompt for the key data or store it differently
            showStatusMessage('Uploaded file decryption not yet implemented. Please select from your file list.', 'error');
            return;
            
        } else {
            showStatusMessage('Please select a file to decrypt from your file list or upload an encrypted file.', 'error');
            return;
        }

        showStatusMessage('Decrypting file...', 'info');
        decryptButton.disabled = true;

        // Convert base64 data back to ArrayBuffers
        const wrappedKey = base64ToBuffer(keyData.wrapped_key);
        const iv = base64ToBuffer(keyData.iv);
        const salt = base64ToBuffer(keyData.salt);
        const keyWrappingIv = base64ToBuffer(keyData.key_wrapping_iv);

        console.log('Deriving wrapping key...');
        
        // Derive the wrapping key from the recovery phrase
        const wrappingKey = await deriveKey(recoveryPhrase, salt);

        console.log('Unwrapping file key...');
        
        // Unwrap the file key
        const fileKey = await window.crypto.subtle.unwrapKey(
            'raw',
            wrappedKey,
            wrappingKey,
            { name: 'AES-GCM', iv: keyWrappingIv },
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );

        console.log('Decrypting file data...');
        
        // Decrypt the file
        const decryptedData = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            fileKey,
            encryptedData
        );

        console.log('File decrypted successfully, size:', decryptedData.byteLength);

        // Create download link
        const blob = new Blob([decryptedData]);
        const url = URL.createObjectURL(blob);
        downloadLink.href = url;
        downloadLink.download = originalFileName;
        downloadArea.classList.remove('hidden');

        showStatusMessage('File decrypted successfully!', 'success');

    } catch (error) {
        console.error('Decryption error:', error);
        if (error.name === 'OperationError') {
            showStatusMessage('Decryption failed: Invalid recovery phrase or corrupted file.', 'error');
        } else {
            showStatusMessage(`Decryption failed: ${error.message}`, 'error');
        }
    } finally {
        decryptButton.disabled = false;
    }
}

// --- Event Listeners Setup ---

document.addEventListener('DOMContentLoaded', () => {
    console.log('DOM loaded, setting up event listeners...');
    
    // Modal listeners
    if (modalCloseBtn) modalCloseBtn.addEventListener('click', hideModal);
    if (modalOkBtn) modalOkBtn.addEventListener('click', hideModal);

    // Auth listeners
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
        console.log('Login form listener added');
    }
    if (registerForm) {
        registerForm.addEventListener('submit', handleRegister);
        console.log('Register form listener added');
    }
    if (logoutButton) logoutButton.addEventListener('click', handleLogout);
    
    authTabs.forEach(tab => {
        tab.addEventListener('click', (e) => switchAuthTab(e.target.dataset.tab));
    });

    // Google Drive listeners
    if (connectDriveBtn) connectDriveBtn.addEventListener('click', connectGoogleDrive);
    if (disconnectDriveBtn) disconnectDriveBtn.addEventListener('click', disconnectGoogleDrive);

    // File operation listeners
    if (fileInput) {
        fileInput.addEventListener('change', handleFileChange);
        console.log('File input listener added');
    }
    if (clearFileButton) clearFileButton.addEventListener('click', handleFileClear);
    if (encryptButton) {
        encryptButton.addEventListener('click', handleEncrypt);
        console.log('Encrypt button listener added');
    }
    if (encryptToDriveButton) encryptToDriveButton.addEventListener('click', handleEncryptToDrive);
    if (decryptButton) {
        decryptButton.addEventListener('click', handleDecrypt);
        console.log('Decrypt button listener added');
    }
    
    // Check initial auth state
    checkInitialAuthState();
    console.log('Initial setup complete');
});

// Global functions for onclick handlers in HTML
window.selectFileForDecryption = selectFileForDecryption;
window.deleteFile = deleteFile;