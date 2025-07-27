// frontend/script.js

// --- DOM Elements (Adjusted to match index.html IDs) ---
const loginForm = document.getElementById('loginForm');
const registerForm = document.getElementById('registerForm');

// Main app elements from index.html
const fileInput = document.getElementById('fileInput');
const recoveryPhraseInput = document.getElementById('recoveryPhrase');
const encryptButton = document.getElementById('encryptButton');
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

const authTabs = document.querySelectorAll('.auth-tab');
const authForms = document.querySelectorAll('.auth-form');

// Google Drive related DOM elements
const connectDriveBtn = document.getElementById('connectDriveBtn');
const disconnectDriveBtn = document.getElementById('disconnectDriveBtn');
const encryptToDriveButton = document.getElementById('encryptToDriveButton');
const driveStatusText = document.getElementById('driveStatusText');
const driveNotConnected = document.getElementById('driveNotConnected');
const driveConnected = document.getElementById('driveConnected');

// New DOM elements for file listing
const userFilesListDiv = document.getElementById('userFilesList');
const noFilesMessage = document.getElementById('noFilesMessage');

const API_BASE_URL = 'http://127.0.0.1:5000/api';

// Global state for current user and selected file for decryption
let currentUser = null;
let selectedFileIdForDecryption = null; // Stores the fileId of the file selected from the list
let selectedFileStorageLocation = null; // Stores storage location (local or google_drive)

// Google Drive state
let isGoogleDriveConnected = false;
let googleAuthWindow = null;

// --- Utility Functions ---

/**
 * Displays a message to the user within the main app section.
 * @param {string} text - The message to display.
 * @param {'success' | 'error' | 'info'} type - The type of message.
 */
function showStatusMessage(text, type) {
    if (statusMessageDiv) {
        statusMessageDiv.textContent = text;
        let colorClass = 'text-gray-600'; // Default for 'info' or general
        if (type === 'error') {
            colorClass = 'text-red-600';
        } else if (type === 'success') {
            colorClass = 'text-green-600';
        }
        statusMessageDiv.className = `text-center text-sm mt-4 ${colorClass}`;
        setTimeout(() => statusMessageDiv.textContent = '', 5000); // Clear after 5 seconds
    }
}

/**
 * Displays a message to the user within the authentication section.
 * @param {string} message - The message to display.
 * @param {string} type - 'success' or 'error'.
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
 * Generates a a V4 UUID (Universally Unique Identifier).
 * @returns {string} A new UUID string.
 */
function generateUUID() {
    return window.crypto.randomUUID(); // Modern browsers support this
}

/**
 * Converts an ArrayBuffer to a Base64 string.
 * @param {ArrayBuffer} buffer - The buffer to convert.
 * @returns {string} The Base64 encoded string.
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
 * Converts a Base64 string to an ArrayBuffer.
 * @param {string} base64 - The Base64 string to convert.
 * @returns {ArrayBuffer} The decoded ArrayBuffer.
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

// --- Authentication UI Logic ---

/**
 * Updates the UI after a successful login.
 */
function updateUIForLogin() {
    if (authSection) authSection.classList.add('hidden');
    if (mainApp) mainApp.classList.remove('hidden');
    if (navbar) navbar.classList.remove('hidden');
    if (welcomeUserSpan) welcomeUserSpan.textContent = `Welcome, ${currentUser.username}`;
    loadUserFiles(); // Load user's files after login
    checkGoogleDriveStatus(); // Check Google Drive status
}

/**
 * Updates the UI after a logout.
 */
function updateUIForLogout() {
    if (authSection) authSection.classList.remove('hidden');
    if (mainApp) mainApp.classList.add('hidden');
    if (navbar) navbar.classList.add('hidden');
    if (welcomeUserSpan) welcomeUserSpan.textContent = '';
    if (userFilesListDiv) {
        userFilesListDiv.innerHTML = '<p class="text-gray-500 text-center" id="noFilesMessage">No files encrypted yet. Encrypt one above!</p>';
    }
    switchAuthTab('login'); // Show login form after logout
}

/**
 * Toggles between login and registration forms.
 * @param {string} tabToActivate - 'login' or 'register'.
 */
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

// --- Authentication Event Handlers ---

if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
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
    });
}

if (registerForm) {
    registerForm.addEventListener('submit', async (e) => {
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
            showAuthMessage('Password must be at least 6 characters', 'error');
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
                showAuthMessage('Account created successfully! You can now log in.', 'success');
                e.target.reset();
                setTimeout(() => switchAuthTab('login'), 2000);
            } else {
                showAuthMessage(data.error || 'Registration failed', 'error');
            }
        } catch (error) {
            showAuthMessage('Network error. Please try again.', 'error');
        } finally {
            setButtonLoading(submitBtn, false);
        }
    });
}

if (logoutButton) {
    logoutButton.addEventListener('click', () => {
        sessionStorage.removeItem('userData');
        currentUser = null;
        updateUIForLogout();
    });
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
        if (driveStatusText) {
            driveStatusText.textContent = 'Connected';
            driveStatusText.className = 'text-sm text-green-600 font-semibold';
        }
        if (driveNotConnected) driveNotConnected.classList.add('hidden');
        if (driveConnected) driveConnected.classList.remove('hidden');
        if (encryptToDriveButton) {
            encryptToDriveButton.disabled = false;
            encryptToDriveButton.classList.remove('opacity-50');
        }
    } else {
        if (driveStatusText) {
            driveStatusText.textContent = 'Not connected';
            driveStatusText.className = 'text-sm text-gray-600';
        }
        if (driveNotConnected) driveNotConnected.classList.remove('hidden');
        if (driveConnected) driveConnected.classList.add('hidden');
        if (encryptToDriveButton) {
            encryptToDriveButton.disabled = true;
            encryptToDriveButton.classList.add('opacity-50');
        }
    }
}

async function connectGoogleDrive() {
    try {
        showStatusMessage('Initiating Google Drive connection...', 'info');
        
        const response = await fetch(`${API_BASE_URL}/auth/google`);
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error);
        }
        
        // Open Google auth in popup
        googleAuthWindow = window.open(
            data.auth_url,
            'google_auth',
            'width=500,height=600,scrollbars=yes,resizable=yes'
        );
        
        // Listen for the callback
        const checkClosed = setInterval(() => {
            if (googleAuthWindow.closed) {
                clearInterval(checkClosed);
                showStatusMessage('Google Drive connection cancelled.', 'error');
            }
        }, 1000);
        
        // Listen for message from popup
        window.addEventListener('message', handleGoogleAuthCallback, { once: true });
        
    } catch (error) {
        console.error('Error connecting to Google Drive:', error);
        showStatusMessage(`Failed to connect to Google Drive: ${error.message}`, 'error');
    }
}

async function handleGoogleAuthCallback(event) {
    if (event.origin !== window.location.origin) return;
    
    try {
        const { credentials } = event.data;
        
        if (credentials) {
            // Store credentials
            const response = await fetch(`${API_BASE_URL}/auth/google/store`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    user_id: currentUser.user_id,
                    credentials: credentials
                })
            });
            
            if (response.ok) {
                isGoogleDriveConnected = true;
                updateDriveUI();
                showStatusMessage('Google Drive connected successfully!', 'success');
            } else {
                throw new Error('Failed to store credentials');
            }
        }
        
        if (googleAuthWindow) {
            googleAuthWindow.close();
        }
    } catch (error) {
        console.error('Error handling Google auth callback:', error);
        showStatusMessage('Failed to complete Google Drive connection.', 'error');
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
            showStatusMessage('Google Drive disconnected successfully.', 'success');
        } else {
            throw new Error('Failed to disconnect');
        }
    } catch (error) {
        console.error('Error disconnecting Google Drive:', error);
        showStatusMessage('Failed to disconnect Google Drive.', 'error');
    }
}

// --- Crypto Functions ---

/**
 * Derives a key from a password and salt using PBKDF2.
 * @param {string} password - The user's password.
 * @param {Uint8Array} salt - The salt for key derivation.
 * @returns {Promise<CryptoKey>} The derived CryptoKey.
 */
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

// --- Event Listeners ---

// Google Drive event listeners
if (connectDriveBtn) {
    connectDriveBtn.addEventListener('click', connectGoogleDrive);
}

if (disconnectDriveBtn) {
    disconnectDriveBtn.addEventListener('click', disconnectGoogleDrive);
}

// File input event listeners
if (fileInput) {
    fileInput.addEventListener('change', () => {
        // Clear previous crypto data and UI state on new file selection
        if (downloadArea) downloadArea.classList.add('hidden');
        if (downloadEncryptedArea) downloadEncryptedArea.classList.add('hidden');
        if (statusMessageDiv) statusMessageDiv.textContent = ''; // Clear status message
        selectedFileIdForDecryption = null; // Clear any previously selected file from list
        if (decryptButton) decryptButton.textContent = 'Decrypt Selected File'; // Reset button text

        if (fileInput.files.length > 0) {
            if (selectedFileNameSpan) selectedFileNameSpan.textContent = fileInput.files[0].name;
            // If a file is selected via input, we assume decryption will happen via this file
            // and not from the list.
            if (decryptButton) decryptButton.textContent = 'Decrypt Uploaded File';
        } else {
            if (selectedFileNameSpan) selectedFileNameSpan.textContent = 'No file selected.';
            if (decryptButton) decryptButton.textContent = 'Decrypt Selected File';
        }
    });
}

if (clearFileButton) {
    clearFileButton.addEventListener('click', () => {
        if (fileInput) fileInput.value = ''; // Clear the file input itself
        if (selectedFileNameSpan) selectedFileNameSpan.textContent = 'No file selected.';
        if (downloadArea) downloadArea.classList.add('hidden');
        if (downloadEncryptedArea) downloadEncryptedArea.classList.add('hidden');
        showStatusMessage('File selection cleared.', 'info');
        selectedFileIdForDecryption = null; // Clear selected file from list
        selectedFileStorageLocation = null;
        if (decryptButton) decryptButton.textContent = 'Decrypt Selected File'; // Reset button text
    });
}

// Encrypt button event listener
if (encryptButton) {
    encryptButton.addEventListener('click', async () => {
        if (downloadArea) downloadArea.classList.add('hidden');
        if (downloadEncryptedArea) downloadEncryptedArea.classList.add('hidden');

        const file = fileInput ? fileInput.files[0] : null;
        const recoveryPhrase = recoveryPhraseInput ? recoveryPhraseInput.value.trim() : '';

        if (!file) {
            showStatusMessage('Please select a file to encrypt.', 'error');
            return;
        }
        if (!recoveryPhrase) {
            showStatusMessage('Please enter a recovery phrase.', 'error');
            return;
        }
        if (recoveryPhrase.length < 6) {
            showStatusMessage("Recovery phrase must be at least 6 characters long.", 'error');
            return;
        }
        if (!currentUser || !currentUser.user_id) {
            showStatusMessage('User not logged in. Please log out and log in again.', 'error');
            return;
        }

        showStatusMessage('Encrypting... Please wait.', 'info');

        try {
            const fileDataBuffer = await file.arrayBuffer(); // Read file as ArrayBuffer

            const salt = window.crypto.getRandomValues(new Uint8Array(16));
            const keyWrappingIv = window.crypto.getRandomValues(new Uint8Array(12));
            const wrappingKey = await deriveKey(recoveryPhrase, salt);

            const fileKey = await window.crypto.subtle.generateKey(
                { name: 'AES-GCM', length: 256 },
                true,
                ['encrypt', 'decrypt']
            );

            const wrappedKey = await window.crypto.subtle.wrapKey(
                'raw',
                fileKey,
                wrappingKey,
                { name: 'AES-GCM', iv: keyWrappingIv }
            );

            const iv = window.crypto.getRandomValues(new Uint8Array(12));
            const encryptedContentBuffer = await window.crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv },
                fileKey,
                fileDataBuffer
            );

            const fileId = generateUUID(); // Generate UUID for this file

            // Prepend fileId to the encrypted content for self-contained decryption
            const fileIdBytes = new TextEncoder().encode(fileId + '|'); // Add a delimiter
            const combinedEncryptedData = new Uint8Array(fileIdBytes.byteLength + encryptedContentBuffer.byteLength);
            combinedEncryptedData.set(fileIdBytes, 0);
            combinedEncryptedData.set(new Uint8Array(encryptedContentBuffer), fileIdBytes.byteLength);

            const encryptedContentBlob = new Blob([combinedEncryptedData], { type: 'application/octet-stream' });

            // Prepare FormData for upload
            const formData = new FormData();
            formData.append('userId', currentUser.user_id);
            formData.append('fileId', fileId); // Send fileId to backend for metadata
            formData.append('originalFileName', file.name);
            formData.append('wrappedKey', bufferToBase64(wrappedKey));
            formData.append('iv', bufferToBase64(iv));
            formData.append('salt', bufferToBase64(salt));
            formData.append('keyWrappingIv', bufferToBase64(keyWrappingIv));
            formData.append('encryptedFile', encryptedContentBlob, file.name); // Append the actual encrypted file content (with prepended ID)

            const response = await fetch(`${API_BASE_URL}/keys`, {
                method: 'POST',
                body: formData,
            });

            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.error || `Server error: ${response.statusText}`);
            }

            showStatusMessage('File encrypted and uploaded successfully!', 'success');
            if (recoveryPhraseInput) recoveryPhraseInput.value = ''; // Clear recovery phrase after successful upload

            // Make encrypted file downloadable directly from frontend (optional, but good for testing)
            const encryptedDownloadUrl = URL.createObjectURL(encryptedContentBlob);
            if (downloadEncryptedLink) {
                downloadEncryptedLink.href = encryptedDownloadUrl;
                downloadEncryptedLink.download = `encrypted_${file.name}.enc`;
            }
            if (downloadEncryptedArea) downloadEncryptedArea.classList.remove('hidden');

            loadUserFiles(); // Reload the file list to show the newly encrypted file

        } catch (error) {
            console.error('Encryption and upload failed:', error);
            showStatusMessage(`Encryption and upload failed: ${error.message}. Check console for details.`, 'error');
        }
    });
}

// Encrypt to Drive button event listener
if (encryptToDriveButton) {
    encryptToDriveButton.addEventListener('click', async () => {
        if (!isGoogleDriveConnected) {
            showStatusMessage('Please connect Google Drive first.', 'error');
            return;
        }
        
        if (downloadArea) downloadArea.classList.add('hidden');
        if (downloadEncryptedArea) downloadEncryptedArea.classList.add('hidden');

        const file = fileInput ? fileInput.files[0] : null;
        const recoveryPhrase = recoveryPhraseInput ? recoveryPhraseInput.value.trim() : '';

        if (!file) {
            showStatusMessage('Please select a file to encrypt.', 'error');
            return;
        }
        if (!recoveryPhrase) {
            showStatusMessage('Please enter a recovery phrase.', 'error');
            return;
        }
        if (recoveryPhrase.length < 6) {
            showStatusMessage("Recovery phrase must be at least 6 characters long.", 'error');
            return;
        }

        showStatusMessage('Encrypting and uploading to Google Drive... Please wait.', 'info');

        try {
            const fileDataBuffer = await file.arrayBuffer();

            const salt = window.crypto.getRandomValues(new Uint8Array(16));
            const keyWrappingIv = window.crypto.getRandomValues(new Uint8Array(12));
            const wrappingKey = await deriveKey(recoveryPhrase, salt);

            const fileKey = await window.crypto.subtle.generateKey(
                { name: 'AES-GCM', length: 256 },
                true,
                ['encrypt', 'decrypt']
            );

            const wrappedKey = await window.crypto.subtle.wrapKey(
                'raw',
                fileKey,
                wrappingKey,
                { name: 'AES-GCM', iv: keyWrappingIv }
            );

            const iv = window.crypto.getRandomValues(new Uint8Array(12));
            const encryptedContentBuffer = await window.crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv },
                fileKey,
                fileDataBuffer
            );

            const fileId = generateUUID();

            // Prepend fileId to encrypted content
            const fileIdBytes = new TextEncoder().encode(fileId + '|');
            const combinedEncryptedData = new Uint8Array(fileIdBytes.byteLength + encryptedContentBuffer.byteLength);
            combinedEncryptedData.set(fileIdBytes, 0);
            combinedEncryptedData.set(new Uint8Array(encryptedContentBuffer), fileIdBytes.byteLength);

            const encryptedContentBlob = new Blob([combinedEncryptedData], { type: 'application/octet-stream' });

            // Upload to Google Drive
            const formData = new FormData();
            formData.append('userId', currentUser.user_id);
            formData.append('fileId', fileId);
            formData.append('originalFileName', file.name);
            formData.append('wrappedKey', bufferToBase64(wrappedKey));
            formData.append('iv', bufferToBase64(iv));
            formData.append('salt', bufferToBase64(salt));
            formData.append('keyWrappingIv', bufferToBase64(keyWrappingIv));
            formData.append('encryptedFile', encryptedContentBlob, file.name);

            const response = await fetch(`${API_BASE_URL}/drive/upload`, {
                method: 'POST',
                body: formData,
            });

            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.error || `Server error: ${response.statusText}`);
            }

            showStatusMessage('File encrypted and uploaded to Google Drive successfully!', 'success');
            if (recoveryPhraseInput) recoveryPhraseInput.value = '';
            loadUserFiles(); // Reload the file list to show the newly encrypted file

        } catch (error) {
            console.error('Google Drive upload failed:', error);
            showStatusMessage(`Google Drive upload failed: ${error.message}`, 'error');
        }
    });
}

// Decrypt button event listener
if (decryptButton) {
    decryptButton.addEventListener('click', async () => {
        if (downloadArea) downloadArea.classList.add('hidden');
        const recoveryPhrase = recoveryPhraseInput ? recoveryPhraseInput.value.trim() : '';

        if (!recoveryPhrase) {
            showStatusMessage('Please enter your recovery phrase.', 'error');
            return;
        }
        if (!currentUser || !currentUser.user_id) {
            showStatusMessage('User not logged in. Please log in to decrypt files.', 'error');
            return;
        }

        let fileIdToDecrypt = null;
        let encryptedContentBuffer = null;
        let originalFileNameFromUpload = null; // To store if decryption is from uploaded file

        // Determine if decryption is from selected file in list or uploaded file
        if (selectedFileIdForDecryption) {
            // Decrypting from selected file in list (metadata fetched, actual file content needs to be fetched)
            showStatusMessage('Fetching encrypted file content and metadata... Please wait.', 'info');
            fileIdToDecrypt = selectedFileIdForDecryption;

            try {
                let fileBlob;
                
                if (selectedFileStorageLocation === 'google_drive') {
                    // Fetch from Google Drive
                    const fileResponse = await fetch(`${API_BASE_URL}/drive/download/${currentUser.user_id}/${fileIdToDecrypt}`);
                    if (!fileResponse.ok) {
                        const errorData = await fileResponse.json();
                        throw new Error(errorData.error || 'Could not fetch encrypted file from Google Drive.');
                    }
                    fileBlob = await fileResponse.blob();
                } else {
                    // Fetch from local storage
                    const fileResponse = await fetch(`${API_BASE_URL}/files/${currentUser.user_id}/${fileIdToDecrypt}`);
                    if (!fileResponse.ok) {
                        const errorData = await fileResponse.json();
                        throw new Error(errorData.error || 'Could not fetch encrypted file from local storage.');
                    }
                    fileBlob = await fileResponse.blob();
                }

                const fullEncryptedBuffer = await fileBlob.arrayBuffer();
                const fullEncryptedBytes = new Uint8Array(fullEncryptedBuffer);

                // Extract fileId and content
                let fileIdString = '';
                let delimiterIndex = -1;
                const textDecoder = new TextDecoder();
                for (let i = 0; i < fullEncryptedBytes.byteLength && i < 40; i++) {
                    const char = textDecoder.decode(fullEncryptedBytes.slice(i, i + 1));
                    if (char === '|') {
                        delimiterIndex = i;
                        break;
                    }
                    fileIdString += char;
                }

                if (delimiterIndex === -1 || fileIdString !== fileIdToDecrypt) {
                    throw new Error("Invalid encrypted file format or mismatched File ID.");
                }
                encryptedContentBuffer = fullEncryptedBuffer.slice(delimiterIndex + 1);

            } catch (error) {
                console.error('Error fetching encrypted file:', error);
                showStatusMessage(`Failed to fetch encrypted file: ${error.message}`, 'error');
                return;
            }

        } else if (fileInput && fileInput.files[0]) {
            // Decrypting from uploaded file (content already in browser, need to extract fileId)
            showStatusMessage('Reading uploaded encrypted file and fetching metadata... Please wait.', 'info');
            const selectedEncryptedFile = fileInput.files[0];
            originalFileNameFromUpload = selectedEncryptedFile.name; // Store original name from uploaded file

            try {
                const fullEncryptedBuffer = await selectedEncryptedFile.arrayBuffer();
                const fullEncryptedBytes = new Uint8Array(fullEncryptedBuffer);

                let fileIdString = '';
                let delimiterIndex = -1;
                const textDecoder = new TextDecoder();
                for (let i = 0; i < fullEncryptedBytes.byteLength && i < 40; i++) { // Max UUID is 36 chars + 1 for delimiter
                    const char = textDecoder.decode(fullEncryptedBytes.slice(i, i + 1));
                    if (char === '|') {
                        delimiterIndex = i;
                        break;
                    }
                    fileIdString += char;
                }

                if (delimiterIndex === -1 || fileIdString.length === 0) {
                    throw new Error("Invalid encrypted file format: File ID not found or missing delimiter.");
                }

                fileIdToDecrypt = fileIdString;
                encryptedContentBuffer = fullEncryptedBuffer.slice(delimiterIndex + 1);

            } catch (error) {
                console.error('Error reading uploaded encrypted file:', error);
                showStatusMessage(`Failed to read uploaded encrypted file: ${error.message || error}.`, 'error');
                return;
            }

        } else {
            showStatusMessage('Please select an encrypted file from your list or upload one.', 'error');
            return;
        }

        // Now, fetch key metadata using the determined fileIdToDecrypt
        try {
            const response = await fetch(`${API_BASE_URL}/keys/${currentUser.user_id}/${fileIdToDecrypt}`);
            const keyData = await response.json();

            if (!response.ok) {
                throw new Error(keyData.error || 'Could not fetch file metadata from server.');
            }

            const unwrappedIv = base64ToBuffer(keyData.iv);
            const unwrappedSalt = base64ToBuffer(keyData.salt);
            const unwrappedWrappedKey = base64ToBuffer(keyData.wrappedKey);
            const unwrappedKeyWrappingIv = base64ToBuffer(keyData.keyWrappingIv);

            const wrappingKey = await deriveKey(recoveryPhrase, unwrappedSalt);

            const aesGcmKey = await window.crypto.subtle.unwrapKey(
                "raw",
                unwrappedWrappedKey,
                wrappingKey,
                { name: "AES-GCM", iv: unwrappedKeyWrappingIv },
                { name: "AES-GCM", length: 256 },
                true,
                ["encrypt", "decrypt"]
            );

            const decryptedContent = await window.crypto.subtle.decrypt(
                { name: "AES-GCM", iv: unwrappedIv },
                aesGcmKey,
                encryptedContentBuffer // Use the buffer (either fetched or from uploaded file)
            );

            const decryptedBlob = new Blob([decryptedContent], { type: 'application/octet-stream' });
            const downloadUrl = URL.createObjectURL(decryptedBlob);

            if (downloadLink) {
                downloadLink.href = downloadUrl;
                // Use originalFileName from metadata or from uploaded file if available
                downloadLink.download = `decrypted_${keyData.originalFileName || originalFileNameFromUpload || 'file'}`;
            }
            if (downloadArea) downloadArea.classList.remove('hidden');
            showStatusMessage('File decrypted successfully! Download ready.', 'success');
            if (recoveryPhraseInput) recoveryPhraseInput.value = ''; // Clear recovery phrase

            // Clear file input and reset selected file for decryption after successful decryption
            if (fileInput) fileInput.value = '';
            if (selectedFileNameSpan) selectedFileNameSpan.textContent = 'No file selected.';
            selectedFileIdForDecryption = null;
            selectedFileStorageLocation = null;
            if (decryptButton) decryptButton.textContent = 'Decrypt Selected File';

        } catch (error) {
            console.error('Decryption failed:', error);
            showStatusMessage(`Decryption failed: ${error.message || error}. Ensure the correct recovery phrase and the correct encrypted file were used.`, 'error');
            if (downloadArea) downloadArea.classList.add('hidden');
        }
    });
}

// --- File Listing Logic ---

/**
 * Fetches and displays the current user's encrypted files.
 */
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
        const files = await response.json();

        userFilesListDiv.innerHTML = ''; // Clear previous list

        if (files.length === 0) {
            userFilesListDiv.innerHTML = '<p class="text-gray-500 text-center">No files encrypted yet. Encrypt one above!</p>';
            return;
        }

        files.forEach(file => {
            const storageIcon = file.storageLocation === 'google_drive' ? '📁' : '💾';
            const storageText = file.storageLocation === 'google_drive' ? 'Google Drive' : 'Local';
            
            const fileItem = document.createElement('div');
            fileItem.className = 'flex items-center justify-between bg-white p-3 rounded-lg shadow-sm hover:shadow-md transition-shadow duration-200';
            fileItem.innerHTML = `
                <div class="flex-1 overflow-hidden">
                    <p class="font-semibold text-gray-800 truncate">${file.originalFileName}</p>
                    <p class="text-xs text-gray-500">ID: <span class="font-mono text-blue-600">${file.fileId}</span></p>
                    <p class="text-xs text-gray-500">
                        <span class="mr-2">${storageIcon} ${storageText}</span>
                        | Encrypted: ${new Date(file.createdAt).toLocaleString()}
                    </p>
                </div>
                <div class="flex space-x-2 ml-4">
                    <button data-file-id="${file.fileId}" data-storage="${file.storageLocation || 'local'}"
                            class="decrypt-from-list-btn bg-[#06D6A0] text-white text-sm py-1 px-3 rounded-md font-semibold
                                   hover:bg-[#118AB2] transition-colors duration-200 shadow-sm">
                        Decrypt
                    </button>
                    <button data-file-id="${file.fileId}"
                            class="delete-file-btn bg-[#FF6B6B] text-white text-sm py-1 px-3 rounded-md font-semibold
                                   hover:bg-[#FFD166] transition-colors duration-200 shadow-sm">
                        Delete
                    </button>
                </div>
            `;
            userFilesListDiv.appendChild(fileItem);
        });

        // Add event listeners to the new decrypt buttons in the list
        document.querySelectorAll('.decrypt-from-list-btn').forEach(button => {
            button.addEventListener('click', (e) => {
                const fileId = e.target.dataset.fileId;
                const storageLocation = e.target.dataset.storage;
                selectedFileIdForDecryption = fileId; // Set the global variable
                selectedFileStorageLocation = storageLocation;
                if (decryptButton) {
                    decryptButton.textContent = `Decrypt '${fileId.substring(0, 8)}...' (${storageLocation === 'google_drive' ? 'Drive' : 'Local'})`;
                }
                showStatusMessage(`File selected for decryption: ${fileId.substring(0, 8)}... from ${storageLocation === 'google_drive' ? 'Google Drive' : 'Local storage'}`, 'info');
                if (fileInput) fileInput.value = ''; // Clear file input if a file from list is selected
                if (selectedFileNameSpan) selectedFileNameSpan.textContent = 'No file selected.';
            });
        });

        // Add event listeners to the new delete buttons
        document.querySelectorAll('.delete-file-btn').forEach(button => {
            button.addEventListener('click', (e) => {
                const fileId = e.target.dataset.fileId;
                if (confirm('Are you sure you want to delete this file metadata and encrypted content? This action cannot be undone.')) {
                    deleteFile(fileId);
                }
            });
        });

    } catch (error) {
        console.error('Error loading user files:', error);
        if (userFilesListDiv) {
            userFilesListDiv.innerHTML = `<p class="text-red-600 text-center">Failed to load files: ${error.message}</p>`;
        }
    }
}

/**
 * Handles deleting a file from the backend.
 * @param {string} fileId - The ID of the file to delete.
 */
async function deleteFile(fileId) {
    if (!currentUser || !currentUser.user_id) {
        showStatusMessage('User not logged in. Cannot delete file.', 'error');
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
        loadUserFiles(); // Reload the list after deletion
    } catch (error) {
        console.error('Error deleting file:', error);
        showStatusMessage(`Failed to delete file: ${error.message}.`, 'error');
    }
}

// --- Initial UI State ---
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

// Run on page load
document.addEventListener('DOMContentLoaded', checkInitialAuthState);

// Add event listeners for auth tabs (since they are now part of regular script)
authTabs.forEach(tab => {
    tab.addEventListener('click', (e) => switchAuthTab(e.target.dataset.tab));
});