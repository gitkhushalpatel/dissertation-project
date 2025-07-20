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

// New DOM elements for file listing
const userFilesListDiv = document.getElementById('userFilesList');
const noFilesMessage = document.getElementById('noFilesMessage');

const API_BASE_URL = 'http://127.0.0.1:5000/api';

// Global state for current user and selected file for decryption
let currentUser = null;
let selectedFileIdForDecryption = null; // Stores the fileId of the file selected from the list

// --- Utility Functions ---

/**
 * Displays a message to the user within the main app section.
 * @param {string} text - The message to display.
 * @param {'success' | 'error' | 'info'} type - The type of message.
 */
function showStatusMessage(text, type) {
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

/**
 * Displays a message to the user within the authentication section.
 * @param {string} message - The message to display.
 * @param {string} type - 'success' or 'error'.
 */
function showAuthMessage(message, type) {
    authMessageDiv.textContent = message;
    authMessageDiv.className = `mt-4 p-3 rounded-lg text-center ${type === 'error' ? 'bg-red-100 text-red-700' : 'bg-green-100 text-green-700'}`;
    authMessageDiv.classList.remove('hidden');
}

function clearAuthMessage() {
    authMessageDiv.classList.add('hidden');
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
    authSection.classList.add('hidden');
    mainApp.classList.remove('hidden');
    navbar.classList.remove('hidden');
    welcomeUserSpan.textContent = `Welcome, ${currentUser.username}`;
    loadUserFiles(); // Load user's files after login
}

/**
 * Updates the UI after a logout.
 */
function updateUIForLogout() {
    authSection.classList.remove('hidden');
    mainApp.classList.add('hidden');
    navbar.classList.add('hidden');
    welcomeUserSpan.textContent = '';
    userFilesListDiv.innerHTML = '<p class="text-gray-500 text-center" id="noFilesMessage">No files encrypted yet. Encrypt one above!</p>'; // Clear file list
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
    activeTab.classList.add('active', 'bg-white', 'shadow-sm');

    document.getElementById(`${tabToActivate}Form`).classList.remove('hidden');
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
    const btnText = button.querySelector('.btn-text');
    const btnLoading = button.querySelector('.btn-loading');
    
    if (loading) {
        button.disabled = true;
        btnText.classList.add('hidden');
        btnLoading.classList.remove('hidden');
    } else {
        button.disabled = false;
        btnText.classList.remove('hidden');
        btnLoading.classList.add('hidden');
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

// --- File Encryption & Decryption Handlers ---

fileInput.addEventListener('change', () => {
    // Clear previous crypto data and UI state on new file selection
    downloadArea.classList.add('hidden');
    downloadEncryptedArea.classList.add('hidden');
    statusMessageDiv.textContent = ''; // Clear status message
    selectedFileIdForDecryption = null; // Clear any previously selected file from list
    decryptButton.textContent = 'Decrypt Selected File'; // Reset button text

    if (fileInput.files.length > 0) {
        selectedFileNameSpan.textContent = fileInput.files[0].name;
        // If a file is selected via input, we assume decryption will happen via this file
        // and not from the list.
        decryptButton.textContent = 'Decrypt Uploaded File';
    } else {
        selectedFileNameSpan.textContent = 'No file selected.';
        decryptButton.textContent = 'Decrypt Selected File';
    }
});

clearFileButton.addEventListener('click', () => {
    fileInput.value = ''; // Clear the file input itself
    selectedFileNameSpan.textContent = 'No file selected.';
    downloadArea.classList.add('hidden');
    downloadEncryptedArea.classList.add('hidden');
    statusMessageDiv.textContent = 'File selection cleared.';
    statusMessageDiv.style.color = '#FF6B6B'; // Using direct style for quick clear
    selectedFileIdForDecryption = null; // Clear selected file from list
    decryptButton.textContent = 'Decrypt Selected File'; // Reset button text
});


encryptButton.addEventListener('click', async () => {
    downloadArea.classList.add('hidden');
    downloadEncryptedArea.classList.add('hidden');

    const file = fileInput.files[0];
    const recoveryPhrase = recoveryPhraseInput.value.trim();

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
        recoveryPhraseInput.value = ''; // Clear recovery phrase after successful upload

        // Make encrypted file downloadable directly from frontend (optional, but good for testing)
        const encryptedDownloadUrl = URL.createObjectURL(encryptedContentBlob);
        downloadEncryptedLink.href = encryptedDownloadUrl;
        downloadEncryptedLink.download = `encrypted_${file.name}.enc`;
        downloadEncryptedArea.classList.remove('hidden');

        loadUserFiles(); // Reload the file list to show the newly encrypted file

    } catch (error) {
        console.error('Encryption and upload failed:', error);
        showStatusMessage(`Encryption and upload failed: ${error.message}. Check console for details.`, 'error');
    }
});


decryptButton.addEventListener('click', async () => {
    downloadArea.classList.add('hidden');
    const recoveryPhrase = recoveryPhraseInput.value.trim();

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
            // Fetch the entire encrypted file content from the backend
            const fileResponse = await fetch(`${API_BASE_URL}/files/${currentUser.user_id}/${fileIdToDecrypt}`);
            if (!fileResponse.ok) {
                const errorData = await fileResponse.json();
                throw new Error(errorData.error || 'Could not fetch encrypted file content from server.');
            }
            const fileBlob = await fileResponse.blob();
            const fullEncryptedBuffer = await fileBlob.arrayBuffer();
            const fullEncryptedBytes = new Uint8Array(fullEncryptedBuffer);

            // Extract fileId and actual encrypted content from the fetched file
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

            if (delimiterIndex === -1 || fileIdString.length === 0 || fileIdString !== fileIdToDecrypt) {
                throw new Error("Invalid encrypted file format or mismatched File ID.");
            }
            encryptedContentBuffer = fullEncryptedBuffer.slice(delimiterIndex + 1);

        } catch (error) {
            console.error('Error fetching encrypted file content:', error);
            showStatusMessage(`Failed to fetch encrypted file: ${error.message || error}.`, 'error');
            return;
        }

    } else if (fileInput.files[0]) {
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

        downloadLink.href = downloadUrl;
        // Use originalFileName from metadata or from uploaded file if available
        downloadLink.download = `decrypted_${keyData.originalFileName || originalFileNameFromUpload || 'file'}`;
        downloadArea.classList.remove('hidden');
        showStatusMessage('File decrypted successfully! Download ready.', 'success');
        recoveryPhraseInput.value = ''; // Clear recovery phrase

        // Clear file input and reset selected file for decryption after successful decryption
        fileInput.value = '';
        selectedFileNameSpan.textContent = 'No file selected.';
        selectedFileIdForDecryption = null;
        decryptButton.textContent = 'Decrypt Selected File';

    } catch (error) {
        console.error('Decryption failed:', error);
        showStatusMessage(`Decryption failed: ${error.message || error}. Ensure the correct recovery phrase and the correct encrypted file were used.`, 'error');
        downloadArea.classList.add('hidden');
    }
});


// --- File Listing Logic ---

/**
 * Fetches and displays the current user's encrypted files.
 */
async function loadUserFiles() {
    if (!currentUser || !currentUser.user_id) {
        userFilesListDiv.innerHTML = '<p class="text-gray-500 text-center">Please log in to see your files.</p>';
        return;
    }

    userFilesListDiv.innerHTML = '<p class="text-gray-500 text-center">Loading files...</p>';
    noFilesMessage.classList.add('hidden'); // Hide "No files" message while loading

    try {
        const response = await fetch(`${API_BASE_URL}/keys/${currentUser.user_id}`);
        const files = await response.json();

        userFilesListDiv.innerHTML = ''; // Clear previous list

        if (files.length === 0) {
            userFilesListDiv.innerHTML = '<p class="text-gray-500 text-center" id="noFilesMessage">No files encrypted yet. Encrypt one above!</p>';
            noFilesMessage.classList.remove('hidden'); // Ensure message is visible
            return;
        }

        files.forEach(file => {
            const fileItem = document.createElement('div');
            fileItem.className = 'flex items-center justify-between bg-white p-3 rounded-lg shadow-sm hover:shadow-md transition-shadow duration-200';
            fileItem.innerHTML = `
                <div class="flex-1 overflow-hidden">
                    <p class="font-semibold text-gray-800 truncate">${file.originalFileName}</p>
                    <p class="text-xs text-gray-500">ID: <span class="font-mono text-blue-600">${file.fileId}</span></p>
                    <p class="text-xs text-gray-500">Encrypted: ${new Date(file.createdAt).toLocaleString()}</p>
                </div>
                <div class="flex space-x-2 ml-4">
                    <button data-file-id="${file.fileId}"
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
                selectedFileIdForDecryption = fileId; // Set the global variable
                decryptButton.textContent = `Decrypt '${fileId.substring(0, 8)}...'`; // Update main decrypt button text
                showStatusMessage(`File selected for decryption: ${fileId.substring(0, 8)}...`, 'info');
                fileInput.value = ''; // Clear file input if a file from list is selected
                selectedFileNameSpan.textContent = 'No file selected.';
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
        userFilesListDiv.innerHTML = `<p class="text-red-600 text-center">Failed to load files: ${error.message}</p>`;
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
