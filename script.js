// Get references to our HTML elements
const form = document.getElementById('crypto-form');
const fileInput = document.getElementById('file-input');
const passwordInput = document.getElementById('password');
const statusArea = document.getElementById('status-area');
const statusMessage = document.getElementById('status-message');
const downloadLink = document.getElementById('download-link');
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

// Listen for the form submission
form.addEventListener('submit', async (event) => {
    event.preventDefault(); // Prevent the form from actually submitting

    // Get user inputs
    const operation = document.querySelector('input[name="operation"]:checked').value;
    const file = fileInput.files[0];
    const password = passwordInput.value;

    // Basic validation
    if (!file || !password) {
        updateStatus('Please provide a file and a password.', 'error');
        return;
    }

    // Show processing message
    updateStatus('Processing your file...', 'processing');

    try {
        // STEP 1: Read the file content into an ArrayBuffer
        const fileBuffer = await file.arrayBuffer();

        // STEP 2: Derive a cryptographic key from the password
        const key = await getKeyFromPassword(password);

        let resultBuffer;
        let outputFilename;

        // STEP 3: Perform encryption or decryption
        if (operation === 'encrypt') {
            // Encrypt the file data
            const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 12 bytes for AES-GCM
            const encryptedContent = await window.crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv },
                key,
                fileBuffer
            );

            // NEW: Store original filename inside the encrypted file.
            // This allows us to restore it perfectly on decryption.
            const filenameBytes = textEncoder.encode(file.name);
            if (filenameBytes.length > 255) {
                throw new Error("Filename is too long (max 255 bytes).");
            }

            // Create a combined buffer with the following structure:
            // [1 byte for filename length] -> [filename bytes] -> [12 bytes for IV] -> [encrypted data]
            const combinedBuffer = new Uint8Array(1 + filenameBytes.length + iv.length + encryptedContent.byteLength);
            combinedBuffer[0] = filenameBytes.length;
            combinedBuffer.set(filenameBytes, 1);
            combinedBuffer.set(iv, 1 + filenameBytes.length);
            combinedBuffer.set(new Uint8Array(encryptedContent), 1 + filenameBytes.length + iv.length);
            resultBuffer = combinedBuffer.buffer;
            
            // Create the output filename, e.g., 'mydoc.txt' -> 'mydoc.enc'
            const originalName = file.name;
            const lastDot = originalName.lastIndexOf('.');
            const baseName = (lastDot > 0) ? originalName.substring(0, lastDot) : originalName;
            outputFilename = baseName + '.enc';
            
            updateStatus('Encryption successful!', 'success');

        } else { // Decryption
            // NEW: Extract the original filename and IV from the file structure.
            const dataView = new DataView(fileBuffer);
            if (fileBuffer.byteLength < 1) {
                    throw new Error("Invalid encrypted file.");
            }
            const filenameLength = dataView.getUint8(0);
            
            const filenameEnd = 1 + filenameLength;
            const ivEnd = filenameEnd + 12;

            if (fileBuffer.byteLength < ivEnd) {
                throw new Error("Invalid encrypted file: file is too short.");
            }

            const filenameBytes = new Uint8Array(fileBuffer.slice(1, filenameEnd));
            outputFilename = textDecoder.decode(filenameBytes); // Restore the original filename

            const iv = new Uint8Array(fileBuffer.slice(filenameEnd, ivEnd));
            const encryptedContent = fileBuffer.slice(ivEnd);

            // Decrypt the content using the extracted IV
            resultBuffer = await window.crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: iv },
                key,
                encryptedContent
            );

            updateStatus('Decryption successful!', 'success');
        }

        // STEP 4: Create a downloadable link for the result
        createDownloadLink(resultBuffer, outputFilename);

    } catch (error) {
        console.error('An error occurred:', error);
        // The most common error during decryption is a wrong password or corrupted file.
        updateStatus('Operation failed. Please check your password and file.', 'error');
    }
});

/**
 * Derives a 256-bit AES-GCM key from a user-provided password.
 * @param {string} password - The password to derive the key from.
 * @returns {Promise<CryptoKey>} A promise that resolves to the derived CryptoKey.
 */
async function getKeyFromPassword(password) {
    const passwordBuffer = textEncoder.encode(password);
    const salt = textEncoder.encode('a-very-secret-salt'); 

    const baseKey = await window.crypto.subtle.importKey(
        'raw',
        passwordBuffer,
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );

    return await window.crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256'
        },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    );
}

/**
 * Creates a Blob from the result buffer and sets up the download link.
 * @param {ArrayBuffer} buffer - The data to be downloaded.
 * @param {string} filename - The name for the downloaded file.
 */
function createDownloadLink(buffer, filename) {
    const blob = new Blob([buffer], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    downloadLink.href = url;
    downloadLink.download = filename;
    downloadLink.classList.remove('hidden');
}

/**
 * Updates the status message and its color.
 * @param {string} message - The message to display.
 * @param {'processing'|'success'|'error'} type - The type of message.
 */
function updateStatus(message, type) {
    statusArea.classList.remove('hidden');
    statusMessage.textContent = message;
    
    // Reset colors
    statusMessage.classList.remove('text-blue-600', 'text-green-600', 'text-red-600');
    downloadLink.classList.add('hidden'); // Hide download link by default

    if (type === 'processing') {
        statusMessage.classList.add('text-blue-600');
    } else if (type === 'success') {
        statusMessage.classList.add('text-green-600');
    } else if (type === 'error') {
        statusMessage.classList.add('text-red-600');
    }
}
