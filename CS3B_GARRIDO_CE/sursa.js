/*
 * JavaScript for PB1-LQ1 RSA Encryption and Decryption Activity
 * Author: CS3B_LASTNAME_I
 * Purpose: Implement RSA 1024-bit and RSA 3072-bit encryption/decryption using JSEncrypt
 * Note: RSA can only encrypt small messages directly. This implementation uses chunking for longer messages.
 */

// Global variables to store RSA key pairs
let keyPair1024 = null;
let keyPair3072 = null;

/**
 * Generate RSA key pair with specified bit size
 * @param {number} bits - The key size in bits (1024 or 3072)
 * @returns {Object} Object containing publicKey and privateKey
 */
function generateRSAKeyPair(bits) {
    try {
        // Create JSEncrypt instance with specified key size
        const crypt = new JSEncrypt({ default_key_size: bits });
        
        // Generate the key pair
        crypt.getKey();
        
        // Retrieve public and private keys
        const publicKey = crypt.getPublicKey();
        const privateKey = crypt.getPrivateKey();
        
        if (!publicKey || !privateKey) {
            throw new Error("Failed to generate RSA keys. Please try again.");
        }
        
        return {
            publicKey: publicKey,
            privateKey: privateKey,
            bits: bits
        };
    } catch (error) {
        throw new Error("Error generating RSA key pair (" + bits + "-bit): " + error.message);
    }
}

/**
 * Calculate maximum bytes that can be encrypted with RSA key using PKCS1 padding
 * Formula: max bytes = (keySize/8) - 11 (for PKCS1 v1.5 padding overhead)
 * @param {number} bits - Key size in bits
 * @returns {number} Maximum number of bytes
 */
function getMaxEncryptBytes(bits) {
    // RSA PKCS1 v1.5 padding adds 11 bytes of overhead
    const keySizeInBytes = Math.floor(bits / 8);
    const maxBytes = keySizeInBytes - 11;
    return maxBytes;
}

/**
 * Encrypt data using RSA with chunking support for messages exceeding key size limit
 * @param {string} data - Data to encrypt
 * @param {string} publicKey - RSA public key
 * @param {number} bits - Key size in bits
 * @returns {string} Base64 encoded encrypted data (chunks separated by ||CHUNK|| if chunked)
 */
function encryptWithRSA(data, publicKey, bits) {
    try {
        const maxBytes = getMaxEncryptBytes(bits);
        const dataBytes = new TextEncoder().encode(data);
        
        // Check if data can be encrypted directly without chunking
        if (dataBytes.length <= maxBytes) {
            const crypt = new JSEncrypt({ default_key_size: bits });
            crypt.setPublicKey(publicKey);
            const encrypted = crypt.encrypt(data);
            
            if (!encrypted) {
                throw new Error("Encryption failed. Data may be too large for this key size.");
            }
            
            return encrypted;
        }
        
        // For longer messages, implement chunking
        const chunks = [];
        // Use conservative character count per chunk for UTF-8 safety
        const charsPerChunk = Math.floor(maxBytes * 0.6);
        let index = 0;
        const dataString = data;
        
        while (index < dataString.length) {
            let chunk = dataString.substring(index, index + charsPerChunk);
            index += charsPerChunk;
            
            // Encrypt each chunk
            const chunkCrypt = new JSEncrypt({ default_key_size: bits });
            chunkCrypt.setPublicKey(publicKey);
            const encryptedChunk = chunkCrypt.encrypt(chunk);
            
            if (!encryptedChunk) {
                throw new Error("Chunk encryption failed. Unable to encrypt message.");
            }
            
            chunks.push(encryptedChunk);
        }
        
        // Join chunks with separator
        return chunks.join("||CHUNK||");
        
    } catch (error) {
        throw new Error("RSA encryption error: " + error.message);
    }
}

/**
 * Decrypt data using RSA with chunking support
 * @param {string} encryptedData - Encrypted data (may contain chunk separators ||CHUNK||)
 * @param {string} privateKey - RSA private key
 * @param {number} bits - Key size in bits
 * @returns {string} Decrypted data
 */
function decryptWithRSA(encryptedData, privateKey, bits) {
    try {
        // Check if data is chunked
        if (encryptedData.includes("||CHUNK||")) {
            const chunks = encryptedData.split("||CHUNK||");
            let decryptedResult = "";
            
            // Decrypt each chunk in order
            for (let i = 0; i < chunks.length; i++) {
                const chunkCrypt = new JSEncrypt({ default_key_size: bits });
                chunkCrypt.setPrivateKey(privateKey);
                const decryptedChunk = chunkCrypt.decrypt(chunks[i]);
                
                if (!decryptedChunk) {
                    throw new Error("Chunk decryption failed at chunk " + (i + 1));
                }
                
                decryptedResult += decryptedChunk;
            }
            
            return decryptedResult;
        } else {
            // Decrypt single chunk
            const crypt = new JSEncrypt({ default_key_size: bits });
            crypt.setPrivateKey(privateKey);
            const decrypted = crypt.decrypt(encryptedData);
            
            if (!decrypted) {
                throw new Error("Decryption failed. Invalid key or corrupted data.");
            }
            
            return decrypted;
        }
        
    } catch (error) {
        throw new Error("RSA decryption error: " + error.message);
    }
}

/**
 * Collect form data and perform validation
 * @returns {Object} Object containing isValid flag, data object, and validation status
 */
function collectAndValidateForm() {
    const errors = {};
    let isValid = true;
    
    // Get all form values
    const fullName = document.getElementById("fullName").value.trim();
    const dateOfBirth = document.getElementById("dateOfBirth").value;
    const yearLevel = document.getElementById("yearLevel").value;
    const gender = document.getElementById("gender").value;
    const username = document.getElementById("username").value.trim();
    const password = document.getElementById("password").value;
    
    // Clear all previous error messages
    const errorElements = document.querySelectorAll(".error-msg");
    errorElements.forEach(function(element) {
        element.textContent = "";
    });
    
    // Validate Full Name
    if (fullName === "") {
        errors.fullName = "Full Name is required.";
        isValid = false;
    } else if (fullName.length < 2) {
        errors.fullName = "Full Name must be at least 2 characters.";
        isValid = false;
    }
    
    // Validate Date of Birth
    if (dateOfBirth === "") {
        errors.dateOfBirth = "Date of Birth is required.";
        isValid = false;
    }
    
    // Validate Year Level
    if (yearLevel === "") {
        errors.yearLevel = "Year Level is required.";
        isValid = false;
    }
    
    // Validate Gender
    if (gender === "") {
        errors.gender = "Gender is required.";
        isValid = false;
    }
    
    // Validate Username
    if (username === "") {
        errors.username = "Username is required.";
        isValid = false;
    } else if (username.length < 3) {
        errors.username = "Username must be at least 3 characters.";
        isValid = false;
    } else if (!/^[a-zA-Z0-9_]+$/.test(username)) {
        errors.username = "Username can only contain letters, numbers, and underscores.";
        isValid = false;
    }
    
    // Validate Password
    if (password === "") {
        errors.password = "Password is required.";
        isValid = false;
    } else if (password.length < 6) {
        errors.password = "Password must be at least 6 characters.";
        isValid = false;
    }
    
    // Display error messages
    if (!isValid) {
        for (const field in errors) {
            const errorElement = document.getElementById("error-" + field);
            if (errorElement) {
                errorElement.textContent = errors[field];
            }
        }
    }
    
    // Return validation result
    if (isValid) {
        const formData = {
            fullName: fullName,
            dateOfBirth: dateOfBirth,
            yearLevel: yearLevel,
            gender: gender,
            username: username,
            password: password
        };
        return { isValid: true, data: formData };
    }
    
    return { isValid: false, data: null };
}

/**
 * Display message in the message area
 * @param {string} message - Message to display
 * @param {string} type - Message type: 'error', 'info', or 'success'
 */
function showMessage(message, type) {
    const messageArea = document.getElementById("messageArea");
    messageArea.textContent = message;
    messageArea.className = "message-area " + type;
    
    // Scroll to message area
    messageArea.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

/**
 * Clear all result displays
 */
function clearResults() {
    document.getElementById("originalInput").textContent = "";
    document.getElementById("encrypted1024").textContent = "";
    document.getElementById("decrypted1024").textContent = "";
    document.getElementById("encrypted3072").textContent = "";
    document.getElementById("decrypted3072").textContent = "";
    
    const match1024 = document.getElementById("match1024");
    match1024.textContent = "";
    match1024.className = "match-status";
    
    const match3072 = document.getElementById("match3072");
    match3072.textContent = "";
    match3072.className = "match-status";
    
    const messageArea = document.getElementById("messageArea");
    messageArea.textContent = "";
    messageArea.className = "message-area";
}

/**
 * Handle RSA 1024-bit encryption and decryption demonstration
 */
function handleEncrypt1024() {
    try {
        // Clear previous results
        clearResults();
        
        // Validate form
        const validation = collectAndValidateForm();
        if (!validation.isValid) {
            showMessage("Please fix the errors in the form before encrypting.", "error");
            return;
        }
        
        showMessage("Generating RSA 1024-bit key pair and performing encryption/decryption...", "info");
        
        // Generate key pair if not already generated
        if (keyPair1024 === null) {
            keyPair1024 = generateRSAKeyPair(1024);
        }
        
        // Convert form data to JSON
        const jsonData = JSON.stringify(validation.data, null, 2);
        document.getElementById("originalInput").textContent = jsonData;
        
        // Encrypt the data
        const encryptedData = encryptWithRSA(jsonData, keyPair1024.publicKey, 1024);
        document.getElementById("encrypted1024").textContent = encryptedData;
        
        // Decrypt the data
        const decryptedData = decryptWithRSA(encryptedData, keyPair1024.privateKey, 1024);
        document.getElementById("decrypted1024").textContent = decryptedData;
        
        // Check if original and decrypted match
        const matchElement = document.getElementById("match1024");
        if (jsonData === decryptedData) {
            matchElement.textContent = "✓ SUCCESS: Decryption is correct - Original data matches decrypted result!";
            matchElement.className = "match-status match";
        } else {
            matchElement.textContent = "✗ FAILED: Decryption error - Original data does not match decrypted result!";
            matchElement.className = "match-status no-match";
        }
        
        showMessage("RSA 1024-bit encryption and decryption completed successfully!", "success");
        
    } catch (error) {
        showMessage("Error: " + error.message, "error");
        console.error("RSA 1024-bit Error:", error);
    }
}

/**
 * Handle RSA 3072-bit encryption and decryption demonstration
 */
function handleEncrypt3072() {
    try {
        // Clear previous results
        clearResults();
        
        // Validate form
        const validation = collectAndValidateForm();
        if (!validation.isValid) {
            showMessage("Please fix the errors in the form before encrypting.", "error");
            return;
        }
        
        showMessage("Generating RSA 3072-bit key pair and performing encryption/decryption...", "info");
        
        // Generate key pair if not already generated
        if (keyPair3072 === null) {
            keyPair3072 = generateRSAKeyPair(3072);
        }
        
        // Convert form data to JSON
        const jsonData = JSON.stringify(validation.data, null, 2);
        document.getElementById("originalInput").textContent = jsonData;
        
        // Encrypt the data
        const encryptedData = encryptWithRSA(jsonData, keyPair3072.publicKey, 3072);
        document.getElementById("encrypted3072").textContent = encryptedData;
        
        // Decrypt the data
        const decryptedData = decryptWithRSA(encryptedData, keyPair3072.privateKey, 3072);
        document.getElementById("decrypted3072").textContent = decryptedData;
        
        // Check if original and decrypted match
        const matchElement = document.getElementById("match3072");
        if (jsonData === decryptedData) {
            matchElement.textContent = "✓ SUCCESS: Decryption is correct - Original data matches decrypted result!";
            matchElement.className = "match-status match";
        } else {
            matchElement.textContent = "✗ FAILED: Decryption error - Original data does not match decrypted result!";
            matchElement.className = "match-status no-match";
        }
        
        showMessage("RSA 3072-bit encryption and decryption completed successfully!", "success");
        
    } catch (error) {
        showMessage("Error: " + error.message, "error");
        console.error("RSA 3072-bit Error:", error);
    }
}

/**
 * Clear all form fields, results, and messages
 */
function handleClear() {
    // Reset the form
    document.getElementById("signupForm").reset();
    
    // Clear all error messages
    const errorElements = document.querySelectorAll(".error-msg");
    errorElements.forEach(function(element) {
        element.textContent = "";
    });
    
    // Clear all results
    clearResults();
    
    showMessage("All form fields and results have been cleared.", "info");
}

/**
 * Initialize event listeners when DOM is fully loaded
 */
function initEventListeners() {
    // Attach click event listeners to buttons
    const btnEncrypt1024 = document.getElementById("btnEncrypt1024");
    const btnEncrypt3072 = document.getElementById("btnEncrypt3072");
    const btnClear = document.getElementById("btnClear");
    
    if (btnEncrypt1024) {
        btnEncrypt1024.addEventListener("click", handleEncrypt1024);
    }
    
    if (btnEncrypt3072) {
        btnEncrypt3072.addEventListener("click", handleEncrypt3072);
    }
    
    if (btnClear) {
        btnClear.addEventListener("click", handleClear);
    }
}

// Initialize the application when DOM is ready
if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initEventListeners);
} else {
    // DOM is already ready
    initEventListeners();
}
