/**
 * Full implementation of Consecutive Square Differences Cryptography
 * Source Data: Md. Anisur Rahman (UIU)
 */

// Helper to convert character code to index (A=0, B=1... Z=25)
function mapToNum(char) {
    return char.charCodeAt(0) - 65;
}

// Helper to convert index (0-25) back to Character safely
function mapToChar(num) {
    if (num < 0) num = 0; 
    return String.fromCharCode((num % 26) + 65);
}

// The carat token used directly as the exponent separator string
const DELIMITER = "^"; 

/**
 * Encryption Loop (Algorithm 1)
 * Input: Plaintext String, Integer Key
 */
function encrypt(plaintext, key) {
    if (!plaintext || isNaN(key) || key <= 0) return "Please enter valid text and a positive key.";
    
    let upperText = plaintext.toUpperCase();
    let tokens = [];

    for (let i = 0; i < upperText.length; i++) {
        let char = upperText[i];
        
        // Preserve spaces and special characters seamlessly
        if (char < 'A' || char > 'Z') {
            if (char === ' ') {
                // শব্দের মাঝের খালি স্পেসকে ডাবল স্পেস ট্র্যাকিংয়ের জন্য একটি অতিরিক্ত স্পেস হিসেবে রাখা হলো
                // join(" ") করার পর এটি নিখুঁত ব্ল্যাংক স্পেস হিসেবেই আউটপুট দেবে
                tokens.push(""); 
            } else {
                tokens.push(char);
            }
            continue;
        }

        let P = mapToNum(char);         // Plaintext character code P (A=0, Z=25)
        let Pk = P * key;               // State expansion parameter P_k = P x K
        
        // Consecutive Square Difference: Diff = (P_k)^2 - (P_k - 1)^2
        let Diff = Math.pow(Pk, 2) - Math.pow(Pk - 1, 2); 

        // If difference fits within standard alphabet block space
        if (Diff < 26) {
            tokens.push(mapToChar(Diff)); 
        } else {
            // Dynamic handling of overflows via quotient-remainder
            let remainder = Diff % 26; 
            let quotient = Math.floor(Diff / 26); 
            let valChar = mapToChar(remainder); 
            
            // Decompose quotient into individual numerical digits
            let quotientStr = quotient.toString();
            let powerString = "";
            
            for (let digit of quotientStr) {
                let digitNum = parseInt(digit); 
                powerString += mapToChar(digitNum); // 0 cleanly becomes A, 1 becomes B, etc.
            }
            
            // Compile final token format (ValChar + ^ + PowerString)
            tokens.push(valChar + DELIMITER + powerString);
        }
    }
    
    return tokens.join(" ");
}

/**
 * Decryption Loop (Algorithm 2)
 * Input: Ciphertext Token String, Integer Key
 */
function decrypt(ciphertext, key) {
    if (!ciphertext || isNaN(key) || key <= 0) return "Please enter valid text and a positive key.";
    

    let tokens = ciphertext.split(" ");
    let recoveredText = "";
    let isPrevSpace = false;

    for (let i = 0; i < tokens.length; i++) {
        let token = tokens[i];

        
        if (token === "") {
            if (!isPrevSpace) {
                recoveredText += " ";
                isPrevSpace = true;
            }
            continue;
        }

        isPrevSpace = false;

        // Skip plain punctuation marks
        if (token.length === 1 && (token < 'A' || token > 'Z')) {
            recoveredText += token;
            continue;
        }

        let Diff = 0;

        // Check for the exponent indicator delimiter "^"
        if (token.includes(DELIMITER) && token.length > 1) {
            // Split token into components
            let parts = token.split(DELIMITER);
            let valChar = parts[0];
            let powerString = parts[1];

            let remainder = mapToNum(valChar); 
            let quotientStr = "";
            
            // Convert character digits back to numeric strings
            for (let char of powerString) {
                let digitNum = mapToNum(char); 
                quotientStr += digitNum.toString();
            }
            
            let quotient = parseInt(quotientStr); 
            Diff = (26 * quotient) + remainder; // Reconstruct original difference
        } else {
            Diff = mapToNum(token); // Direct mapping if no overflow token was created
        }

        // Reversing structural arithmetic maps to find internal state P_k
        let Pk = (Diff + 1) / 2;
        let P = Pk / key; // Extract original character index P

        recoveredText += mapToChar(Math.round(P));
    }

    return recoveredText.trim();
}

// Attach event tracking hooks when DOM fully compiles
document.addEventListener("DOMContentLoaded", () => {
    const messageInput = document.getElementById("messageInput");
    const keyInput = document.getElementById("keyInput");
    const encryptBtn = document.getElementById("encryptBtn");
    const decryptBtn = document.getElementById("decryptBtn");
    const outputMessage = document.getElementById("outputMessage");

    encryptBtn.addEventListener("click", () => {
        let text = messageInput.value;
        let key = parseInt(keyInput.value);
        outputMessage.textContent = encrypt(text, key);
        outputMessage.classList.remove("placeholder-text");
    });

    decryptBtn.addEventListener("click", () => {
        let text = messageInput.value;
        let key = parseInt(keyInput.value);
        outputMessage.textContent = decrypt(text, key);
        outputMessage.classList.remove("placeholder-text");
    });
});
const textInput = document.getElementById('messageInput');

textInput.addEventListener('keydown', (e) => {
    const keyChar = e.key.toUpperCase();
    const targetKey = document.querySelector(`.key[data-key="${keyChar}"]`);
    if(targetKey) targetKey.classList.add('pressed');
});

textInput.addEventListener('keyup', (e) => {
    const keyChar = e.key.toUpperCase();
    const targetKey = document.querySelector(`.key[data-key="${keyChar}"]`);
    if(targetKey) targetKey.classList.remove('pressed');
});

// ==========================================================================
// ENIGMA INTERACTIVE KEYBOARD SCRIPT
// ==========================================================================

document.addEventListener("DOMContentLoaded", () => {
    const messageInput = document.getElementById("messageInput");
    const virtualKeys = document.querySelectorAll(".key");

    // 1. Handle Virtual Keyboard Clicks
    virtualKeys.forEach(key => {
        key.addEventListener("click", () => {
            const letter = key.getAttribute("data-key");
            
            // Append the letter to the textarea
            messageInput.value += letter;
            
            // Force focus back to the textarea so the user sees the cursor
            messageInput.focus();
            
            // Optional: Trigger input event if your encryption algorithm listens to live typing
            messageInput.dispatchEvent(new Event('input'));
        });
    });

    // 2. Handle Physical Keyboard Typing (Adds visual keypress animation)
    document.addEventListener("keydown", (e) => {
        const pressedKey = e.key.toUpperCase();
        const targetVisualKey = document.querySelector(`.key[data-key="${pressedKey}"]`);
        
        if (targetVisualKey) {
            targetVisualKey.classList.add("pressed");
        }
    });

    document.addEventListener("keyup", (e) => {
        const releasedKey = e.key.toUpperCase();
        const targetVisualKey = document.querySelector(`.key[data-key="${releasedKey}"]`);
        
        if (targetVisualKey) {
            targetVisualKey.classList.remove("pressed");
        }
    });
});


document.addEventListener("DOMContentLoaded", function () {
    const messageInput = document.getElementById("messageInput");
    const outputMessage = document.getElementById("outputMessage");
    const keyboardPanel = document.querySelector(".enigma-keyboard-panel");

    if (keyboardPanel) {
        // Use 'true' for capturing phase to intercept the click before old code can run
        keyboardPanel.addEventListener("click", function (e) {
            const keyElement = e.target.closest(".key");
            if (!keyElement) return;

            // Stop any other script in this file from reacting to this specific click
            e.stopImmediatePropagation();
            e.preventDefault();

            // 1. Handle Clear Action
            if (keyElement.id === "clearBtn") {
                messageInput.value = "";
                outputMessage.textContent = "";
                outputMessage.classList.add("placeholder-text");
                messageInput.focus();
                return;
            }

            // 2. Handle Character Input Safely (Fixes the "AA" duplicate bug)
            const keyChar = keyElement.getAttribute("data-key");
            if (keyChar !== null && keyChar !== "null") {
                messageInput.value += keyChar;
                
                // Dispatches input event so your cipher logic processes the single letter
                messageInput.dispatchEvent(new Event('input', { bubbles: true }));
            }
        }, true); // The 'true' flag ensures this runs first and blocks duplicates
    }

    // Mechanical Active Compression States (Physical Sync)
    document.addEventListener("keydown", function (e) {
        let physicalKey = e.key.toUpperCase();
        if (physicalKey === " ") physicalKey = " ";

        const targetVirtualKey = document.querySelector(`.key[data-key="${physicalKey}"]`);
        if (targetVirtualKey) targetVirtualKey.classList.add("pressed");
    });

    document.addEventListener("keyup", function (e) {
        let physicalKey = e.key.toUpperCase();
        if (physicalKey === " ") physicalKey = " ";

        const targetVirtualKey = document.querySelector(`.key[data-key="${physicalKey}"]`);
        if (targetVirtualKey) targetVirtualKey.classList.remove("pressed");
    });
});


// ==========================================================================
// MOUSE DRAG & TOUCH SCREEN ROTOR WHEEL CONTROLLER
// ==========================================================================
document.addEventListener("DOMContentLoaded", () => {
    const wheel = document.querySelector(".mechanical-wheel");
    const keyInput = document.getElementById("keyInput");
    
    if (!wheel || !keyInput) return;

    let isInteracting = false;
    let startY = 0;
    let startValue = 1;
    
    // Sync initial physical rotation with current state code matrix on load
    let currentRotation = (parseInt(keyInput.value) * 15) % 360;
    wheel.style.transform = `rotate(${currentRotation}deg)`;

    // Common event function handler to calculate rotation matrix and key adjustments
    function handleMove(clientY) {
        if (!isInteracting) return;
        const deltaY = startY - clientY;
        const sensitivity = 8; // Pixels dragged per vertical unit change
        const stepChange = Math.floor(deltaY / sensitivity);
        
        let newValue = startValue + stepChange;
        if (newValue < 2) newValue = 2; // Structural boundary constraint

        if (parseInt(keyInput.value) !== newValue) {
            keyInput.value = newValue;
            currentRotation = (newValue * 15) % 360;
            wheel.style.transform = `rotate(${currentRotation}deg)`;
            keyInput.dispatchEvent(new Event('input', { bubbles: true }));
        }
    }

    // --- Desktop Mouse Tracking Interfaces ---
    wheel.addEventListener("mousedown", (e) => {
        isInteracting = true;
        startY = e.clientY;
        startValue = parseInt(keyInput.value) || 1;
        wheel.style.cursor = "grabbing";
    });

    document.addEventListener("mousemove", (e) => {
        if (isInteracting) handleMove(e.clientY);
    });

    document.addEventListener("mouseup", () => {
        if (isInteracting) {
            isInteracting = false;
            wheel.style.cursor = "ns-resize";
        }
    });

    // --- Mobile Touchscreen Tracking Interfaces ---
    wheel.addEventListener("touchstart", (e) => {
        isInteracting = true;
        startY = e.touches[0].clientY;
        startValue = parseInt(keyInput.value) || 1;
    }, { passive: true });

    document.addEventListener("touchmove", (e) => {
        if (isInteracting) {
            handleMove(e.touches[0].clientY);
            // Prevent bounce scroll motions on mobile screens while handling the dial
            if (e.cancelable) e.preventDefault(); 
        }
    }, { passive: false });

    document.addEventListener("touchend", () => {
        isInteracting = false;
    });

    // --- Desktop Native Scroll-Wheel Hooks ---
    wheel.addEventListener("wheel", (e) => {
        e.preventDefault();
        let currentValue = parseInt(keyInput.value) || 1;
        if (e.deltaY < 0) {
            currentValue++;
        } else {
            if (currentValue > 2) currentValue--;
        }
        keyInput.value = currentValue;
        currentRotation = (currentValue * 15) % 360;
        wheel.style.transform = `rotate(${currentRotation}deg)`;
        keyInput.dispatchEvent(new Event('input', { bubbles: true }));
    }, { passive: false });
    
});

document.addEventListener("DOMContentLoaded", () => {

    const copyBtn = document.getElementById("copyBtn");
    const outputMessage = document.getElementById("outputMessage");

    if (!copyBtn || !outputMessage) return;

    copyBtn.addEventListener("click", async () => {

        const textToCopy = outputMessage.textContent.trim();

        if (!textToCopy) 
        {
            return;
        }

        try {
            await navigator.clipboard.writeText(textToCopy);

            alert("Successfully copied");

        } catch (err) {

            // fallback copy
            const tempArea = document.createElement("textarea");
            tempArea.value = textToCopy;
            document.body.appendChild(tempArea);

            tempArea.select();
            document.execCommand("copy");

            document.body.removeChild(tempArea);

            alert("Successfully copied");
        }
    });
});
