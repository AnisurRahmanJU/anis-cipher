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
            tokens.push(char);
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
    // Separate tokens cleanly with a space to parse correctly during recovery
    return tokens.join(" ");
}

/**
 * Decryption Loop (Algorithm 2)
 * Input: Ciphertext Token String, Integer Key
 */
function decrypt(ciphertext, key) {
    if (!ciphertext || isNaN(key) || key <= 0) return "Please enter valid text and a positive key.";
    
    let tokens = ciphertext.trim().split(" ");
    let recoveredText = "";

    for (let token of tokens) {
        if (!token) continue;

        // Skip spaces or plain punctuation marks
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

    return recoveredText;
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

// ==========================================================================
// ENIGMA INTERACTIVE KEYBOARD SCRIPT - STABLE INTERACTION LAYER (FIXED DUPLICATE)
// ==========================================================================

document.addEventListener("DOMContentLoaded", () => {
    const messageInput = document.getElementById("messageInput");
    const virtualKeys = document.querySelectorAll(".key");

    // ১. ডিরেক্ট ক্লিক হ্যান্ডলার (এটি ডাবল ক্যারেক্টার ইনপুট হওয়া সম্পূর্ণ বন্ধ করবে)
    virtualKeys.forEach(key => {
        key.onclick = (e) => {
            // ব্রাউজারের অন্যান্য ফালতু বা ডাবল ইভেন্ট ট্রিগার হওয়া থামিয়ে দেবে
            if (e) {
                e.preventDefault();
                e.stopPropagation();
            }

            const keyValue = key.getAttribute("data-key");
            
            if (keyValue === "CLEAR") {
                // কনসোল পুরো পরিষ্কার করবে
                messageInput.value = "";
            } else if (keyValue === "BACKSPACE") {
                // শেষের একটি ক্যারেক্টার মুছে ফেলবে
                messageInput.value = messageInput.value.slice(0, -1);
            } else {
                // শুধুমাত্র একটি ক্যারেক্টার বা স্পেস ইনপুট করবে
                messageInput.value += keyValue;
            }
            
            // ইনপুট বক্সে ফোকাস ধরে রাখবে
            messageInput.focus();
            
            // আপনার এনিক্রিপশন অ্যালগরিদমকে লাইভ আপডেট পাঠাবে
            messageInput.dispatchEvent(new Event('input'));
        };
    });

    // ২. ফিজিক্যাল কীবোর্ড অ্যানিমেশন সিঙ্ক (ঐচ্ছিক)
    document.addEventListener("keydown", (e) => {
        let pressedKey = e.key.toUpperCase();
        if (e.key === "Backspace") pressedKey = "BACKSPACE";
        if (e.key === "Escape") pressedKey = "CLEAR";
        
        const targetVisualKey = document.querySelector(`.key[data-key="${pressedKey}"]`);
        if (targetVisualKey) {
            targetVisualKey.classList.add("pressed");
        }
    });

    document.addEventListener("keyup", (e) => {
        let releasedKey = e.key.toUpperCase();
        if (e.key === "Backspace") releasedKey = "BACKSPACE";
        if (e.key === "Escape") releasedKey = "CLEAR";
        
        const targetVisualKey = document.querySelector(`.key[data-key="${releasedKey}"]`);
        if (targetVisualKey) {
            targetVisualKey.classList.remove("pressed");
        }
    });
});
