// Helper to convert character code to index (A=0, B=1... Z=25)
function mapToNum(char) {
    return char.charCodeAt(0) - 65;
}

// Helper to convert index (0-25) back to Character
function mapToChar(num) {
    return String.fromCharCode(num + 65);
}

// Global Delimiter Token outlined in Section IV-C
const DELIMITER = "^"; 

/**
 * Encryption Loop (Algorithm 1)
 */
function encrypt(plaintext, key) {
    if (!plaintext || isNaN(key) || key <= 0) return "Please enter valid text and a positive key.";
    
    // Normalize input data for standard base-26 matching text
    let upperText = plaintext.toUpperCase();
    let tokens = [];

    for (let i = 0; i < upperText.length; i++) {
        let char = upperText[i];
        
        // Preserve spaces and special characters seamlessly
        if (char < 'A' || char > 'Z') {
            tokens.push(char);
            continue;
        }

        let P = mapToNum(char);         // Plaintext matching ID (0-25)
        let Pk = P * key;               // State expansion
        
        // Consecutive Square Difference property validation
        let Diff = Math.pow(Pk, 2) - Math.pow(Pk - 1, 2); 

        if (Diff < 26) {
            let cipherTextValue = Diff;
            tokens.push(mapToChar(cipherTextValue));
        } else {
            let remainder = Diff % 26;
            let quotient = Math.floor(Diff / 26);
            let valChar = mapToChar(remainder);
            
            // Digit expansion rules to safeguard overflow boundaries
            let quotientStr = quotient.toString();
            let powerString = "";
            for (let digit of quotientStr) {
                let digitNum = parseInt(digit);
                powerString += mapToChar(digitNum);
            }
            
            tokens.push(valChar + DELIMITER + powerString);
        }
    }
    // Joining tokens with a clean space delimiter if token strings are long strings
    return tokens.join(" ");
}

/**
 * Decryption Loop (Algorithm 2)
 */
function decrypt(ciphertext, key) {
    if (!ciphertext || isNaN(key) || key <= 0) return "Please enter valid text and a positive key.";
    
    // Split combined space-separated tokens
    let tokens = ciphertext.trim().split(" ");
    let recoveredText = "";

    for (let token of tokens) {
        if (!token) continue;

        // Pass spaces or unique strings that do not follow base-26 structural maps
        if (token.length === 1 && (token < 'A' || token > 'Z')) {
            recoveredText += token;
            continue;
        }

        let Diff = 0;

        if (token.includes(DELIMITER)) {
            // Split token into ValChar component and the Digitized PowerString exponent
            let parts = token.split(DELIMITER);
            let valChar = parts[0];
            let powerString = parts[1];

            let remainder = mapToNum(valChar);
            let quotientStr = "";
            
            for (let char of powerString) {
                let digitNum = mapToNum(char);
                quotientStr += digitNum.toString();
            }
            
            let quotient = parseInt(quotientStr);
            Diff = (26 * quotient) + remainder;
        } else {
            Diff = mapToNum(token);
        }

        // Reversing structural arithmetic maps
        let Pk = (Diff + 1) / 2;
        let P = Pk / key;

        recoveredText += mapToChar(Math.round(P));
    }

    return recoveredText;
}

// DOM Setup Connections
document.addEventListener("DOMContentLoaded", () => {
    const messageInput = document.getElementById("messageInput");
    const keyInput = document.getElementById("keyInput");
    const encryptBtn = document.getElementById("encryptBtn");
    const decryptBtn = document.getElementById("decryptBtn");
    const outputMessage = document.getElementById("outputMessage");

    encryptBtn.addEventListener("click", () => {
        let text = messageInput.value;
        let key = parseInt(keyInput.value);
        let result = encrypt(text, key);
        outputMessage.textContent = result;
        outputMessage.classList.remove("placeholder-text");
    });

    decryptBtn.addEventListener("click", () => {
        let text = messageInput.value;
        let key = parseInt(keyInput.value);
        let result = decrypt(text, key);
        outputMessage.textContent = result;
        outputMessage.classList.remove("placeholder-text");
    });
});