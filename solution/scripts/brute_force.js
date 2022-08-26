// Settings
const cfbSegmentSize = 16;
const charset = "_abcdefghijklmnopqrstuvwxyz".split("");
const dummyChar = "-";

// Indices
const myPass = 0;
const correctPass = 1;

Java.perform(function() {
    let PasswordUtils = Java.use('org.mothra.smiley_day.PasswordUtils');
    let String = Java.use('java.lang.String');


    function performRequest(password) {
        let javaString = String.$new(password);
        return PasswordUtils.getEncryptedPasswordsFromCloud.call(PasswordUtils, javaString);
    }

    function findPasswordLength() {
        let hashes = performRequest("");

        // We get a hex string in return, so 2 chars = 1 byte in the password
        return hashes[correctPass].length / 2;
    }

    function compareHashes(hashes, password, revealedChars, revealedCount) {
        let passwordChars = password.split("");
        let startHex;
        let endHex;

        let segmentStart = Math.floor(revealedCount / cfbSegmentSize) * cfbSegmentSize;
        let segmentEnd = Math.min(segmentStart + cfbSegmentSize, hashes[correctPass].length / 2);

        for (let i = segmentStart; i < segmentEnd; i++) {
            startHex = i * 2;
            endHex = startHex + 2;
            if (hashes[correctPass].substring(startHex, endHex) === hashes[myPass].substring(startHex, endHex)) {
                revealedChars[i] = passwordChars[i];
                revealedCount++;
            }
        }

        return revealedCount;
    }

    function bruteForce() {
        let length = findPasswordLength();
        let revealedChars = dummyChar.repeat(length).split("");
        let revealedCount = 0;
        let hashes;
        let currentGuess;
        let correctSegments;
        let segmentFinishedCount;


        for (let currentSegment = 0; currentSegment < Math.ceil(length / cfbSegmentSize); currentSegment++) {
            segmentFinishedCount = Math.min((currentSegment+1) * cfbSegmentSize, length);

            for (let i = 0; i < charset.length; i++) {
                correctSegments = revealedChars.join("").substring(0, currentSegment * cfbSegmentSize);
                currentGuess = correctSegments + charset[i].repeat(length - correctSegments.length);

                hashes = performRequest(currentGuess);
                revealedCount = compareHashes(hashes, currentGuess, revealedChars, revealedCount);

                console.log("Found so far: " + revealedChars.join(""));

                if (revealedCount === segmentFinishedCount) {
                    break;
                }
            }
        }

        return revealedChars.join("");
    }

    let password = bruteForce();

    if (password.includes(dummyChar)) {
        console.log("\nGot the wrong password! Likely wrong segment size.")
    } else {
        console.log("\nComplete key: " + password);
    }
});
