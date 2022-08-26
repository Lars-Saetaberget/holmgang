// Settings
const cfbSegmentSize = 16;
const charset = "_abcdefghijklmnopqrstuvwxyz".split("");
const dummyChar = "-";

// Indices
const myPass = 0;
const correctPass = 1;

Java.perform(function() {
    let PasswordUtils = Java.use('org.mothra.smiley_day.PasswordUtils');
    let JavaString = Java.use('java.lang.String');


    function performRequest(password) {
        let javaString = JavaString.$new(password);
        return PasswordUtils.getEncryptedPasswordsFromCloud.call(PasswordUtils, javaString);
    }

    function toHex(string) {
        let hexString = "";
        for (let i = 0; i < string.length; i++) {
            hexString += string.charCodeAt(i).toString(16);
        }
        return hexString;
    }

    function fromHex(hexString) {
        let string = "";
        for (let i = 0; i < hexString.length / 2; i++) {
            String.fromCharCode(123);
            string += String.fromCharCode(parseInt(hexString.substring(i * 2, 2 + (i * 2)), 16));
        }
        return string;
    }

    function xor(hexString1, hexString2) {
        let result = "";

        for (let i = 0; i < hexString1.length / 2; i++) {
            let byte1 = parseInt(hexString1.substring(i * 2, 2 + (i * 2)), 16);
            let byte2 = parseInt(hexString2.substring(i * 2, 2 + (i * 2)), 16);

            let hexResult = (byte1 ^ byte2).toString(16);

            while (hexResult.length < 2) {
                hexResult = "0" + hexResult;
            }

            result += hexResult;
        }

        return result
    }

    function solveSegment(hashes, segment) {
        let start = 2 * segment * cfbSegmentSize;
        let end = Math.min(start + (cfbSegmentSize * 2), hashes[correctPass].length);

        let c1_xor_c2 = xor(hashes[correctPass].substring(start, end), hashes[myPass].substring(start, end));
        let hexResult = xor(c1_xor_c2, toHex(dummyChar.repeat(cfbSegmentSize)));

        return fromHex(hexResult);
    }

    function solveAll() {
        let dummyLength;
        let revealedSegments = "";
        let currentSegment = 0;
        let hashes;
        let currentGuess;

        do {
            dummyLength = cfbSegmentSize + (currentSegment * cfbSegmentSize) - revealedSegments.length;
            currentGuess = revealedSegments + dummyChar.repeat(dummyLength);

            hashes = performRequest(currentGuess);
            revealedSegments += solveSegment(hashes, currentSegment);

            console.log("Found so far: " + revealedSegments)
        } while (++currentSegment < Math.ceil(hashes[correctPass].length / 2 / cfbSegmentSize));

        return revealedSegments;
    }

    let password = solveAll();

    for (let i = 0; i < password.length; i++) {
        if (!charset.includes(password.charAt(i))) {
            console.log("\nGot the wrong password! Likely wrong segment size.")
            return;
        }
    }
    console.log("\nComplete key: " + password);
});
