package org.mothra.smiley_day;

import android.widget.Toast;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class PasswordUtils {

    private static final Object lock = new Object();

    public static boolean validatePassword(String password) {
        return validatePasswordNew(password);
    }

    public static boolean validatePasswordNew(String password) {
        String[] encryptedPasswords = getEncryptedPasswords(password);
        return encryptedPasswords[0].equals(encryptedPasswords[1]);
    }


    private static byte[] encrypt(byte[] key, byte[] data, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        Key keySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance(getAlgorithm());
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(data);
    }


    private static String getAlgorithm() {
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < 17; i++) {
            if (i == (int) (Utils.eval("767 - (01350 + 0x24a) * 0b101111000 / 0b1010010010"))) {
                sb.append((char) (int) (Utils.eval("(0x234 / (0b101000000 / (0b100010000 - (524 - 0x100)) - 68))")));
            }
            else if (i == (int) (Utils.eval("(01035 + 0x15f + 0b10111100) / 0x21c - (0b10010011 - 0x91)"))) {
                sb.append((char) (int) (Utils.eval("(01236 - (0x2e7 - (0x12c - 0b10100010)))")));
            }
            else if (i == (int) (Utils.eval("0x1e6 * (0x1a8 - 146) / (01070 - 0655) - 01676"))) {
                sb.append((char) (int) (Utils.eval("(739 - (0x34c - (0x1b6 - (0x14f - (249 - 0x8e)))))")));
            }
            else if (i == (int) (Utils.eval("(0x308 + 0600) / (898 - (01165 + 0b100101))"))) {
                sb.append((char) (int) (Utils.eval("(0x25c - (01143 - (0530 - (423 - (0x22c - 0b110010000)))))")));
            }
            else if (i == (int) (Utils.eval("(0b1010011111 + 0x158 + 0x80) / (0x23e - 0xc1)"))) {
                sb.append((char) (int) (Utils.eval("(0b10111100 / (0b1000001000 - (0654 + 0b1011000)))")));
            }
            else if (i == (int) (Utils.eval("((0x12e + 31) * 0b1111 - (387 - 0x75)) / 0x13b"))) {
                sb.append((char) (int) (Utils.eval("(01405 - (0x3b4 - (484 - (0x146 - 127))))")));
            }
            else if (i == (int) (Utils.eval("(0x219 - (0b110000010 - (0x154 - 331))) / 0x10"))) {
                sb.append((char) (int) (Utils.eval("(0b1110110101 - (0x321 + (0b1110100011 + 0x2ab + 0b100100010) / 034))")));
            }
            else if (i == (int) (Utils.eval("0b1011000111 - (681 + 0b11101)"))) {
                sb.append((char) (int) (Utils.eval("((0x208 - (0x5f - 13)) * (0b1111100000 - 01450) / (0x30f + 0b110000001))")));
            }
            else if (i == (int) (Utils.eval("(823 - (692 - 0x6d)) / (0b101011 - 3)"))) {
                sb.append((char) (int) (Utils.eval("((0x10f - 0b11011011) * 0b101111 - (01621 + 784) - (0x1f5 + 0264))")));
            }
            else if (i == (int) (Utils.eval("0b1011111101 / (0x25e - (827 - (0b1111010011 - 0x2a1)))"))) {
                sb.append((char) (int) (Utils.eval("(302 - (01277 - (0272 + 0254) - (0144 + 066)))")));
            }
            else if (i == (int) (Utils.eval("034 - (0x2ce + 0707) / (676 - (01415 - 0xae))"))) {
                sb.append((char) (int) (Utils.eval("(0b101011110 - (539 - (0433 + 0644 / (119 + 21))))")));
            }
            else if (i == (int) (Utils.eval("(997 - (0b1101101100 - 01551) + 94) / (0b11101001 - 0b1100001)"))) {
                sb.append((char) (int) (Utils.eval("(0xb4 - 0b111001011 * 200 / (01203 + 0x101))")));
            }
            else if (i == (int) (Utils.eval("(0xd9 - (0x223 - (01643 - (222 + 0301)))) / 93"))) {
                sb.append((char) (int) (Utils.eval("(0641 - (620 - (0562 - (78 + 06))))")));
            }
            else if (i == (int) (Utils.eval("(0b1100100111 - (01557 - 0x198)) / (869 - 0x349)"))) {
                sb.append((char) (int) (Utils.eval("(01401 - (0x2b8 - (0237 - 132)))")));
            }
            else if (i == (int) (Utils.eval("(01464 - (0x361 - 0x5d)) / (964 - (0x3e0 - 0b11111))"))) {
                sb.append((char) (int) (Utils.eval("((01075 * (0b1010111111 - 0b1000001111) - (01551 - 01367)) / (0x368 + 0x6a))")));
            }
            else if (i == (int) (Utils.eval("230 - ((0b1100101100 - 0xab) * 0b101011 + 0b111001101) / 0b1111100"))) {
                sb.append((char) (int) (Utils.eval("(0b111010 + 01474 / (776 - (0x247 + 101)))")));
            }
            else if (i == (int) (Utils.eval("(0b1011011110 - (0b111000010 + 0x32)) / (0b110101010 - (0x2cf - 311))"))) {
                sb.append((char) (int) (Utils.eval("(0b1000011101 - (0b1011000011 - (884 - (0b1010001110 - 36))))")));
            }
        }
        return sb.toString();
    }


    private static boolean validatePasswordOld(byte[] password) throws Exception {
        byte[] correctPassword = getCorrectPassword();

        SecureRandom random = new SecureRandom();
        byte[] randomPassword = new byte[32];
        byte[] iv = new byte[16];
        random.nextBytes(randomPassword);
        random.nextBytes(iv);

        try {
            byte[] correctHash = encrypt(randomPassword, correctPassword, iv);
            byte[] submittedHash = encrypt(randomPassword, password, iv);

            return Arrays.equals(submittedHash, correctHash);
        } catch(Exception e) {
            e.printStackTrace();
        }

        return false;
    }


    public static String[] getEncryptedPasswords(String password) {
        final String[] hashes = new String[2];

        Thread thread = new Thread(() -> {
            synchronized (lock) {
                String[] result = getEncryptedPasswordsFromCloud(password);
                hashes[0] = result[0];
                hashes[1] = result[1];
                lock.notify();
            }
        });
        thread.start();

        try {
            synchronized (lock) {
                lock.wait(1000);
            }
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        if (hashes[0].equals("401")) {
            Toast.makeText(App.getContext(), Utils.decryptStandardString(App.getRString(R.string.unauthorized_response_enc)), Toast.LENGTH_LONG).show();
        }

        return hashes;
    }


    private static String[] getEncryptedPasswordsFromCloud(String password) {
        String[] hashes = new String[2];

        HttpURLConnection urlConnection = null;

        try {
            URL url = new URL(App.getRString(R.string.api_url) + App.getRString(R.string.api_endpoint_encrypted));
            urlConnection = (HttpURLConnection) url.openConnection();

            urlConnection.setRequestMethod("POST");
            urlConnection.setRequestProperty("Content-Type", "application/json");
            urlConnection.setRequestProperty("Accept", "application/json");
            urlConnection.setDoOutput(true);
            urlConnection.setDoInput(true);

            JSONObject body = new JSONObject();
            body.put("username", Utils.getAppID());
            body.put("password", password);
            body.put("key", NothingToSeeHereActivity.clicks.toString());

            DataOutputStream os = new DataOutputStream(urlConnection.getOutputStream());
            os.writeBytes(body.toString());

            int status = urlConnection.getResponseCode();
            if (status == 401) {
                return new String[]{"401", null};
            }

            BufferedReader br = new BufferedReader(
                    new InputStreamReader(urlConnection.getInputStream(), "utf-8"));
            StringBuilder response = new StringBuilder();
            String responseLine = null;
            while ((responseLine = br.readLine()) != null) {
                response.append(responseLine.trim());
            }

            JSONObject responseJSON = new JSONObject(response.toString());

            hashes[0] = responseJSON.getString("supplied_password");
            hashes[1] = responseJSON.getString("correct_password");
        } catch (IOException | JSONException e) {
            e.printStackTrace();
        } finally {
            if (urlConnection != null) {
                urlConnection.disconnect();
            }
        }

        return hashes;
    }


    private static byte[] getCorrectPassword() throws Exception {
        throw new Extras.DeprecatedException(Utils.decryptStandardString(App.getRString(R.string.get_stored_deprecated_enc)));
    }
}
