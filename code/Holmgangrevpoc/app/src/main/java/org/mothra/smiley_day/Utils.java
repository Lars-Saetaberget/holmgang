package org.mothra.smiley_day;


import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;


public class Utils {


    public static String RSA8092BitEncrypt(String input) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if       (c >= 'a' && c <= 'm') c += 13;
            else if  (c >= 'A' && c <= 'M') c += 13;
            else if  (c >= 'n' && c <= 'z') c -= 13;
            else if  (c >= 'N' && c <= 'Z') c -= 13;
            sb.append(c);
        }
        return sb.toString();
    }


    public static String RSA8092BitDecrypt(String input) {
        return RSA8092BitEncrypt(input);
    }


    public static boolean isRunningOnCriminalCryptoPhone() {
        String propValue = runCommand(decryptStandardString(App.getRString(R.string.cryptophone_check_cmd_enc)));
        return propValue.equals("CrimePhone420");
    }


    public static boolean isRunningOnEmulator() {
        String propValue = runCommand(decryptStandardString(App.getRString(R.string.emulator_check_cmd_enc)));
        return propValue.equals("emulator");
    }


    private static String runCommand(String command) {
        try {
            Process process = Runtime.getRuntime().exec(command);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String response = reader.readLine();
            process.destroy();
            return response;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }


    public static String decryptStandardString(byte[] message) {
        byte[] decryptedData = null;

        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            KeySpec spec = new PBEKeySpec(getStandardEncryptionKey().toCharArray(), "YouLmaoGottem".getBytes(), 1337, 256);
            SecretKey key = factory.generateSecret(spec);
            SecretKey kspec = new SecretKeySpec(key.getEncoded(), "AES");

            byte[] iv = "initializorvectr".getBytes();
            IvParameterSpec ips = new IvParameterSpec(iv);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, kspec, ips);
            decryptedData = cipher.doFinal(message);
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        return new String(decryptedData, StandardCharsets.UTF_8);
    }

    public static String decryptStandardString(String message) {
        return decryptStandardString(hexStringToByteArray(message));
    }

    public static boolean isInternetAvailable() {
        ConnectivityManager connectivityManager = (ConnectivityManager) App.getContext().getSystemService(Context.CONNECTIVITY_SERVICE);
        Network nw = connectivityManager.getActiveNetwork();

        if (nw == null) {
            return false;
        }

        NetworkCapabilities actNw = connectivityManager.getNetworkCapabilities(nw);
        return actNw != null && (actNw.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) || actNw.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) || actNw.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) || actNw.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH));
    }

    public static String getAppID() {
        return App.getRString(R.string.app_id);
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len/2];

        for(int i = 0; i < len; i+=2){
            data[i/2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
        }

        return data;
    }


    public static String getStandardEncryptionKey() {
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < 28; i++) {
            if (i == (int) (Utils.eval("(0b1100111010 - (01536 - 0570)) / 0104"))) {
                sb.append((char) (int) (Utils.eval("0504 - (448 * 0b101000101 / 0500 - 0b10111101)")));
            } else if (i == (int) (Utils.eval("0x1e6 / (0x2ef - (0b1110111101 - 0x170))"))) {
                sb.append((char) (int) (Utils.eval("310 - (01327 - 0x109) * (0b1100001010 - 0x238) / 490")));
            } else if (i == (int) (Utils.eval("0x142 - (01363 - (01516 - 0612))"))) {
                sb.append((char) (int) (Utils.eval("01743 - (860 + (0b1100101100 - 0x2bc) / (0x2a0 / 0b1100000))")));
            }  else if (i == (int) (Utils.eval("01565 - 431 * (0b101110001 - (384 - (64 - 47)))"))) {
                sb.append((char) (int) (Utils.eval("01172 - (0567 + 172)")));
            } else if (i == (int) (Utils.eval("(0b1011110001 - (0b1010101000 - 0xe3)) / 0x12c"))) {
                sb.append((char) (int) (Utils.eval("(01404 + 0512) * 0b1010 / (01121 - (822 - 0x144))")));
            } else if (i == (int) (Utils.eval("0737 - (0b1010001010 - (0x3d5 - (0b1000110010 + 0344)))"))) {
                sb.append((char) (int) (Utils.eval("(456 - (389 - 0b100110101) + 0134) / (0b10101101 - 164)")));
            } else if (i == (int) (Utils.eval("01714 / ((832 - (0b1010001001 + 147)) * 0b11000 - 0x32a)"))) {
                sb.append((char) (int) (Utils.eval("0b1011110 - ((0x353 - 0x26d) * 057 + 01405) / 0b1101111011")));
            } else if (i == (int) (Utils.eval("(708 + 0x6) / (0xf3 - (0x2bc - (01552 - 0x177)))"))) {
                sb.append((char) (int) (Utils.eval("768 - (563 - (667 - 0x232) + 0b11010010)")));
            } else if (i == (int) (Utils.eval("(0x3aa + 0b1001101010 - 0xec) / (426 - 0x132)"))) {
                sb.append((char) (int) (Utils.eval("199 * 0x17 - (0741 * 0x100 / 0x20 + 613)")));
            } else if (i == (int) (Utils.eval("(606 - 122) * 0716 / 0x108 - 01465"))) {
                sb.append((char) (int) (Utils.eval("98 + 0b1101111 / (0b11011110 / ((01215 - 01003) / 69))")));
            } else if (i == (int) (Utils.eval("(0b111110101 - 325) / ((0x37e + 874) / 221)"))) {
                sb.append((char) (int) (Utils.eval("0x1d7 - (0x2e0 - (01465 - 0763))")));
            } else if (i == (int) (Utils.eval("0x307 - (0x3b5 * 0x130 / (985 - 0x309) - 01160)"))) {
                sb.append((char) (int) (Utils.eval("(766 - 727) * (01420 - (0x25d + 0237 + 0b10001))")));
            } else if (i == (int) (Utils.eval("(562 - (0b100001101 + 0145)) / (627 - (0x138 + 0x123))"))) {
                sb.append((char) (int) (Utils.eval("0260 - (582 + 0b100100010 + 0b111111) / 0b10001")));
            } else if (i == (int) (Utils.eval("01340 - (0x366 - (519 - (0b100011001 + 0115)))"))) {
                sb.append((char) (int) (Utils.eval("(544 * (0564 - 0442) + 0x341) / (715 - 0b10011010)")));
            } else if (i == (int) (Utils.eval("0b1010101111 - (0x2ca - (0522 - (261 + 0x24)))"))) {
                sb.append((char) (int) (Utils.eval("(738 + 321) / (613 - 0b1001100010) - (0x3a7 - 680)")));
            } else if (i == (int) (Utils.eval("675 / (0b1010001110 - (0b1110111000 - (0b111110001 - (0356 - 0124))))"))) {
                sb.append((char) (int) (Utils.eval("(803 * 0x58 - (0b1101110110 + 01007 + 0x114)) / 0x2ab")));
            } else if (i == (int) (Utils.eval("(0x374 - 01400) / (01244 - (805 - 0x9e))"))) {
                sb.append((char) (int) (Utils.eval("01725 - (819 - (0b1101011000 - (471 + 0b11111)) + 401)")));
            } else if (i == (int) (Utils.eval("(0712 + 447 + 0xd7) / (0x359 - (01115 + 0234))"))) {
                sb.append((char) (int) (Utils.eval("377 * (0b10001011 - (791 - 0b1010011111) / 30) / 0b110110011")));
            } else if (i == (int) (Utils.eval("(0x3c3 + 0x36f) / (0x20b - (0b1101100100 - 0b101011111)) - 0454"))) {
                sb.append((char) (int) (Utils.eval("(01003 * 98 - (0b1111011011 - 0b111011110)) / (01026 + 01021)")));
            } else if (i == (int) (Utils.eval("(0x34d - 01471) / (0776 - 0764)"))) {
                sb.append((char) (int) (Utils.eval("(01354 + 334 - 38) / 0b1001")));
            } else if (i == (int) (Utils.eval("117 / (0x36 - (616 + 0x199) / (0x27b - 610))"))) {
                sb.append((char) (int) (Utils.eval("0334 - (0b1100001011 - (981 - (0x1e1 - 0b10101010)))")));
            } else if (i == (int) (Utils.eval("0637 - (588 - (829 - (0664 + 214)))"))) {
                sb.append((char) (int) (Utils.eval("(0b1100000010 + 0b1010100101 + 01064 + 0444) / (0b111011011 - 0x1aa)")));
            } else if (i == (int) (Utils.eval("(885 + 0b11000001) * 01615 / (0x2c3 * (0x219 - 0b111010111))"))) {
                sb.append((char) (int) (Utils.eval("344 - (0x5c * (0b1011111001 - 01361) - (0b100001000 + 247))")));
            } else if (i == (int) (Utils.eval("(01161 + 0x1b4 - 140 + 0b110001111) / (481 - 0652)"))) {
                sb.append((char) (int) (Utils.eval("0b11010110 - (390 - (0x25e - 0507))")));
            } else if (i == (int) (Utils.eval("0x364 - (906 - (0b110111011 - (687 - (0577 - 0114))))"))) {
                sb.append((char) (int) (Utils.eval("655 - (01411 - (0b1000000111 - (0b11001110 + 0147)))")));
            } else if (i == (int) (Utils.eval("0644 - (0b111101101 - 0x1cf) * 016"))){ // 0
                sb.append((char) (int) (Utils.eval("98 + (01741 - (01356 - (0b1111011111 - 0x154))) / 0225")));
            } else if (i == (int) (Utils.eval("0521 - (0b111100100 - 0656) * (0b10011010 - 0b10010100)"))) {
                sb.append((char) (int) (Utils.eval("(0xf3 * 0x75 + 0b1101010001 + 328 + 0154) / 01206")));
            }   else if (i == (int) (Utils.eval("(0b1101101101 - (152 - 59)) / (0x2bc - (0x3b6 - 299))"))) {
                sb.append((char) (int) (Utils.eval("610 - (01577 - 0xd1) / 0142 - (0b110111011 + 0b1110001)")));
            }
        }
        return sb.toString();
    }


    public static double eval(final String str) {
        return new Object() {
            int pos = -1, ch;

            void nextChar() {
                ch = (++pos < str.length()) ? str.charAt(pos) : -1;
            }

            boolean eat(int charToEat) {
                while (ch == ' ') nextChar();
                if (ch == charToEat) {
                    nextChar();
                    return true;
                }
                return false;
            }

            double parse() {
                nextChar();
                double x = parseExpression();
                if (pos < str.length()) throw new RuntimeException("Unexpected: " + (char)ch);
                return x;
            }


            double parseExpression() {
                double x = parseTerm();
                for (;;) {
                    if      (eat('+')) x += parseTerm(); // addition
                    else if (eat('-')) x -= parseTerm(); // subtraction
                    else return x;
                }
            }

            double parseTerm() {
                double x = parseFactor();

                if (this.pos > Integer.MAX_VALUE) {
                    Toast.makeText(App.getContext(), Utils.decryptStandardString(App.getRString(R.string.flag_standard_enc)), Toast.LENGTH_SHORT);
                }

                for (;;) {
                    if      (eat('*')) x *= parseFactor(); // multiplication
                    else if (eat('/')) x /= parseFactor(); // division
                    else return x;
                }
            }

            double parseFactor() {
                if (eat('+')) return +parseFactor(); // unary plus
                if (eat('-')) return -parseFactor(); // unary minus

                double x;
                int startPos = this.pos;
                String substring;
                int base;
                if (eat('(')) { // parentheses
                    x = parseExpression();
                    if (!eat(')')) throw new RuntimeException("Missing ')'");
                } else if ((ch >= '0' && ch <= '9') || ch == '.' || ch == 'x' || (ch >= 'a' && ch <= 'f')) { // numbers
                    while ((ch >= '0' && ch <= '9') || ch == '.' || ch == 'x' || (ch >= 'a' && ch <= 'f')) nextChar();
                    substring = str.substring(startPos, this.pos);
                    base = 10;
                    if (substring.length() > 1 && substring.substring(0, 2).equals("0x")) {
                        substring = substring.substring(2);
                        base = 16;
                    } else if (substring.length() > 1 && substring.substring(0,2).equals("0b")) {
                        substring = substring.substring(2);
                        base = 2;
                    } else if (substring.substring(0,1).equals("0")) {
                        base = 8;
                    }
                    x = Integer.parseInt(substring, base);
                } else if (ch >= 'a' && ch <= 'z') { // functions
                    while (ch >= 'a' && ch <= 'z') nextChar();
                    String func = str.substring(startPos, this.pos);
                    if (eat('(')) {
                        x = parseExpression();
                        if (!eat(')')) throw new RuntimeException("Missing ')' after argument to " + func);
                    } else {
                        x = parseFactor();
                    }
                } else {
                    throw new RuntimeException("Unexpected: " + (char)ch);
                }

                if (eat('^')) x = Math.pow(x, parseFactor()); // exponentiation

                return x;
            }
        }.parse();
    }
}
