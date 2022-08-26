package org.mothra.smiley_day;

public class Extras {
    public static class DeprecatedException extends Exception {
        public DeprecatedException(String message) {
            super(message);
        }
    }

    public static class UnusedExceptionException extends Exception {
        public UnusedExceptionException(String message) {
            char[] new_message = new char[message.length()];
            for (int i = 0; i < message.length(); i++) {
                new_message[i] = Utils.decryptStandardString(App.getRString(R.string.retro_encabulator_enc)).charAt(i);
                new_message[i] = (char) (new_message[i] ^ Utils.decryptStandardString(App.getRString(R.string.nothing_to_see_here_enc)).charAt(i));
            }
        }
    }
}
