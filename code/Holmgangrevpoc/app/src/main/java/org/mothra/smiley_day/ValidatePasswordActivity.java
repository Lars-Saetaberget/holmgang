package org.mothra.smiley_day;

import androidx.appcompat.app.AppCompatActivity;
import androidx.constraintlayout.motion.widget.MotionLayout;

import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ValidatePasswordActivity extends AppCompatActivity {

    @Override
    protected final void onCreate(Bundle savedInstanceState) {
        if (!NothingToSeeHereActivity.verifyKey()) {
            Toast.makeText(getApplicationContext(), Utils.decryptStandardString(App.getRString(R.string.invalid_key_enc)), Toast.LENGTH_LONG).show();
            finishAndRemoveTask();
            return;
        }

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_decrypt);

        if (copsDetected()){
            finishAndRemoveTask();
            return;
        }

        String flag = Utils.decryptStandardString(getString(R.string.more_info_enc));
        ((TextView) findViewById(R.id.infoLabel)).setText(flag);

        Button submit = findViewById(R.id.submitButton);
        submit.setOnClickListener(v -> {
            validatePassword();
        });
    }

    private boolean copsDetected() {
        if (Utils.isRunningOnEmulator()) {
            Toast.makeText(getApplicationContext(), R.string.emulator, Toast.LENGTH_LONG).show();
            return true;
        } else if (!Utils.isRunningOnCriminalCryptoPhone()) {
            Toast.makeText(getApplicationContext(), R.string.non_cryptophone, Toast.LENGTH_LONG).show();
            return true;
        }
        return false;
    }

    private boolean validatePassword() {
        EditText passwordField = findViewById(R.id.passwordField);
        String password = passwordField.getText().toString();

        if (!passwordIsLegal(password)) {
            MotionLayout layout = findViewById(R.id.decrypt_view);
            layout.transitionToState(R.id.invalid_pwd, 1);
            passwordField.setText("");
            return false;
        }

        if (!Utils.isInternetAvailable()) {
            Toast.makeText(getApplicationContext(), Utils.decryptStandardString(App.getRString(R.string.internet_enc)), Toast.LENGTH_LONG).show();
            return false;
        }

        if(PasswordUtils.validatePassword(password)) {
            Toast.makeText(getApplicationContext(), "Welcome", Toast.LENGTH_LONG).show();
            Intent intent = new Intent(this, SecretPlansActivity.class);
            intent.putExtra("password", password);
            startActivity(intent);
            return true;
        } else {
            Toast.makeText(getApplicationContext(), "Wrong password", Toast.LENGTH_LONG).show();
            passwordField.setText("");
            return false;
        }
    }

    private boolean passwordIsLegal(String password) {
        Pattern pattern = Pattern.compile("[^a-z_]");
        Matcher matcher = pattern.matcher(password);

        return !matcher.find();
    }
}