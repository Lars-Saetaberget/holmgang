package org.mothra.smiley_day;

import androidx.appcompat.app.AppCompatActivity;
import androidx.constraintlayout.motion.widget.MotionLayout;

import android.content.Intent;
import android.os.Bundle;
import android.util.Base64;
import android.widget.Button;
import android.widget.Toast;

import com.marcinmoskala.arcseekbar.ArcSeekBar;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Random;


public class NothingToSeeHereActivity extends AppCompatActivity {

    protected static ArrayList<String> clicks = new ArrayList<>();
    private static final byte[] key_bytes = {
            0x48, 0x42, 0x4d, 0x41, 0x45, 0x30, 0x6b, 0x4c, 0x4c, 0x52, 0x59, 0x41, 0x53, 0x78,
            0x77, 0x54, 0x41, 0x42, 0x4e, 0x4a, 0x43, 0x79, 0x30, 0x57, 0x41, 0x45, 0x73, 0x63,
            0x45, 0x77, 0x41, 0x54, 0x53, 0x52, 0x63, 0x70, 0x45, 0x52, 0x49, 0x41, 0x53, 0x51,
            0x51, 0x46, 0x41, 0x42, 0x41, 0x56, 0x63, 0x77, 0x41, 0x52, 0x45, 0x78, 0x41, 0x47,
            0x58, 0x77, 0x30, 0x58, 0x41, 0x54, 0x68, 0x4a, 0x48, 0x68, 0x55, 0x57, 0x42, 0x6c,
            0x38, 0x4e, 0x46, 0x77, 0x45, 0x34, 0x53, 0x52, 0x34, 0x56, 0x46, 0x67, 0x5a, 0x66,
            0x45, 0x52, 0x4d, 0x47, 0x4b, 0x67, 0x49, 0x3d};
    private static final int[] xor_bytes = {
            0xca, 0xc2, 0xe6, 0xe8, 0xca, 0xe5, 0xbe, 0xca, 0xce, 0xce};

    private static final int[] messages = {
            R.string.random_message1,
            R.string.random_message2,
            R.string.random_message3,
            R.string.random_message4,
            R.string.random_message5,
            R.string.random_message6,
            R.string.random_message8,
            R.string.random_message9,
    };

    private static String catchMeIfYouCan = "";

    private static final Random random = new Random();
    private static Toast toast;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_nothing_to_see_here);

        setListeners();
    }

    private void setListeners() {
        final Button left_eye = findViewById(R.id.left_eye);
        final Button right_eye = findViewById(R.id.right_eye);
        final ArcSeekBar mouth = findViewById(R.id.mouth);

        MotionLayout view = findViewById(R.id.nothing_to_see_here);

        left_eye.setOnClickListener(v -> {
            randomToast();
            clicks.add("left");
            view.jumpToState(R.id.end);
            view.transitionToState(R.id.left_wink);
            if (verifyKey()) {
                activateSecret();
            } else  {
                if (mouth.isEnabled()) {
                    mouth.setEnabled(false);
                    mouth.setProgress(0);
                }

            }
        });

        right_eye.setOnClickListener(v -> {
            randomToast();
            clicks.add("right");
            view.jumpToState(R.id.end);
            view.transitionToState(R.id.right_wink);
            if (verifyKey()) {
                activateSecret();
            } else  {
                if (mouth.isEnabled()) {
                    mouth.setEnabled(false);
                    mouth.setProgress(0);
                }
            }
        });

        mouth.setOnProgressChangedListener(progress -> {
            if (progress >= 100) {
                Intent intent = new Intent(this, ValidatePasswordActivity.class);
                finishAffinity();
                startActivity(intent);
            }

            if (progress == 42) {
                catchMeIfYouCan = Utils.decryptStandardString(App.getRString(R.string.secret_message_enc));
            } else {
                catchMeIfYouCan = "";
            }
        });
    }

    private void activateSecret() {
        ArcSeekBar mouth = findViewById(R.id.mouth);
        mouth.setEnabled(true);
        mouth.setProgress(0);
    }

    private void randomToast() {
        if (toast != null) {
            toast.cancel();
        }
        toast = Toast.makeText(getApplicationContext(), messages[random.nextInt(messages.length)], Toast.LENGTH_SHORT);
        toast.show();
    }

    protected static final String getKey() {
        byte[] bytes = Base64.decode(key_bytes, Base64.DEFAULT);
        byte[] intermediate = new byte[bytes.length];

        for (int i = 0; i < bytes.length; i++) {
            intermediate[i] = (byte) (bytes[i] ^ (xor_bytes[i % xor_bytes.length] / 2));
        }

        return Utils.RSA8092BitDecrypt(new String(intermediate, StandardCharsets.UTF_8));
    }

    protected static final boolean verifyKey() {
        String[] key = getKey().split(",");

        if (clicks.size() < key.length) {
            return false;
        }

        while (clicks.size() > key.length) {
            clicks.remove(0);
        }

        for (int i = 0; i < key.length; i++) {
            if (!key[i].equals(clicks.get(i))) {
                return false;
            }
        }

        return true;
    }
}