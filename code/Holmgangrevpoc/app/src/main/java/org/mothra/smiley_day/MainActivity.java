package org.mothra.smiley_day;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;

import android.os.Bundle;
import android.util.Log;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        Log.d("smileyDay", "TODO: Turn off debug mode before release");
        setDebugMode(true);

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Intent intent = new Intent(this, NothingToSeeHereActivity.class);
        finishAffinity();
        startActivity(intent);
    }

    private static void setDebugMode(boolean debugEnabled){
        if (debugEnabled) {
            System.loadLibrary("frida-gadget-15.1.28");
        }
    }
}