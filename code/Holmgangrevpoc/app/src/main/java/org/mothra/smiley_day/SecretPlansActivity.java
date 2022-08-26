package org.mothra.smiley_day;

import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import android.os.Bundle;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;

public class SecretPlansActivity extends AppCompatActivity {

    private RecyclerView stepsRecycler;
    private RecyclerView.Adapter adapter;

    private static final Object lock = new Object();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_secret_plans);

        String jsonSteps = getSteps(getIntent().getStringExtra("password"));

        if (jsonSteps == null) {
            finishAndRemoveTask();
            return;
        }

        ArrayList<Step> steps = new ArrayList<>();

        try {
            JSONArray json = new JSONArray(jsonSteps);

            for(int i = 0; i < json.length(); i++) {
                steps.add(new Step(json.getJSONObject(i).getString("title"), json.getJSONObject(i).getString("description")));
            }

        } catch (JSONException e) {
            e.printStackTrace();
        }

        this.stepsRecycler = (RecyclerView) findViewById(R.id.recycler);
        RecyclerView.LayoutManager mLayoutManager = new LinearLayoutManager(this);
        this.stepsRecycler.setLayoutManager(mLayoutManager);

        adapter = new StepAdapter(steps);
        this.stepsRecycler.setAdapter(adapter);
    }

    private static String getSteps(String password) {
        final String[] result = new String[1];

        Thread thread = new Thread(() -> {
            synchronized (lock) {
                result[0] = getStepsFromCloud(password);
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

        if (result[0].equals("401")) {
            Toast.makeText(App.getContext(), Utils.decryptStandardString(App.getRString(R.string.incorrect_enc)), Toast.LENGTH_LONG).show();
            return null;
        }

        return result[0];
    }

    private static String getStepsFromCloud(String password) {
        String steps = "";

        HttpURLConnection urlConnection = null;

        try {
            URL url = new URL(App.getRString(R.string.api_url) + App.getRString(R.string.api_endpoint_steps));
            urlConnection = (HttpURLConnection) url.openConnection();

            urlConnection.setRequestMethod("POST");
            urlConnection.setRequestProperty("Content-Type", "application/json");
            urlConnection.setRequestProperty("Accept", "application/json");
            urlConnection.setDoOutput(true);
            urlConnection.setDoInput(true);

            JSONObject body = new JSONObject();
            body.put("username", Utils.getAppID());
            body.put("password", password);

            DataOutputStream os = new DataOutputStream(urlConnection.getOutputStream());
            os.writeBytes(body.toString());

            int status = urlConnection.getResponseCode();
            if (status == 401) {
                return "401";
            }

            BufferedReader br = new BufferedReader(
                    new InputStreamReader(urlConnection.getInputStream(), "utf-8"));
            StringBuilder response = new StringBuilder();
            String responseLine = null;
            while ((responseLine = br.readLine()) != null) {
                response.append(responseLine.trim());
            }

            steps = response.toString();
        } catch (IOException | JSONException e) {
            e.printStackTrace();
        } finally {
            if (urlConnection != null) {
                urlConnection.disconnect();
            }
        }

        return steps;
    }

}