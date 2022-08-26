package org.mothra.smiley_day;

import android.graphics.Typeface;
import android.text.SpannableString;
import android.text.style.StyleSpan;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import java.util.ArrayList;

public class StepAdapter extends RecyclerView.Adapter {

    private ArrayList<Step> steps;

    public StepAdapter(ArrayList<Step> steps) {
        this.steps = steps;
    }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View v = (View) LayoutInflater.from(parent.getContext()).inflate(R.layout.item_step, parent, false);

        return new ViewHolder(v);
    }

    @Override
    public void onBindViewHolder(@NonNull RecyclerView.ViewHolder holder, int position) {
        Step step = steps.get(position);

        SpannableString title = new SpannableString("TODO " + (position + 1) + " - " + step.getTitle());
        title.setSpan(new StyleSpan(Typeface.BOLD), 0, title.length(), 0);

        ((ViewHolder) holder).name.setText(title);
        ((ViewHolder) holder).description.setText(step.getDescription());
    }

    @Override
    public int getItemCount() {
        if (steps != null) {
            return steps.size();
        } else {
            return 0;
        }
    }

    public static class ViewHolder extends RecyclerView.ViewHolder {
        public final View view;
        public final TextView name;
        public final TextView description;

        public ViewHolder(View view) {
            super(view);
            this.view = view;
            name = view.findViewById(R.id.step_title);
            description = view.findViewById(R.id.step_description);
        }
    }
}
