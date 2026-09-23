package com.chatbot.app;

import android.app.Activity;
import android.os.Bundle;
import android.view.Gravity;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import com.chatbot.app.util.ServerUrlSettingStore;

/**
 * Native server-selection screen. Writes through
 * {@link ServerUrlSettingStore#setAsync} / {@code #resetAsync}: invalid
 * input stays inline and applies nothing, a no-op closes canceled (no
 * reload), and a real change persists only after the old origin's
 * session + credential cookies are purged, then reports OK so MainActivity
 * recreates the Bridge onto a clean jar. Purge or persist failure stays
 * inline with a retry message: nothing is saved and nothing reloads.
 */
public class ServerSettingsActivity extends Activity {
    private EditText input;
    private TextView errorLabel;
    private Button applyButton;
    private Button resetButton;
    private Button cancelButton;
    private boolean pending = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (24 * getResources().getDisplayMetrics().density);
        root.setPadding(pad, pad, pad, pad);
        root.setGravity(Gravity.CENTER);

        TextView title = new TextView(this);
        title.setText("Server URL");
        title.setTextSize(20f);
        root.addView(title);

        TextView hint = new TextView(this);
        hint.setText("Enter an https:// address (host[:port] only).\n"
                + "No path, userinfo, query or fragment. Applies to the app,"
                + " cookies, logs and voice screens after reload.");
        hint.setTextSize(13f);
        hint.setPadding(0, pad / 2, 0, 0);
        root.addView(hint);

        input = new EditText(this);
        input.setSingleLine(true);
        input.setHint("https://example.com");
        input.setText(ServerUrlSettingStore.selected(this));
        LinearLayout.LayoutParams inputParams = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
        inputParams.setMargins(0, pad, 0, 0);
        root.addView(input, inputParams);

        TextView flavorLabel = new TextView(this);
        flavorLabel.setTextSize(12f);
        flavorLabel.setText("Build default: " + ServerUrlSettingStore.flavorDefault(this));
        flavorLabel.setPadding(0, pad / 2, 0, 0);
        root.addView(flavorLabel);

        errorLabel = new TextView(this);
        errorLabel.setTextColor(0xFFFFB4AB);
        errorLabel.setTextSize(13f);
        errorLabel.setPadding(0, pad / 2, 0, 0);
        errorLabel.setVisibility(android.view.View.GONE);
        root.addView(errorLabel);

        Button apply = new Button(this);
        apply.setText("Apply");
        applyButton = apply;
        apply.setOnClickListener(v -> applyChange(input == null
                ? "" : input.getText().toString()));
        root.addView(apply);

        Button reset = new Button(this);
        reset.setText("Reset to default");
        resetButton = reset;
        reset.setOnClickListener(v -> {
            if (pending) {
                return;
            }
            setPending(true);
            ServerUrlSettingStore.resetAsync(this, change -> {
                setPending(false);
                if (!change.success) {
                    errorLabel.setText(change.error);
                    errorLabel.setVisibility(android.view.View.VISIBLE);
                    return;
                }
                input.setText(ServerUrlSettingStore.flavorDefault(this));
                if (change.applied) {
                    finishWithSuccess();
                } else {
                    Toast.makeText(this, "Already the default server", Toast.LENGTH_SHORT).show();
                    setResult(RESULT_CANCELED);
                    finish();
                }
            });
        });
        root.addView(reset);

        Button cancel = new Button(this);
        cancel.setText("Cancel");
        cancelButton = cancel;
        cancel.setOnClickListener(v -> {
            if (pending) {
                return;
            }
            setResult(RESULT_CANCELED);
            finish();
        });
        root.addView(cancel);

        setContentView(root);
    }

    /** While the cookie purge is in flight the selection must not move. */
    private void setPending(boolean value) {
        pending = value;
        boolean enabled = !value;
        if (applyButton != null) {
            applyButton.setEnabled(enabled);
        }
        if (resetButton != null) {
            resetButton.setEnabled(enabled);
        }
        if (cancelButton != null) {
            cancelButton.setEnabled(enabled);
        }
    }

    private void applyChange(String raw) {
        if (pending) {
            return;
        }
        setPending(true);
        ServerUrlSettingStore.setAsync(this, raw, change -> {
            setPending(false);
            if (!change.success) {
                errorLabel.setText(change.error);
                errorLabel.setVisibility(android.view.View.VISIBLE);
                return;
            }
            if (!change.applied) {
                Toast.makeText(this, "Server unchanged", Toast.LENGTH_SHORT).show();
                setResult(RESULT_CANCELED);
                finish();
                return;
            }
            Toast.makeText(this, "Server switched to " + change.value, Toast.LENGTH_SHORT).show();
            finishWithSuccess();
        });
    }

    private void finishWithSuccess() {
        setResult(RESULT_OK);
        finish();
    }
}
