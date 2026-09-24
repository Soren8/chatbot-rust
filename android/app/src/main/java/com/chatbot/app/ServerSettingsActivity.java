package com.chatbot.app;

import android.app.Activity;
import android.os.Bundle;
import android.text.InputType;
import android.util.DisplayMetrics;
import android.view.Gravity;
import android.view.View;
import android.view.inputmethod.EditorInfo;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import com.chatbot.app.util.ServerUiStyle;
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
        ServerUiStyle.applyDarkChrome(this);
        float density = getResources().getDisplayMetrics().density;
        int padOuter = (int) (16 * density);
        int padCard = (int) (20 * density);

        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(ServerUiStyle.BG_DARK);
        scroll.setPadding(padOuter, padOuter, padOuter, padOuter);

        LinearLayout outer = new LinearLayout(this);
        outer.setOrientation(LinearLayout.VERTICAL);
        outer.setGravity(Gravity.CENTER);
        outer.setBackgroundColor(ServerUiStyle.BG_DARK);
        ScrollView.LayoutParams outerParams = new ScrollView.LayoutParams(
                ScrollView.LayoutParams.MATCH_PARENT,
                ScrollView.LayoutParams.WRAP_CONTENT);
        outer.setLayoutParams(outerParams);

        DisplayMetrics metrics = getResources().getDisplayMetrics();
        int maxCard = (int) (420 * density);
        int avail = metrics.widthPixels - (int) (32 * density);
        int cardWidth = Math.min(avail, maxCard);
        int minCard = (int) (280 * density);
        if (cardWidth < minCard) {
            cardWidth = LinearLayout.LayoutParams.MATCH_PARENT;
        }

        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackground(ServerUiStyle.cardBackground(density));
        card.setPadding(padCard, padCard, padCard, padCard);
        LinearLayout.LayoutParams cardParams = new LinearLayout.LayoutParams(
                cardWidth,
                LinearLayout.LayoutParams.WRAP_CONTENT);
        cardParams.gravity = Gravity.CENTER_HORIZONTAL;
        card.setLayoutParams(cardParams);

        TextView title = new TextView(this);
        title.setText("Server URL");
        title.setTextSize(20f);
        title.setTextColor(ServerUiStyle.TEXT_LIGHT);
        title.setGravity(Gravity.CENTER);
        card.addView(title);

        TextView hint = new TextView(this);
        hint.setText("Enter an https:// address (host[:port] only).\n"
                + "No path, userinfo, query or fragment. Applies to the app,"
                + " cookies, logs and voice screens after reload.");
        hint.setTextSize(13f);
        hint.setTextColor(ServerUiStyle.MUTED);
        hint.setPadding(0, padCard / 2, 0, 0);
        card.addView(hint);

        input = new EditText(this);
        input.setSingleLine(true);
        input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        input.setImeOptions(EditorInfo.IME_ACTION_DONE);
        input.setHint("https://example.com");
        input.setText(ServerUrlSettingStore.selected(this));
        ServerUiStyle.styleField(input, density);
        LinearLayout.LayoutParams inputParams = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
        inputParams.setMargins(0, padCard, 0, 0);
        card.addView(input, inputParams);

        TextView flavorLabel = new TextView(this);
        flavorLabel.setTextSize(12f);
        flavorLabel.setTextColor(ServerUiStyle.MUTED);
        flavorLabel.setText("Build default: " + ServerUrlSettingStore.flavorDefault(this));
        flavorLabel.setPadding(0, padCard / 2, 0, 0);
        card.addView(flavorLabel);

        errorLabel = new TextView(this);
        errorLabel.setTextColor(ServerUiStyle.ERROR);
        errorLabel.setTextSize(13f);
        errorLabel.setPadding(0, padCard / 2, 0, 0);
        errorLabel.setVisibility(View.GONE);
        card.addView(errorLabel);

        Button apply = new Button(this);
        apply.setText("Apply");
        ServerUiStyle.stylePrimaryButton(apply, density);
        applyButton = apply;
        apply.setOnClickListener(v -> applyChange(input == null
                ? "" : input.getText().toString()));
        LinearLayout.LayoutParams applyParams = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
        applyParams.setMargins(0, padCard, 0, 0);
        card.addView(apply, applyParams);

        Button reset = new Button(this);
        reset.setText("Reset to default");
        ServerUiStyle.styleOutlineButton(reset, density);
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
                    errorLabel.setVisibility(View.VISIBLE);
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
        LinearLayout.LayoutParams resetParams = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
        resetParams.setMargins(0, (int) (12 * density), 0, 0);
        card.addView(reset, resetParams);

        Button cancel = new Button(this);
        cancel.setText("Cancel");
        ServerUiStyle.styleOutlineButton(cancel, density);
        cancelButton = cancel;
        cancel.setOnClickListener(v -> {
            if (pending) {
                return;
            }
            setResult(RESULT_CANCELED);
            finish();
        });
        LinearLayout.LayoutParams cancelParams = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
        cancelParams.setMargins(0, (int) (12 * density), 0, 0);
        card.addView(cancel, cancelParams);

        outer.addView(card);
        scroll.addView(outer);
        setContentView(scroll);
    }

    /** While the cookie purge is in flight the selection must not move. */
    private void setPending(boolean value) {
        pending = value;
        boolean enabled = !value;
        ServerUiStyle.setEnabledWithDisabledAlpha(applyButton, enabled);
        ServerUiStyle.setEnabledWithDisabledAlpha(resetButton, enabled);
        ServerUiStyle.setEnabledWithDisabledAlpha(cancelButton, enabled);
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
                errorLabel.setVisibility(View.VISIBLE);
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
