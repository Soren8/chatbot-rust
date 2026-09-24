package com.chatbot.app.util;

import android.app.Activity;
import android.content.res.ColorStateList;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.os.Build;
import android.view.View;
import android.view.Window;
import android.widget.Button;
import android.widget.EditText;

/**
 * Shared Bootstrap-login styling for native server surfaces.
 *
 * <p>Matches {@code static/templates/login.html}: card {@code bg-dark}
 * {@code #212529} with {@code border-secondary} {@code #6c757d} rounding,
 * light {@code #f8f9fa} text, muted {@code #adb5bd} hints, primary
 * {@code #0d6efd} Apply and outlined Reset/Cancel. Both
 * {@code ServerSettingsActivity} and the MainActivity offline overlay build
 * through here so the two native screens stay cohesive.
 */
public final class ServerUiStyle {
    /** Bootstrap {@code bg-dark} used by the login card and inputs. */
    public static final int BG_DARK = 0xFF212529;
    /** Bootstrap {@code text-light} for titles, fields and buttons. */
    public static final int TEXT_LIGHT = 0xFFF8F9FA;
    /** Bootstrap {@code border-secondary} for card and field strokes. */
    public static final int BORDER = 0xFF6C757D;
    /** Bootstrap primary for the Apply action. */
    public static final int PRIMARY = 0xFF0D6EFD;
    /** Muted supporting text on the dark card. */
    public static final int MUTED = 0xFFADB5BD;
    /** Input placeholder tone matching {@code style.css} hints. */
    public static final int PLACEHOLDER = 0xFF9AA0A6;
    /** Inline error tone readable on the dark card. */
    public static final int ERROR = 0xFFFFB4AB;

    private ServerUiStyle() {
    }

    /** Dark status/navigation chrome with no light action bar flash. */
    public static void applyDarkChrome(Activity activity) {
        if (activity == null) {
            return;
        }
        try {
            if (activity.getActionBar() != null) {
                activity.getActionBar().hide();
            }
        } catch (Exception ignored) {
        }
        try {
            Window window = activity.getWindow();
            if (window == null) {
                return;
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                window.setStatusBarColor(BG_DARK);
                window.setNavigationBarColor(BG_DARK);
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                View decor = window.getDecorView();
                if (decor != null) {
                    int flags = decor.getSystemUiVisibility();
                    flags &= ~View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR;
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        flags &= ~View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR;
                    }
                    decor.setSystemUiVisibility(flags);
                }
            }
            window.setBackgroundDrawable(null);
            try {
                window.setBackgroundDrawableResource(android.R.color.transparent);
            } catch (Exception ignored) {
            }
            window.getDecorView().setBackgroundColor(BG_DARK);
        } catch (Exception ignored) {
        }
    }

    /** Card container matching the login {@code card bg-dark border-secondary}. */
    public static GradientDrawable cardBackground(float density) {
        GradientDrawable card = new GradientDrawable();
        card.setShape(GradientDrawable.RECTANGLE);
        card.setCornerRadius(12f * density);
        card.setColor(BG_DARK);
        card.setStroke((int) (1f * density + 0.5f), BORDER);
        return card;
    }

    /** Input field matching {@code form-control bg-dark border-secondary}. */
    public static GradientDrawable fieldBackground(float density) {
        GradientDrawable field = new GradientDrawable();
        field.setShape(GradientDrawable.RECTANGLE);
        field.setCornerRadius(8f * density);
        field.setColor(BG_DARK);
        field.setStroke((int) (1f * density + 0.5f), BORDER);
        return field;
    }

    /** Primary filled action with touch ripple. */
    public static Drawable primaryButtonBackground(float density) {
        GradientDrawable content = new GradientDrawable();
        content.setShape(GradientDrawable.RECTANGLE);
        content.setCornerRadius(8f * density);
        content.setColor(PRIMARY);
        return new RippleDrawable(
                ColorStateList.valueOf(0x33FFFFFF), content, null);
    }

    /** Outlined secondary action with touch ripple. */
    public static Drawable outlineButtonBackground(float density) {
        GradientDrawable content = new GradientDrawable();
        content.setShape(GradientDrawable.RECTANGLE);
        content.setCornerRadius(8f * density);
        content.setColor(0x00000000);
        content.setStroke((int) (1f * density + 0.5f), BORDER);
        return new RippleDrawable(
                ColorStateList.valueOf(0x20FFFFFF), content, null);
    }

    /** Sentence-case 16sp primary button with ripple and disabled dimming. */
    public static void stylePrimaryButton(Button button, float density) {
        if (button == null) {
            return;
        }
        button.setAllCaps(false);
        button.setTextSize(16f);
        button.setTextColor(TEXT_LIGHT);
        button.setBackground(primaryButtonBackground(density));
        int v = (int) (12f * density);
        int h = (int) (16f * density);
        button.setPadding(h, v, h, v);
        button.setMinHeight(0);
        button.setMinimumHeight(0);
    }

    /** Sentence-case 16sp outlined button with ripple and disabled dimming. */
    public static void styleOutlineButton(Button button, float density) {
        if (button == null) {
            return;
        }
        button.setAllCaps(false);
        button.setTextSize(16f);
        button.setTextColor(TEXT_LIGHT);
        button.setBackground(outlineButtonBackground(density));
        int v = (int) (12f * density);
        int h = (int) (16f * density);
        button.setPadding(h, v, h, v);
        button.setMinHeight(0);
        button.setMinimumHeight(0);
    }

    /** Dark rounded URL/text field matching the login inputs. */
    public static void styleField(EditText field, float density) {
        if (field == null) {
            return;
        }
        field.setTextColor(TEXT_LIGHT);
        field.setHintTextColor(PLACEHOLDER);
        field.setBackground(fieldBackground(density));
        int p = (int) (12f * density);
        field.setPadding(p, p, p, p);
        field.setTextSize(16f);
    }

    /** Enabled state with a dimmed disabled presentation. */
    public static void setEnabledWithDisabledAlpha(View view, boolean enabled) {
        if (view == null) {
            return;
        }
        view.setEnabled(enabled);
        view.setAlpha(enabled ? 1f : 0.5f);
    }
}
