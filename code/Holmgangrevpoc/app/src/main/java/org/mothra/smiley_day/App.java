package org.mothra.smiley_day;

import android.app.Application;
import android.content.Context;

import java.lang.ref.WeakReference;

public class App extends Application {

    private static WeakReference<Context> mContext;

    @Override
    public void onCreate() {
        super.onCreate();
        mContext = new WeakReference<>(this);
    }

    public static Context getContext() {
        return mContext.get();
    }

    public static String getRString(int resId) {
        return getContext().getString(resId);
    }
}