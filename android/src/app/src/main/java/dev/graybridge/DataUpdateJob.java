package dev.graybridge;

import android.app.job.*;

public class DataUpdateJob extends JobService {
    private DataUpdates.Control control;
    @Override public boolean onStartJob(JobParameters params) {
        if (!Settings.prefs(this).getBoolean("auto_updates", true)) return false;
        DataUpdates.Control task = new DataUpdates.Control();
        control = task;
        DataUpdates.submit(getApplicationContext(), false, task, ok -> {
            if (control != task || !task.keepRunning()) return;
            control = null;
            jobFinished(params, !ok);
        });
        return true;
    }
    @Override public boolean onStopJob(JobParameters params) {
        if (control != null) control.cancel();
        control = null;
        return Settings.prefs(this).getBoolean("auto_updates", true);
    }
}
