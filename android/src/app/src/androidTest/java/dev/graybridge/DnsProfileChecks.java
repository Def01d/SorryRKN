package dev.graybridge;

import android.app.*;
import android.content.*;
import android.os.*;
import android.view.*;
import android.widget.*;
import com.chaquo.python.Python;
import org.json.*;

/** Offline UI/config checks; public network checks are separate. */
final class DnsProfileChecks {
    private static Spinner spinner(View view) {
        if(view instanceof Spinner)return (Spinner)view;
        if(view instanceof ViewGroup)for(int i=0;i<((ViewGroup)view).getChildCount();i++) {
            Spinner found=spinner(((ViewGroup)view).getChildAt(i));if(found!=null)return found;
        }
        return null;
    }
    static void run(Instrumentation instrumentation,Context context,Bundle report) throws Exception {
        SharedPreferences prefs=Settings.prefs(context);
        String priorProfile=prefs.getString("dns_profile",null);
        boolean hadAuto=prefs.contains("dns_check_startup"),priorAuto=prefs.getBoolean("dns_check_startup",true);
        boolean hadData=prefs.contains("auto_updates"),priorData=prefs.getBoolean("auto_updates",true);
        String secretBefore=Settings.secret(context);
        Activity activity=null;
        try {
            prefs.edit().putBoolean("dns_check_startup",false).putBoolean("auto_updates",false).commit();
            JSONObject catalog=new JSONObject(Python.getInstance().getModule("dns_matrix").callAttr("catalog_json",context.getFilesDir().getPath()).toString());
            JSONArray profiles=catalog.getJSONArray("profiles");
            if(profiles.length()!=7)throw new AssertionError("Bundled DNS profiles unavailable inside APK");
            activity=instrumentation.startActivitySync(new Intent(context,MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
            final Activity target=activity;
            final AlertDialog[] dialog=new AlertDialog[1];
            instrumentation.runOnMainSync(()->dialog[0]=DnsProfiles.show(target));
            final Spinner[] picker=new Spinner[1];
            long expires=SystemClock.elapsedRealtime()+15000;
            do {
                instrumentation.runOnMainSync(()->picker[0]=spinner(dialog[0].getWindow().getDecorView()));
                if(picker[0]!=null && picker[0].isEnabled())break;
                Thread.sleep(100);
            }while(SystemClock.elapsedRealtime()<expires);
            if(picker[0]==null || !picker[0].isEnabled() || picker[0].getCount()!=7)throw new AssertionError("DNS picker did not load");
            instrumentation.runOnMainSync(()->{
                picker[0].setSelection(2);
                dialog[0].getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(true);
                dialog[0].getButton(AlertDialog.BUTTON_POSITIVE).performClick();
            });
            if(!prefs.getString("dns_profile","").equals(profiles.getJSONObject(2).getString("id")))throw new AssertionError("DNS choice was not saved");
            if(!Settings.secret(context).equals(secretBefore))throw new AssertionError("DNS choice changed proxy secret");
            if(!Settings.state(context).equals("off"))throw new AssertionError("DNS comparison started VPN");
            report.putInt("dns_profile_count",7);report.putString("dns_picker_and_persistence","PASS");
            report.putString("dns_bundled_asset_loader","PASS");report.putString("proxy_secret_unchanged","PASS");
        }finally {
            if(activity!=null){final Activity target=activity;instrumentation.runOnMainSync(target::finish);}
            SharedPreferences.Editor edit=prefs.edit();
            if(priorProfile==null)edit.remove("dns_profile");else edit.putString("dns_profile",priorProfile);
            if(hadAuto)edit.putBoolean("dns_check_startup",priorAuto);else edit.remove("dns_check_startup");
            if(hadData)edit.putBoolean("auto_updates",priorData);else edit.remove("auto_updates");
            edit.commit();
        }
    }
}
