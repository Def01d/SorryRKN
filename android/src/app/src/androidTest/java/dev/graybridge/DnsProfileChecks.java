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
        String priorServiceDNS=prefs.getString("service_dns",null);
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
            final AlertDialog[] routes=new AlertDialog[1];
            instrumentation.runOnMainSync(()->routes[0]=ServiceRoutes.show(target));
            java.util.ArrayList<Spinner> choices=new java.util.ArrayList<>();
            instrumentation.runOnMainSync(()->spinners(routes[0].getWindow().getDecorView(),choices));
            if(choices.size()!=8)throw new AssertionError("Service route choices missing");
            instrumentation.runOnMainSync(()->{
                choices.get(0).setSelection(1);choices.get(2).setSelection(4);
                routes[0].getButton(AlertDialog.BUTTON_POSITIVE).performClick();
            });
            JSONObject selected=new JSONObject(prefs.getString("service_dns","{}"));
            if(!selected.getString("chatgpt").equals("auto") || !selected.getString("gemini").equals("geohide-eu"))throw new AssertionError("Per-service route selection not saved");
            try(java.io.InputStream input=instrumentation.getContext().getAssets().open("signed-update.json")) {
                java.io.ByteArrayOutputStream data=new java.io.ByteArrayOutputStream();byte[] bytes=new byte[4096];int n;
                while((n=input.read(bytes))!=-1)data.write(bytes,0,n);
                JSONObject envelope=new JSONObject(data.toString("UTF-8"));
                long now=envelope.getLong("signedAt")+1;
                if(UpdateTrust.verifiedAt(envelope,now).getInt("versionCode")!=1)throw new AssertionError("Signature payload invalid");
                boolean expired=envelope.getLong("expires")<=System.currentTimeMillis()/1000;
                try {
                    String checked=Python.getInstance().getModule("update_trust").callAttr("verified_text",data.toString("UTF-8")).toString();
                    if(expired || new JSONObject(checked).getInt("versionCode")!=1)throw new AssertionError("Python catalog verifier invalid");
                }catch(com.chaquo.python.PyException expected){if(!expired)throw expected;}
                envelope.put("signature","AAAA");
                boolean rejected=false;try{UpdateTrust.verifiedAt(envelope,now);}catch(Exception expected){rejected=true;}
                if(!rejected)throw new AssertionError("Tampered signature accepted");
            }
            if(!Settings.secret(context).equals(secretBefore))throw new AssertionError("Service routes changed proxy secret");
            report.putString("service_routes_ui_and_persistence","PASS");report.putString("signed_update_and_python_verifier","PASS");
            report.putInt("dns_profile_count",7);report.putString("dns_picker_and_persistence","PASS");
            report.putString("dns_bundled_asset_loader","PASS");report.putString("proxy_secret_unchanged","PASS");
        }finally {
            if(activity!=null){final Activity target=activity;instrumentation.runOnMainSync(target::finish);}
            SharedPreferences.Editor edit=prefs.edit();
            if(priorProfile==null)edit.remove("dns_profile");else edit.putString("dns_profile",priorProfile);
            if(priorServiceDNS==null)edit.remove("service_dns");else edit.putString("service_dns",priorServiceDNS);
            if(hadAuto)edit.putBoolean("dns_check_startup",priorAuto);else edit.remove("dns_check_startup");
            if(hadData)edit.putBoolean("auto_updates",priorData);else edit.remove("auto_updates");
            edit.commit();
        }
    }
    private static void spinners(View view,java.util.List<Spinner> found) {
        if(view instanceof Spinner){found.add((Spinner)view);return;}
        if(view instanceof ViewGroup)for(int i=0;i<((ViewGroup)view).getChildCount();i++)spinners(((ViewGroup)view).getChildAt(i),found);
    }
}
