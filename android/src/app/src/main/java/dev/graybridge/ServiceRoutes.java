package dev.graybridge;

import android.app.*;
import android.os.*;
import android.widget.*;
import org.json.*;
import java.util.*;
import java.util.concurrent.*;
import com.chaquo.python.Python;

final class ServiceRoutes {
    private static final ExecutorService WORK = Executors.newSingleThreadExecutor();
    private static final Handler MAIN = new Handler(Looper.getMainLooper());

    static AlertDialog show(Activity activity) {
        LinearLayout body=new LinearLayout(activity);body.setOrientation(LinearLayout.VERTICAL);
        int padding=(int)(16*activity.getResources().getDisplayMetrics().density);body.setPadding(padding,padding,padding,padding);
        TextView note=new TextView(activity);
        note.setText("По умолчанию используется общий DNS. «Авто с резервом» разрешает смену DNS для этого сервиса после двух неудачных проверок. Ручной выбор закреплён. Применится при следующем подключении; активные соединения не переносятся.");body.addView(note);
        TextView loading=new TextView(activity);loading.setText("Загрузка маршрутов…");body.addView(loading);
        ScrollView scroll=new ScrollView(activity);scroll.addView(body);
        LinkedHashMap<String,Spinner> pickers=new LinkedHashMap<>();
        ArrayList<String> ids=new ArrayList<>(Arrays.asList("","auto"));
        AlertDialog dialog=new AlertDialog.Builder(activity).setTitle("Маршруты сервисов").setView(scroll).setNegativeButton("Отмена",null)
            .setPositiveButton("Сохранить",null).create();
        dialog.setOnShowListener(d->{
            Button save=dialog.getButton(AlertDialog.BUTTON_POSITIVE);
            save.setEnabled(false);
            save.setOnClickListener(v->{
                JSONObject value=new JSONObject();
                try {for(var entry:pickers.entrySet()){int pos=entry.getValue().getSelectedItemPosition();if(pos>=0 && pos<ids.size()){String selected=ids.get(pos);if(!selected.isEmpty())value.put(entry.getKey(),selected);}}}
                catch(JSONException ignored){return;}
                Settings.prefs(activity).edit().putString("service_dns",value.toString()).apply();
                String st=Settings.state(activity);
                if(st.equals("on") || st.equals("partial")) {
                    BridgeService.reload(activity);
                    Toast.makeText(activity,"Маршруты сохранены и применены.",Toast.LENGTH_SHORT).show();
                } else {
                    Toast.makeText(activity,"Маршруты сохранены.",Toast.LENGTH_SHORT).show();
                }
                dialog.dismiss();
            });
            Context app=activity.getApplicationContext();
            WORK.execute(()->{
                try {
                    DataUpdates.module(app);
                    JSONObject catalog=new JSONObject(Python.getInstance().getModule("dns_matrix").callAttr("catalog_json",app.getFilesDir().getPath()).toString());
                    JSONArray definitions=new JSONArray(Python.getInstance().getModule("service_catalog").callAttr("services_json").toString());
                    MAIN.post(()->{
                        if(activity.isFinishing()||activity.isDestroyed()||!dialog.isShowing())return;
                        try {
                            body.removeView(loading);
                            populate(activity,body,catalog,definitions,ids,pickers);
                            save.setEnabled(true);
                        } catch(Exception e){
                            loading.setText("Не удалось загрузить маршруты. Повторите позже.");
                        }
                    });
                } catch(Exception error) {
                    MAIN.post(()->{
                        if(activity.isFinishing()||activity.isDestroyed()||!dialog.isShowing())return;
                        loading.setText("Не удалось загрузить маршруты. Повторите после открытия экрана DNS.");
                    });
                }
            });
        });
        dialog.show();
        return dialog;
    }
    private static void populate(Activity activity,LinearLayout body,JSONObject catalog,JSONArray definitions,ArrayList<String> ids,LinkedHashMap<String,Spinner> pickers) throws Exception {
        JSONObject saved=new JSONObject(Settings.prefs(activity).getString("service_dns","{}"));
        ArrayList<String> names=new ArrayList<>(Arrays.asList("По умолчанию","Авто с резервом"));
        JSONArray profiles=catalog.getJSONArray("profiles");
        for(int i=0;i<profiles.length();i++){JSONObject p=profiles.getJSONObject(i);ids.add(p.getString("id"));names.add(p.getString("name"));}
        for(int i=0;i<definitions.length();i++){
            JSONObject service=definitions.getJSONObject(i);String id=service.getString("id");
            TextView label=new TextView(activity);label.setText(service.getString("name"));body.addView(label);
            Spinner picker=new Spinner(activity);picker.setAdapter(new ArrayAdapter<>(activity,android.R.layout.simple_spinner_dropdown_item,names));
            picker.setSelection(Math.max(0,ids.indexOf(saved.optString(id))));body.addView(picker);pickers.put(id,picker);
        }
    }
}
