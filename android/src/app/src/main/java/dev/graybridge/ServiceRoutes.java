package dev.graybridge;

import android.app.*;
import android.widget.*;
import org.json.*;
import java.util.*;
import com.chaquo.python.Python;

final class ServiceRoutes {
    static AlertDialog show(Activity activity) {
        LinearLayout body=new LinearLayout(activity);body.setOrientation(LinearLayout.VERTICAL);
        int padding=(int)(16*activity.getResources().getDisplayMetrics().density);body.setPadding(padding,padding,padding,padding);
        TextView note=new TextView(activity);
        note.setText("По умолчанию используется общий DNS. «Авто с резервом» разрешает смену DNS для этого сервиса после двух неудачных проверок. Ручной выбор закреплён. Применится при следующем подключении; активные соединения не переносятся.");body.addView(note);
        try {
            DataUpdates.module(activity);
            JSONObject catalog=new JSONObject(Python.getInstance().getModule("dns_matrix").callAttr("catalog_json",activity.getFilesDir().getPath()).toString());
            JSONArray definitions=new JSONArray(Python.getInstance().getModule("service_catalog").callAttr("services_json").toString());
            return populate(activity,body,catalog,definitions);
        } catch(Exception error) {
            TextView message=new TextView(activity);message.setText("Не удалось загрузить маршруты. Повторите после открытия экрана DNS.");body.addView(message);
            return new AlertDialog.Builder(activity).setTitle("Маршруты сервисов").setView(body).setPositiveButton("Закрыть",null).show();
        }
    }
    private static AlertDialog populate(Activity activity,LinearLayout body,JSONObject catalog,JSONArray definitions) throws Exception {
        JSONObject saved=new JSONObject(Settings.prefs(activity).getString("service_dns","{}"));
        ArrayList<String> ids=new ArrayList<>(Arrays.asList("","auto"));
        ArrayList<String> names=new ArrayList<>(Arrays.asList("По умолчанию","Авто с резервом"));
        JSONArray profiles=catalog.getJSONArray("profiles");
        for(int i=0;i<profiles.length();i++){JSONObject p=profiles.getJSONObject(i);ids.add(p.getString("id"));names.add(p.getString("name"));}
        LinkedHashMap<String,Spinner> pickers=new LinkedHashMap<>();
        for(int i=0;i<definitions.length();i++){
            JSONObject service=definitions.getJSONObject(i);String id=service.getString("id");
            TextView label=new TextView(activity);label.setText(service.getString("name"));body.addView(label);
            Spinner picker=new Spinner(activity);picker.setAdapter(new ArrayAdapter<>(activity,android.R.layout.simple_spinner_dropdown_item,names));
            picker.setSelection(Math.max(0,ids.indexOf(saved.optString(id))));body.addView(picker);pickers.put(id,picker);
        }
        ScrollView scroll=new ScrollView(activity);scroll.addView(body);
        return new AlertDialog.Builder(activity).setTitle("Маршруты сервисов").setView(scroll).setNegativeButton("Отмена",null)
            .setPositiveButton("Сохранить",(d,w)->{
                JSONObject value=new JSONObject();
                try {for(var entry:pickers.entrySet()){String selected=ids.get(entry.getValue().getSelectedItemPosition());if(!selected.isEmpty())value.put(entry.getKey(),selected);}}
                catch(JSONException ignored){return;}
                Settings.prefs(activity).edit().putString("service_dns",value.toString()).apply();
                Toast.makeText(activity,"Маршруты сохранены. Переподключитесь для применения.",Toast.LENGTH_LONG).show();
            }).show();
    }
}
