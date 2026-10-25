package dev.graybridge;

import android.content.Context;
import org.json.*;
import java.time.OffsetDateTime;

final class RouteSummary {
    static String text(Context context,JSONObject report,JSONArray definitions) throws JSONException {
        if(definitions==null)return "\nЗагружаем список сервисов…";
        StringBuilder out=new StringBuilder("\nПубличные страницы; вход и генерация не проверены.\n");
        JSONObject choices=new JSONObject(Settings.prefs(context).getString("service_dns","{}"));
        JSONObject active=new JSONObject();
        JSONArray routes=new JSONObject(Settings.prefs(context).getString("traffic_report","{}")).optJSONArray("service_routes");
        if(!Settings.state(context).equals("off") && routes!=null)for(int i=0;i<routes.length();i++){
            JSONObject route=routes.getJSONObject(i);active.put(route.optString("service"),route.optString("profile"));
        }
        String fallback=Settings.prefs(context).getString("dns_profile","comss");
        JSONArray profiles=report.optJSONArray("profiles");
        boolean current=DnsProfiles.networkKey(context).equals(report.optString("network_key")) && fresh(report.optString("checked_at"));
        for(int i=0;i<definitions.length();i++){
            JSONObject service=definitions.getJSONObject(i);String id=service.getString("id");
            String mode=choices.optString(id),selected=mode.isEmpty()?fallback:mode;
            if(mode.equals("auto")){
                selected=fallback;int best=0;
                if(current && profiles!=null)for(int j=0;j<profiles.length();j++){
                    JSONObject row=profiles.getJSONObject(j);JSONObject cell=cell(row,id);
                    int score=cell==null?0:score(cell.optString("state"));
                    if(score>best || score>0 && score==best && row.optString("id").equals(fallback)){best=score;selected=row.optString("id");}
                }
            }
            out.append("\n").append(service.getString("name")).append(" · ")
                .append(mode.equals("auto")?"авто с резервом":mode.isEmpty()?"по умолчанию":"закреплён")
                .append(" · ").append(profileName(selected,profiles));
            if(active.has(id)){selected=active.optString(id);out.append("\nАктивен: ").append(profileName(selected,profiles));}
            String state="not_checked";
            if(current && profiles!=null)for(int j=0;j<profiles.length();j++){
                JSONObject row=profiles.getJSONObject(j);JSONObject cell=cell(row,id);
                if(row.optString("id").equals(selected) && cell!=null && fresh(cell.optString("checked_at",report.optString("checked_at"))))state=cell.optString("state");
            }
            out.append("\n").append(DnsProfiles.stateLabel(state));
            String hint=hint(state);if(!hint.isEmpty())out.append("\n").append(hint);
            out.append("\n");
        }
        if(!current)out.append("\nРезультаты отсутствуют, устарели или относятся к другой сети.");
        return out.toString();
    }
    private static JSONObject cell(JSONObject row,String service) throws JSONException {
        JSONArray cells=row.optJSONArray("results");if(cells==null)return null;
        for(int i=0;i<cells.length();i++)if(cells.getJSONObject(i).optString("service").equals(service))return cells.getJSONObject(i);
        return null;
    }
    private static int score(String state){return state.equals("reachable_public")?2:state.equals("login_unchecked")?1:0;}
    private static String profileName(String id,JSONArray profiles) throws JSONException {
        if(id.equals("public-doh"))return "Обычный DNS · свой IP";
        if(profiles!=null)for(int i=0;i<profiles.length();i++)if(profiles.getJSONObject(i).optString("id").equals(id))return profiles.getJSONObject(i).optString("name",id);
        return id;
    }
    private static boolean fresh(String date){try{long age=System.currentTimeMillis()/1000-OffsetDateTime.parse(date).toEpochSecond();return age>=-60 && age<1800;}catch(Exception ignored){return false;}}
    private static String hint(String state){
        switch(state){
            case "challenge":return "Откройте сервис в браузере и пройдите проверку.";
            case "login_unchecked":return "Страница отвечает; проверьте вход в своём браузере.";
            case "regional_refusal":return "Выберите другой DNS или включите авто с резервом.";
            case "rate_limited":return "Подождите перед повторной проверкой.";
            case "denied":return "Причина HTTP 403 не подтверждена как геоблокировка.";
            case "dns_error":case "timeout":case "transport_error":return "Повторите проверку или сравните другой DNS.";
            default:return "";
        }
    }
}
