package dev.graybridge;

import android.app.PendingIntent;
import android.content.*;
import android.net.VpnService;
import android.os.Build;
import android.service.quicksettings.*;

public class BridgeTile extends TileService {
    @Override public void onStartListening() {
        Tile tile = getQsTile();
        if (tile == null) return;
        String state = Settings.state(this);
        tile.setState(state.equals("on") || state.equals("partial") ? Tile.STATE_ACTIVE : Tile.STATE_INACTIVE);
        tile.setLabel("SorryRKN");
        if (Build.VERSION.SDK_INT >= 29) tile.setSubtitle(switch(state) {
            case "on" -> "Включён"; case "partial" -> Settings.prefs(this).getBoolean("vpn_active",false)?"Частичный доступ":"Только Telegram"; case "starting" -> "Запуск…";
            case "stopping" -> "Выключение…"; case "error" -> "Ошибка"; default -> "Выключен";
        });
        tile.updateTile();
    }
    @android.annotation.SuppressLint("StartActivityAndCollapseDeprecated") // Intent overload is required before API 34.
    @Override public void onClick() {
        super.onClick();
        unlockAndRun(() -> {
            if (Settings.busy(this)) BridgeService.stop(this);
            else if ((Settings.vpn(this) && VpnService.prepare(this) != null) ||
                     (!Settings.vpn(this) && !Settings.telegram(this))) {
                Intent intent = new Intent(this, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK).putExtra("connect", true);
                if (Build.VERSION.SDK_INT >= 34) startActivityAndCollapse(PendingIntent.getActivity(this, 2, intent, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT));
                else startActivityAndCollapse(intent);
            } else BridgeService.start(this);
        });
    }
}
