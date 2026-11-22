package dev.graybridge;

import android.app.*;
import android.content.*;
import android.content.pm.ServiceInfo;
import android.os.*;
import com.jcraft.jsch.Session;

/** Keeps a private server SOCKS port reachable via authenticated SSH on Android loopback. */
public class SshForward extends Service {
    private static Session session;
    private static int port;
    static synchronized int port(){return session!=null && session.isConnected()?port:0;}
    static synchronized void keep(Context c,Session opened,int number) {
        if(session!=null && session!=opened)session.disconnect();
        session=opened;port=number;
        c.startForegroundService(new Intent(c,SshForward.class));
    }
    static void stop(Context c){
        synchronized(SshForward.class){if(session!=null)session.disconnect();session=null;port=0;}
        c.stopService(new Intent(c,SshForward.class));
    }
    private final Handler handler=new Handler(Looper.getMainLooper());
    private final Runnable watch=new Runnable(){public void run(){if(port()==0)stopSelf();else handler.postDelayed(this,2000);}};
    @Override public int onStartCommand(Intent intent,int flags,int id) {
        if (intent != null && "stop".equals(intent.getAction())) {
            synchronized(SshForward.class){if(session!=null)session.disconnect();session=null;port=0;}
            stopForeground(STOP_FOREGROUND_REMOVE);
            stopSelfResult(id);
            return START_NOT_STICKY;
        }
        NotificationManager nm=getSystemService(NotificationManager.class);
        nm.createNotificationChannel(new NotificationChannel("socks","SOCKS5 через SSH",NotificationManager.IMPORTANCE_LOW));
        PendingIntent open=PendingIntent.getActivity(this,6,new Intent(this,RemoteActivity.class),PendingIntent.FLAG_IMMUTABLE|PendingIntent.FLAG_UPDATE_CURRENT);
        PendingIntent close=PendingIntent.getService(this,7,new Intent(this,SshForward.class).setAction("stop"),PendingIntent.FLAG_IMMUTABLE|PendingIntent.FLAG_UPDATE_CURRENT);
        Notification n=new Notification.Builder(this,"socks").setSmallIcon(R.drawable.ic_bridge)
            .setContentTitle("SorryRKN · SOCKS5").setContentText("127.0.0.1:"+port()).setContentIntent(open)
            .setOngoing(true).setOnlyAlertOnce(true)
            .addAction(new Notification.Action.Builder(null,"Отключить",close).build()).build();
        if (Build.VERSION.SDK_INT >= 34) startForeground(214, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        else startForeground(214, n);
        if (port() == 0) {
            stopForeground(STOP_FOREGROUND_REMOVE);
            stopSelfResult(id);
            return START_NOT_STICKY;
        }
        handler.removeCallbacks(watch);handler.postDelayed(watch,2000);
        return START_NOT_STICKY;
    }
    @Override public void onDestroy(){handler.removeCallbacks(watch);synchronized(SshForward.class){if(session!=null)session.disconnect();session=null;port=0;}super.onDestroy();}
    @Override public IBinder onBind(Intent intent){return null;}
}
