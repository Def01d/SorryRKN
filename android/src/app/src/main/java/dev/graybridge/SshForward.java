package dev.graybridge;

import android.app.*;
import android.content.*;
import android.os.*;
import com.jcraft.jsch.Session;

/** Keeps a private server SOCKS port reachable via authenticated SSH on Android loopback. */
public class SshForward extends Service {
    private static Session session;
    private static int port;
    static synchronized int port(){return session!=null && session.isConnected()?port:0;}
    static synchronized void keep(Context c,Session opened,int number) {
        c.startForegroundService(new Intent(c,SshForward.class));
        if(session!=null)session.disconnect();
        session=opened;port=number;
    }
    static void stop(Context c){c.stopService(new Intent(c,SshForward.class));}
    private final Handler handler=new Handler(Looper.getMainLooper());
    private final Runnable watch=new Runnable(){public void run(){if(port()==0)stopSelf();else handler.postDelayed(this,2000);}};
    @Override public int onStartCommand(Intent intent,int flags,int id) {
        NotificationManager nm=getSystemService(NotificationManager.class);
        nm.createNotificationChannel(new NotificationChannel("socks","SOCKS5 через SSH",NotificationManager.IMPORTANCE_LOW));
        PendingIntent open=PendingIntent.getActivity(this,6,new Intent(this,RemoteActivity.class),PendingIntent.FLAG_IMMUTABLE|PendingIntent.FLAG_UPDATE_CURRENT);
        startForeground(214,new Notification.Builder(this,"socks").setSmallIcon(R.drawable.ic_bridge)
            .setContentTitle("SorryRKN · SOCKS5").setContentText("127.0.0.1:"+port()).setContentIntent(open).build());
        handler.removeCallbacks(watch);handler.postDelayed(watch,2000);
        return START_NOT_STICKY;
    }
    @Override public void onDestroy(){handler.removeCallbacks(watch);synchronized(SshForward.class){if(session!=null)session.disconnect();session=null;port=0;}super.onDestroy();}
    @Override public IBinder onBind(Intent intent){return null;}
}
