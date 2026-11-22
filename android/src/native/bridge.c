#include <jni.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <unistd.h>
#include <hev-socks5-tunnel.h>

static pthread_mutex_t tunnel_mutex = PTHREAD_MUTEX_INITIALIZER;
static atomic_bool tunnel_active = false;
static atomic_bool tunnel_quit_sent = false;

JNIEXPORT jint JNICALL Java_dev_graybridge_NativeTunnel_run(JNIEnv *env, jclass cls, jstring config, jint fd) {
    (void)cls;
    const char *path = (*env)->GetStringUTFChars(env, config, 0);
    if (!path) return -1;
    pthread_mutex_lock(&tunnel_mutex);
    atomic_store(&tunnel_quit_sent, false);
    atomic_store(&tunnel_active, true);
    // The service retains ownership of the ParcelFileDescriptor.
    int owned_fd = dup(fd);
    int result = owned_fd < 0 ? -1 : hev_socks5_tunnel_main_from_file(path, owned_fd);
    if (owned_fd >= 0) close(owned_fd);
    atomic_store(&tunnel_active, false);
    atomic_store(&tunnel_quit_sent, false);
    pthread_mutex_unlock(&tunnel_mutex);
    (*env)->ReleaseStringUTFChars(env, config, path);
    return result;
}
JNIEXPORT void JNICALL Java_dev_graybridge_NativeTunnel_quit(JNIEnv *env, jclass cls) {
    (void)env; (void)cls;
    // Calling hev_socks5_tunnel_quit() a second time after SYNC_SEND clears in
    // hev_socks5_tunnel_fini() sets SYNC_STOP and aborts the next tunnel start.
    if (atomic_load(&tunnel_active) && !atomic_exchange(&tunnel_quit_sent, true)) {
        hev_socks5_tunnel_quit();
    }
}
JNIEXPORT jlongArray JNICALL Java_dev_graybridge_NativeTunnel_stats(JNIEnv *env, jclass cls) {
    (void)cls;
    size_t txp=0,txb=0,rxp=0,rxb=0;
    if (atomic_load(&tunnel_active)) {
        hev_socks5_tunnel_stats(&txp,&txb,&rxp,&rxb);
    }
    jlong values[4]={(jlong)txp,(jlong)txb,(jlong)rxp,(jlong)rxb};
    jlongArray result=(*env)->NewLongArray(env,4);
    if(result) (*env)->SetLongArrayRegion(env,result,0,4,values);
    return result;
}
