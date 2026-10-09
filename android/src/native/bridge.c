#include <jni.h>
#include <unistd.h>
#include <hev-socks5-tunnel.h>

JNIEXPORT jint JNICALL Java_dev_graybridge_NativeTunnel_run(JNIEnv *env, jclass cls, jstring config, jint fd) {
    (void)cls;
    const char *path = (*env)->GetStringUTFChars(env, config, 0);
    if (!path) return -1;
    // The service retains ownership of the ParcelFileDescriptor.
    int owned_fd = dup(fd);
    int result = owned_fd < 0 ? -1 : hev_socks5_tunnel_main_from_file(path, owned_fd);
    if (owned_fd >= 0) close(owned_fd);
    (*env)->ReleaseStringUTFChars(env, config, path);
    return result;
}
JNIEXPORT void JNICALL Java_dev_graybridge_NativeTunnel_quit(JNIEnv *env, jclass cls) {
    (void)env; (void)cls;
    hev_socks5_tunnel_quit();
}
JNIEXPORT jlongArray JNICALL Java_dev_graybridge_NativeTunnel_stats(JNIEnv *env, jclass cls) {
    (void)cls;
    size_t txp=0,txb=0,rxp=0,rxb=0;
    hev_socks5_tunnel_stats(&txp,&txb,&rxp,&rxb);
    jlong values[4]={(jlong)txp,(jlong)txb,(jlong)rxp,(jlong)rxb};
    jlongArray result=(*env)->NewLongArray(env,4);
    if(result) (*env)->SetLongArrayRegion(env,result,0,4,values);
    return result;
}
