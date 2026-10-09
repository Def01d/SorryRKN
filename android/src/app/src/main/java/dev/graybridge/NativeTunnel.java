package dev.graybridge;

final class NativeTunnel {
    static { System.loadLibrary("graybridge"); }
    static native int run(String config, int fd);
    static native void quit();
    static native long[] stats();
}
