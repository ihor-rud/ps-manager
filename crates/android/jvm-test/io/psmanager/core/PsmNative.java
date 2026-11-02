package io.psmanager.core;

/** Desktop-JVM twin of the Android app's PsmNative object; same JNI symbols. */
public final class PsmNative {
    static {
        System.loadLibrary("psm_android");
    }

    private PsmNative() {}

    public static native byte[] deriveRootKey(String identity, byte[] secret);

    public static native String fingerprint(byte[] rootKey);

    public static native String generate(
            byte[] rootKey, String site, String account, long generation, String profile, int length);

    public static native String normalizeSite(String site);

    public static native String normalizeText(String text);

    public static native int selftest();
}
