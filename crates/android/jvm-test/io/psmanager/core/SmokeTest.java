package io.psmanager.core;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Exercises every native method once, with values from spec/vectors-v1.json. */
public final class SmokeTest {
    private static int failures = 0;

    private static void check(String what, Object expected, Object actual) {
        if (!expected.equals(actual)) {
            failures++;
            System.out.println("FAIL " + what + ": expected " + expected + ", got " + actual);
        }
    }

    private static void expectInvalid(String what, Runnable call) {
        try {
            call.run();
            failures++;
            System.out.println("FAIL " + what + ": no exception");
        } catch (IllegalArgumentException e) {
            System.out.println("ok   " + what + " -> " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        byte[] secret = "correct horse battery staple".getBytes(StandardCharsets.UTF_8);
        byte[] key = PsmNative.deriveRootKey("Test User", secret);
        Arrays.fill(secret, (byte) 0);

        check("fingerprint", "FZHC", PsmNative.fingerprint(key));
        check("default", "=0tL!yWs0M2$LJTag7W?H%G9",
                PsmNative.generate(key, "github.com", "", 1, "standard", 0));
        check("rotated account", "oF*mdnl3C37KNcqv@%=5U8sQ",
                PsmNative.generate(key, "GitHub.com", "Alice@Example.com", 2, "standard", 24));
        check("pin", "7829", PsmNative.generate(key, "github.com", "", 1, "pin", 4));
        check("max generation", "NSS3vGK7g4x8p?uUcZbwKj?K",
                PsmNative.generate(key, "github.com", "", 4294967295L, "standard", 0));

        byte[] unicodeKey = PsmNative.deriveRootKey(
                "  Jane   DOE\u00A0", "\u00E4\u00F6\u00FC \u20AC100 \u2713".getBytes(StandardCharsets.UTF_8));
        check("unicode fingerprint", "2CK2", PsmNative.fingerprint(unicodeKey));
        check("unicode site", "8m1SP*uoqd-w_ICI1vyeGvT&",
                PsmNative.generate(unicodeKey, "WWW.\u00C5\u00D8.EXAMPLE", "", 1, "standard", 0));

        check("normalizeSite", "github.com", PsmNative.normalizeSite("https://www.GitHub.com/login"));
        check("normalizeText", "jane doe", PsmNative.normalizeText("  Jane   DOE\u00A0"));
        check("selftest", 6, PsmNative.selftest());

        expectInvalid("empty site", () -> PsmNative.generate(key, "https://", "", 1, "standard", 0));
        expectInvalid("generation 0", () -> PsmNative.generate(key, "a.com", "", 0, "standard", 0));
        expectInvalid("generation too big", () -> PsmNative.generate(key, "a.com", "", 1L << 32, "standard", 0));
        expectInvalid("unknown profile", () -> PsmNative.generate(key, "a.com", "", 1, "strong", 0));
        expectInvalid("length too short", () -> PsmNative.generate(key, "a.com", "", 1, "standard", 7));
        expectInvalid("negative length", () -> PsmNative.generate(key, "a.com", "", 1, "standard", -1));
        expectInvalid("short key", () -> PsmNative.fingerprint(new byte[16]));
        expectInvalid("empty secret", () -> PsmNative.deriveRootKey("me", new byte[0]));
        expectInvalid("bad UTF-8", () -> PsmNative.deriveRootKey("me", new byte[] {(byte) 0xff}));

        if (failures > 0) {
            System.out.println(failures + " FAILURES");
            System.exit(1);
        }
        System.out.println("JNI bridge: all checks passed");
    }
}
