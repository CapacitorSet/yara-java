package com.github.plusvic.yara;

/**
 * Yara factory
 */
public class YaraFactory {
    public enum Mode {
        EMBEDDED,
        EXTERNAL
    }

    public static Yara create(Mode mode) {
        switch (mode) {
            case EXTERNAL:
                return new Yara();
            default:
                throw new UnsupportedOperationException();
        }
    }
}
