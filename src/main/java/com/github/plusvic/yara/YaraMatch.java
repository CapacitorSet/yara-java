package com.github.plusvic.yara;


public class YaraMatch {
    private String value;
    private long offset;

    public YaraMatch(long offset, String value) {
        this.offset = offset;
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public long getOffset() {
        return offset;
    }
}
