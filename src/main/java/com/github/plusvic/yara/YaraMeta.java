package com.github.plusvic.yara;

import static com.github.plusvic.yara.Preconditions.checkArgument;

public class YaraMeta {
    private String identifier;
    private Type type;
    private String string;
    private int integer;

    public YaraMeta(String identifier, String value) {
        checkArgument(!Utils.isNullOrEmpty(identifier));
        this.identifier = identifier;
        this.type = Type.STRING;
        this.string = value;
    }

    public YaraMeta(String identifier, int value) {
        checkArgument(!Utils.isNullOrEmpty(identifier));
        this.identifier = identifier;
        this.type = Type.INTEGER;
        this.integer = value;
    }

    public YaraMeta(String identifier, boolean value) {
        checkArgument(!Utils.isNullOrEmpty(identifier));
        this.identifier = identifier;
        this.type = Type.BOOLEAN;
        this.integer = value ? 1 : 0;
    }

    public Type getType() {
        return type;
    }

    public String getIndentifier() {
        return identifier;
    }

    public String getString() {
        return string;
    }

    public int getInteger() {
        return integer;
    }

    public enum Type {
        NULL(0),
        INTEGER(1),
        STRING(2),
        BOOLEAN(3);

        private int value;

        Type(int value) {
            this.value = value;
        }

        public static Type from(int value) {
            for (Type t : YaraMeta.Type.values()) {
                if (t.value == value) {
                    return t;
                }
            }

            throw new IllegalArgumentException();
        }
    }
}
