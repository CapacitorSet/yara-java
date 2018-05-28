package com.github.plusvic.yara;


import java.util.*;

import static com.github.plusvic.yara.Preconditions.checkArgument;

public class YaraRule {
    private String identifier;
    private List<String> tags = new ArrayList<>();
    private List<YaraMeta> metas = new ArrayList<>();
    private List<YaraString> strings = new ArrayList<>();

    public YaraRule(String identifier) {
        checkArgument(!Utils.isNullOrEmpty(identifier));

        this.identifier = identifier;
    }

    public void addTag(String tag) {
        this.tags.add(tag);
    }

    public void addMeta(YaraMeta meta) {
        this.metas.add(meta);
    }

    public void addString(YaraString string) {
        this.strings.add(string);
    }

    public String getIdentifier() {
        return identifier;
    }

    public Iterator<String> getTags() {
        return tags.iterator();
    }

    public Iterator<YaraMeta> getMetadata() {
        return metas.iterator();
    }

    public Iterator<YaraString> getStrings() {
        return strings.iterator();
    }
}
