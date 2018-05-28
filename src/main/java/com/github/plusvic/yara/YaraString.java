package com.github.plusvic.yara;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import static com.github.plusvic.yara.Preconditions.checkArgument;

public class YaraString {
    private String identifier;
    private List<YaraMatch> matches = new ArrayList<>();

    public YaraString(String identifier) {
        checkArgument(!Utils.isNullOrEmpty(identifier));
        this.identifier = identifier;
    }

    public void addMatch(long offset, String value) {
        this.matches.add(new YaraMatch(offset, value));
    }

    public String getIdentifier() {
        return identifier;
    }

    public Iterator<YaraMatch> getMatches() {
        return matches.iterator();
    }
}
