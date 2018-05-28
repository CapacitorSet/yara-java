package com.github.plusvic.yara;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Map;

import static com.github.plusvic.yara.Preconditions.checkArgument;


public class YaraScanner {
    private YaraExecutable yara;
    private YaraScanCallback callback;

    public YaraScanner(Path rules) {
        checkArgument(rules != null);
        this.yara = new YaraExecutable();
        this.yara.addRule(rules);
    }

    public void setTimeout(int timeout) {
        this.yara.setTimeout(timeout);
    }

    public void setMaxRules(int count) {
        yara.setMaxRules(count);
    }

    public void setNotSatisfiedOnly(boolean value) {
        yara.setNegate(value);
    }

    public void setCallback(YaraScanCallback cbk) {
        checkArgument(cbk != null);
        this.callback = cbk;
    }

    public void scan(File file) {
        scan(file, null);
    }

    public void scan(File file, Map<String, String> moduleArgs) {
        scan(file, moduleArgs, this.callback);
    }
    public void scan(File file, Map<String, String> moduleArgs, YaraScanCallback yaraScanCallback) {
        checkArgument(file != null);

        if (!file.exists()) {
            throw new YaraException(ErrorCode.COULD_NOT_OPEN_FILE.getValue());
        }

        try {
            yara.match(file.toPath(), moduleArgs, yaraScanCallback);
        } catch (Exception e) {
            throw new YaraException(e.getMessage());
        }

    }

    public void scan(byte[] buffer) throws IOException, InterruptedException {
        scan(buffer, null);
    }

    public void scan(byte[] buffer, Map<String, String> moduleArgs) throws IOException, InterruptedException {
        scan(buffer, moduleArgs, this.callback);
    }

    public void scan(byte[] buffer, Map<String, String> moduleArgs, YaraScanCallback yaraScanCallback) throws IOException, InterruptedException {
        checkArgument(buffer != null);

        yara.match(buffer, moduleArgs, yaraScanCallback);
    }

    public void close() throws Exception {
    }

    public void finalizeThread() {
    }
}
