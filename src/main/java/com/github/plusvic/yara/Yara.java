package com.github.plusvic.yara;


public class Yara implements AutoCloseable {
    public YaraCompiler createCompiler() {
        return new YaraCompiler();
    }
  
    public void finalizeThread() {
    }

    @Override
    public void close() throws Exception {
    }
}
