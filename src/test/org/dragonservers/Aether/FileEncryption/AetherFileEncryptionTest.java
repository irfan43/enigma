package org.dragonservers.Aether.FileEncryption;


import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

class AetherFileEncryptionTest {

    @Test
    void checkEncryption() throws IOException, GeneralSecurityException {
        List<Path> testDir = new ArrayList<>();
        testDir.add(Path.of("Papers"));
        testDir.add(Path.of("CS553"));
    }

}