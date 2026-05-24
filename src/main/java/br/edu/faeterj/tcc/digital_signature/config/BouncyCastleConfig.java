package br.edu.faeterj.tcc.digital_signature.config;

import java.security.Provider;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class BouncyCastleConfig {

    public static final String PROVIDER      = "BC";
    public static final String ALGORITHM_MLDSA = "ML-DSA";
    public static final String ALGORITHM_ECDSA = "SHA256withECDSA";

    @Bean
    public Provider bouncyCastleProvider() {
        Provider bc = new BouncyCastleProvider();
        if (Security.getProvider(bc.getName()) == null) {
            Security.addProvider(bc);
        }
        return bc;
    }
}