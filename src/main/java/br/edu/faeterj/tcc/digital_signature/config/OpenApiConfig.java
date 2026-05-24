package br.edu.faeterj.tcc.digital_signature.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI digitalSignatureOpenApi() {
        return new OpenAPI()
                .info(new Info()
                        .title("Digital Signature API")
                        .description("API para assinatura digital e métricas de overhead de algoritmos de assinatura.")
                        .version("1.0.0")
                        .contact(new Contact().name("FAETERJ TCC").email("noreply@example.com"))
                        .license(new License().name("MIT")));
    }
}
