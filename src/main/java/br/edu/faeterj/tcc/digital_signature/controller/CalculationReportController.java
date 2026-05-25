package br.edu.faeterj.tcc.digital_signature.controller;

import java.math.BigInteger;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import br.edu.faeterj.tcc.digital_signature.domain.Utils.Polynomial;
import br.edu.faeterj.tcc.digital_signature.service.AlgorithmCalculatedService;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/calculation-reports")
@RequiredArgsConstructor
public class CalculationReportController {
    
    private final AlgorithmCalculatedService service;

    @GetMapping(value = "/ecdsa/simulated-signature", produces = "text/html;charset=UTF-8")
    public String simulatedSignatureEcdsa() {
        // Mockando valores de entrada (normalmente viriam no RequestBody)
        BigInteger dPrivate = new BigInteger("12345"); // Chave privada
        BigInteger kRandon = new BigInteger("67890");  // Nonce
        BigInteger eHash = new BigInteger("99999");    // Hash da mensagem

        return service.calculatedSignatureECDSA(dPrivate, kRandon, eHash);
    }

    // Adicionado o produces aqui também para garantir a acentuação e renderização
    @GetMapping(value = "/mldsa/simulated-public-key", produces = "text/html;charset=UTF-8")
    public String simulatedPublicKeyMlDsa() {
        int k = 2, l = 2; // Reduzi para 2x2 apenas para o relatório não ficar gigantesco na tela
        Polynomial[][] A = new Polynomial[k][l];
        Polynomial[] s1 = new Polynomial[l];
        Polynomial[] s2 = new Polynomial[k];

        // 1. Mockando o vetor secreto s1 (coeficientes pequenos, ex: 1, 0, -1)
        s1[0] = new Polynomial(1, -1, 0, 1);  // x^3 - x^2 + 1
        s1[1] = new Polynomial(0, 1, -1, 0);  // x^2 - x

        // 2. Mockando o vetor de erro s2 (valores pequenos)
        s2[0] = new Polynomial(1, 0, 1, -1);  // x^3 + x - 1
        s2[1] = new Polynomial(-1, 1, 0, 0);  // -x^3 + x^2

        // 3. Mockando a matriz pública A (valores maiores)
        A[0][0] = new Polynomial(5, -2, 3, 1);
        A[0][1] = new Polynomial(2, 4, -1, 0);
        A[1][0] = new Polynomial(-3, 1, 5, -2);
        A[1][1] = new Polynomial(1, 0, 2, 4);

        // O serviço vai multiplicar A * s1 e somar s2
        return service.calculatedPublicKeyMLDSA(A, s1, s2, k, l);
    }
}