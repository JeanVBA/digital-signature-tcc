package br.edu.faeterj.tcc.digital_signature.controller;

import java.math.BigInteger;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import br.edu.faeterj.tcc.digital_signature.domain.DTO.CalculationReportDTO;
import br.edu.faeterj.tcc.digital_signature.domain.Utils.Polynomial;
import br.edu.faeterj.tcc.digital_signature.service.AlgorithmCalculatedService;

@RestController
@RequestMapping("/api/calculation-reports")
public class CalculationReportController {
    
    @Autowired
    private AlgorithmCalculatedService service;

    @GetMapping("/ecdsa/simulated-signature")
    public ResponseEntity<CalculationReportDTO> simulatedSignatureEcdsa() {
        // Mockando valores de entrada (normalmente viriam no RequestBody)
        BigInteger dPrivate = new BigInteger("12345"); // Chave privada
        BigInteger kRandon = new BigInteger("67890"); // Nonce
        BigInteger eHash = new BigInteger("99999"); // Hash da mensagem

        CalculationReportDTO report = service.calculatedSignatureECDSA(dPrivate, kRandon, eHash);
        
        return ResponseEntity.ok(report);
    }

    // Endpoint para testar o passo a passo do ML-DSA
    @GetMapping("/mldsa/simulated-public-key")
    public ResponseEntity<CalculationReportDTO> simulatedPublicKeyMlDsa() {
        // Como o ML-DSA lida com matrizes complexas, estamos instanciando 
        // matrizes de tamanho k=4, l=4 (parâmetros do ML-DSA-44 real)
        int k = 4, l = 4;
        Polynomial[][] A = new Polynomial[k][l];
        Polynomial[] s1 = new Polynomial[l];
        Polynomial[] s2 = new Polynomial[k];

        // Inicializando os arrays com instâncias vazias
        for(int i=0; i<k; i++) {
            s2[i] = new Polynomial();
            for(int j=0; j<l; j++) {
                A[i][j] = new Polynomial();
                if(i == 0) s1[j] = new Polynomial();
            }
        }

        CalculationReportDTO report = service.calculatedPublicKeyMLDSA(A, s1, s2, k, l);
        return ResponseEntity.ok(report);
    }
}
