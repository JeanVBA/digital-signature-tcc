package br.edu.faeterj.tcc.digital_signature.controller;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import br.edu.faeterj.tcc.digital_signature.domain.SignatureEntity;
import br.edu.faeterj.tcc.digital_signature.service.CryptoSignatureService;
import br.edu.faeterj.tcc.digital_signature.service.NetworkMeasurementService;
import br.edu.faeterj.tcc.digital_signature.service.TlsOverheadService;
import io.swagger.v3.oas.annotations.Operation;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/metrics")
@RequiredArgsConstructor
public class TlsOverheadController {

    @Autowired
    private TlsOverheadService overheadService;

    @Autowired
    private CryptoSignatureService cryptoService;

    @Autowired
    private NetworkMeasurementService networkService;

    // Visão geral — médias de todos os documentos do banco
    @GetMapping("/overhead-tls")
    public ResponseEntity<Map<String, Object>> metricsAll() {
        return ResponseEntity.ok(overheadService.calculatedRealMetrics());
    }

    // Detalhe por documento específico
    @GetMapping("/overhead-tls/document/{id}")
    public ResponseEntity<Map<String, Object>> metricsByDocument(
            @PathVariable Long id) {
        return ResponseEntity.ok(
                overheadService.calculatedMetricsByDocument(id));
    }

    // Ranking dos documentos com maior overhead
    @GetMapping("/overhead-tls/ranking")
    public ResponseEntity<List<Map<String, Object>>> rankingOverhead() {
        return ResponseEntity.ok(
                overheadService.rankingOverheadByDocument());
    }

    @GetMapping(value = "/overhead-tls/grafics", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> generatedGrafics() {
        Map<String, Object> data = overheadService.calculatedRealMetrics();
        String html = overheadService.generatedHtmlGrafics(data);
        return ResponseEntity.ok(html);
    }

    @GetMapping("/network-conditions")
    @Operation(summary = "Mede MTU real e latência TCP da rede atual")
    public ResponseEntity<Map<String, Object>> networkConditions() {
        int mtu = networkService.discoverRealMTU();
        Map<String, Object> latencia = networkService.measureLatencyTCP();

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("mtuReal", mtu);
        response.put("latenciaTCP", latencia);
        response.put("interpretacao", Map.of(
                "ECDSA_fragmenta", 163 > mtu,
                "MLDSA_fragmenta", 3754 > mtu,
                "nota", String.format(
                        "Com MTU de %d bytes, ECDSA (%d bytes) %s e ML-DSA-44 (%d bytes) %s.",
                        mtu, 163,
                        163 > mtu ? "fragmenta" : "não fragmenta",
                        3754,
                        3754 > mtu ? "fragmenta" : "não fragmenta")));
        return ResponseEntity.ok(response);
    }

    // Simulação do handshake TLS com medições reais
    @GetMapping("/simulate-tls-handshake")
    @Operation(summary = "Simula handshake TLS com tamanhos reais do banco e latência medida")
    public ResponseEntity<Map<String, Object>> simulateHandshake() {
        List<SignatureEntity> todas = cryptoService.findAll();

        // Pega tamanhos reais do banco
        int bytesEC = todas.stream()
                .filter(s -> "ECDSA".equals(s.getTypeAlgorithm()))
                .mapToInt(s -> s.getPublicKeyBytes().length + s.getSignatureBytes().length)
                .max().orElse(163);

        int bytesML = todas.stream()
                .filter(s -> "ML-DSA-44".equals(s.getTypeAlgorithm()))
                .mapToInt(s -> s.getPublicKeyBytes().length + s.getSignatureBytes().length)
                .max().orElse(3754);

        return ResponseEntity.ok(
                networkService.simulateHandshakeTLS(bytesEC, bytesML));
    }
}
