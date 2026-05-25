package br.edu.faeterj.tcc.digital_signature.service;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Service;

@Service
public class NetworkMetricsService {

    public Map<String, Object> measureRealTransmission(
            byte[] documentBytes,
            byte[] signatureBytes,
            byte[] publicKeyBytes) throws Exception {

        // Base64 aumenta o tamanho em ~33% — é como o MIME envia anexos
        int base64Doc = (int) Math.ceil(documentBytes.length    * 4.0 / 3);
        int base64Sig = (int) Math.ceil(signatureBytes.length   * 4.0 / 3);
        int base64Key = (int) Math.ceil(publicKeyBytes.length * 4.0 / 3);
        int totalPayload = base64Doc + base64Sig + base64Key;

        int tamanhoOriginal = documentBytes.length
            + signatureBytes.length
            + publicKeyBytes.length;

        // RTT real para o servidor SMTP via TCP handshake
        double rttMs = measureRTT("smtp.gmail.com", 587);

        int mssEfetivo = 1460; // MTU(1500) - IP(20) - TCP(20)
        int pacotesTCP = (int) Math.ceil((double) totalPayload / mssEfetivo);

        Map<String, Object> m = new LinkedHashMap<>();
        m.put("tamanhoDocumentBytes",      documentBytes.length);
        m.put("tamanhoSignatureBytes",     signatureBytes.length);
        m.put("tamanhoChavePublicaBytes",   publicKeyBytes.length);
        m.put("totalOriginalBytes",         tamanhoOriginal);
        m.put("totalBase64EmailBytes",      totalPayload);
        m.put("overheadBase64Percentual",
            String.format("%.1f%%",
                (totalPayload - tamanhoOriginal) * 100.0 / tamanhoOriginal));
        m.put("rttSMTPms",                  rttMs);
        m.put("mssEfetivo",                 mssEfetivo);
        m.put("pacotesTCPEstimados",        pacotesTCP);
        m.put("latenciaEstimadaMs",         pacotesTCP * rttMs);
        m.put("wiresharkFiltro",            "tcp.port == 587");
        return m;
    }

    private double measureRTT(String host, int porta) {
        List<Double> amostras = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            long inicio = System.nanoTime();
            try (Socket s = new Socket()) {
                s.connect(new InetSocketAddress(host, porta), 3000);
                amostras.add((System.nanoTime() - inicio) / 1_000_000.0);
            } catch (Exception ignored) {}
            try { Thread.sleep(100); } catch (InterruptedException ignored) {}
        }
        return amostras.stream()
            .mapToDouble(Double::doubleValue)
            .average()
            .orElse(0.0);
    }
}
