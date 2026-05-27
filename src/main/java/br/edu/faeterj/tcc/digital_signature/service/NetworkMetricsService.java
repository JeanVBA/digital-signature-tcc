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

        int base64Doc    = (int) Math.ceil(documentBytes.length    * 4.0 / 3);
        int base64Sig    = (int) Math.ceil(signatureBytes.length   * 4.0 / 3);
        int base64Key    = (int) Math.ceil(publicKeyBytes.length   * 4.0 / 3);
        int totalPayload = base64Doc + base64Sig + base64Key;
        int totalOriginal= documentBytes.length + signatureBytes.length
                         + publicKeyBytes.length;

        // Usa smtp.gmail.com:587 — confirmado aberto no seu ambiente
        double rttMs = measureRTT("smtp.gmail.com", 587);
        boolean fallback = rttMs <= 0;
        if (fallback) rttMs = 20.0; // fallback realista documentado

        int mssEffective = 1460;
        int packageTCP = (int) Math.ceil((double) totalPayload / mssEffective);

        Map<String, Object> m = new LinkedHashMap<>();
        m.put("SizeDocumentBytes",    documentBytes.length);
        m.put("SizeSignatureBytes",   signatureBytes.length);
        m.put("SizePublicKeyBytes",   publicKeyBytes.length);
        m.put("totalOriginalBytes",      totalOriginal);
        m.put("totalBase64EmailBytes",   totalPayload);
        m.put("overheadBase64Percentage",
            String.format("%.1f%%",
                (totalPayload - totalOriginal) * 100.0 / totalOriginal));
        m.put("rttSMTPms",             rttMs);
        m.put("rttFallback",           fallback);
        m.put("mssEffective",            mssEffective);
        m.put("estimatedPackagesTCP",   packageTCP);
        m.put("EstimatedLatencyMs",    packageTCP * rttMs);
        m.put("wiresharkFiltro",       "tcp.port == 587");
        return m;
    }

    private double measureRTT(String host, int porta) {
        List<Double> amostras = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            long inicio = System.nanoTime();
            try (Socket s = new Socket()) {
                s.connect(new InetSocketAddress(host, porta), 3000);
                double rtt = (System.nanoTime() - inicio) / 1_000_000.0;
                if (rtt >= 0.1 && rtt < 5000) amostras.add(rtt);
            } catch (Exception ignored) {}
            try { Thread.sleep(100); } catch (InterruptedException ignored) {}
        }

        if (amostras.isEmpty()) return -1;

        // Remove maior e menor outlier
        if (amostras.size() > 3) {
            amostras.sort(Double::compareTo);
            amostras = amostras.subList(1, amostras.size() - 1);
        }

        return amostras.stream().mapToDouble(Double::doubleValue).average().orElse(-1);
    }
}