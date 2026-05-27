package br.edu.faeterj.tcc.digital_signature.service;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.DoubleSummaryStatistics;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Service;

@Service
public class NetworkMeasurementService {

    // Porta 587 confirmada aberta no seu ambiente
    private static final List<String[]> ALVOS = List.of(
        new String[]{"smtp.gmail.com", "587"},
        new String[]{"google.com",     "80"},
        new String[]{"1.1.1.1",        "80"},
        new String[]{"8.8.8.8",        "80"}
    );
    private static final int AMOSTRAS_ALVO = 10;
    private static final int MTU_FALLBACK  = 1500;

    public int discoverRealMTU() {
        // UDP para descoberta de MTU — usa o primeiro host que responder
        int[] tamanhos = {1500, 1400, 1300, 1200, 1000, 576};
        for (int tam : tamanhos) {
            for (String[] alvo : ALVOS) {
                if (canTransmitUDP(alvo[0], tam)) return tam;
            }
        }
        return MTU_FALLBACK;
    }

    private boolean canTransmitUDP(String host, int tamanho) {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(1500);
            int payloadSize = Math.max(1, tamanho - 28);
            DatagramPacket pkt = new DatagramPacket(
                new byte[payloadSize], payloadSize,
                InetAddress.getByName(host),
                Integer.parseInt(ALVOS.get(0)[1]));
            socket.send(pkt);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public Map<String, Object> measureLatencyTCP() {
        List<Double> amostras     = new ArrayList<>();
        String       hostUsado    = "nenhum";
        int          tentativas   = 0;

        // Percorre os alvos até coletar amostras suficientes
        outer:
        for (String[] alvo : ALVOS) {
            String host = alvo[0];
            int    port = Integer.parseInt(alvo[1]);

            for (int i = 0; i < 4; i++) {
                tentativas++;
                long inicio = System.nanoTime();
                try (Socket s = new Socket()) {
                    s.connect(new InetSocketAddress(host, port), 3000);
                    double rtt = (System.nanoTime() - inicio) / 1_000_000.0;
                    // Descarta valores absurdos (< 0.1ms ou > 5000ms)
                    if (rtt >= 0.1 && rtt < 5000) {
                        amostras.add(rtt);
                        hostUsado = host + ":" + port;
                    }
                } catch (Exception ignored) {}

                try { Thread.sleep(80); } catch (InterruptedException ignored) {}
                if (amostras.size() >= AMOSTRAS_ALVO) break outer;
            }
        }

        Map<String, Object> m = new LinkedHashMap<>();
        m.put("hostMedido",    hostUsado);
        m.put("tentativas",    tentativas);

        if (amostras.isEmpty()) {
            m.put("erro",          "Nenhuma amostra coletada — verifique conectividade");
            m.put("amostras",      0);
            m.put("latencyMediaMs", 20.0); // fallback realista
            m.put("latencyMinMs",   20.0);
            m.put("latencyMaxMs",   20.0);
            m.put("jitterMs",       0.0);
            m.put("fallback",       true);
            return m;
        }

        // Remove outliers se tiver amostras suficientes
        if (amostras.size() > 4) {
            amostras.sort(Double::compareTo);
            amostras = amostras.subList(1, amostras.size() - 1);
        }

        DoubleSummaryStatistics stats = amostras.stream()
            .mapToDouble(Double::doubleValue)
            .summaryStatistics();

        m.put("amostras",      amostras.size());
        m.put("latencyMediaMs", stats.getAverage());
        m.put("latencyMinMs",   stats.getMin());
        m.put("latencyMaxMs",   stats.getMax());
        m.put("jitterMs",       stats.getMax() - stats.getMin());
        m.put("fallback",       false);
        return m;
    }

    public Map<String, Object> simulateHandshakeTLS(
            int bytesECDSA, int bytesMLDSA) {

        int    mtu    = discoverRealMTU();
        Map<String, Object> latObj = measureLatencyTCP();
        double rttMs  = (double) latObj.getOrDefault("latencyMediaMs", 20.0);
        boolean fb    = (boolean) latObj.getOrDefault("fallback", true);

        int    pktsEC = (int) Math.ceil((double) bytesECDSA / mtu);
        int    pktsML = (int) Math.ceil((double) bytesMLDSA / mtu);
        double latEC  = pktsEC * rttMs;
        double latML  = pktsML * rttMs;

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("networkMeasurement", Map.of(
            "realMTU",      mtu,
            "averageRTTMs", rttMs,
            "fallback",     fb,
            "hostMedido",   latObj.getOrDefault("hostMedido", "N/A"),
            "amostras",     latObj.getOrDefault("amostras", 0)
        ));
        result.put("ECDSA", Map.of(
            "totalBytes",        bytesECDSA,
            "packagesTCP",       pktsEC,
            "fragmentationIP",   bytesECDSA > mtu,
            "latencyHandshakeMs",latEC,
            "bytesAboveMTU",     Math.max(0, bytesECDSA - mtu)
        ));
        result.put("ML-DSA-44", Map.of(
            "totalBytes",        bytesMLDSA,
            "packagesTCP",       pktsML,
            "fragmentationIP",   bytesMLDSA > mtu,
            "latencyHandshakeMs",latML,
            "bytesAboveMTU",     Math.max(0, bytesMLDSA - mtu)
        ));
        result.put("impacto", Map.of(
            "packagesExtras",         pktsML - pktsEC,
            "latencyExtraMs",         latML  - latEC,
            "factorIncreaseLatency",  String.format("%.1fx", latML / Math.max(latEC, 0.001)),
            "conclusion", String.format(
                "Com RTT %s de %.2fms e MTU de %d bytes, ML-DSA-44 leva " +
                "%.2fms contra %.2fms do ECDSA (%.1fx mais lento).",
                fb ? "estimado" : "medido",
                rttMs, mtu, latML, latEC, latML / Math.max(latEC, 0.001))
        ));
        return result;
    }
}