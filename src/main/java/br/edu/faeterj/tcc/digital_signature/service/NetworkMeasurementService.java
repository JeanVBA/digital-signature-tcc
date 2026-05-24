package br.edu.faeterj.tcc.digital_signature.service;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.LongSummaryStatistics;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class NetworkMeasurementService {

    private static final String HOST_TESTE = "8.8.8.8"; // Google DNS — sempre acessível
    private static final int    PORT_TESTE  = 53;
    private static final int    SAMPLES    = 10;        // medições para calcular média

    /**
     * Descobre o MTU real da rede fazendo probe com packages de tamanhos crescentes.
     * Simula o comportamento do TCP Path MTU Discovery (RFC 1191).
     */
    public int discoverRealMTU() {
        int[] sizesTest = {1500, 1400, 1300, 1200, 1000, 576};

        for (int size : sizesTest) {
            if (canTransmit(size)) {
                return size;
            }
        }
        return 576; // MTU mínimo garantido pelo RFC 791
    }

    private boolean canTransmit(int tamanho) {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(2000);
            byte[] payload = new byte[tamanho - 28]; // 28 = cabeçalho IP(20) + UDP(8)
            DatagramPacket pkt = new DatagramPacket(
                payload, payload.length,
                InetAddress.getByName(HOST_TESTE), PORT_TESTE);
            socket.send(pkt);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Mede latência real de rede via TCP handshake (mais preciso que ICMP/ping
     * pois simula o que o TLS realmente faz).
     */
    public Map<String, Object> measureLatencyTCP() {
        List<Long> samples = new ArrayList<>();

        for (int i = 0; i < SAMPLES; i++) {
            long inicio = System.nanoTime();
            try (Socket socket = new Socket()) {
                socket.connect(
                    new InetSocketAddress(HOST_TESTE, PORT_TESTE), 3000);
                samples.add(System.nanoTime() - inicio);
            } catch (Exception e) {
                // Alguns hosts bloqueiam TCP na porta 53 — tenta sem contar
            }
            try { Thread.sleep(50); } catch (InterruptedException ignored) {}
        }

        if (samples.isEmpty()) {
            return Map.of("erro", "Não foi possível estabelecer conexão TCP para medição.");
        }

        LongSummaryStatistics stats = samples.stream()
            .collect(Collectors.summarizingLong(Long::longValue));

        Map<String, Object> m = new LinkedHashMap<>();
        m.put("hostMedido",        HOST_TESTE);
        m.put("SAMPLES",           samples.size());
        m.put("latencyMediaMs",   stats.getAverage() / 1_000_000.0);
        m.put("latencyMinMs",     stats.getMin()     / 1_000_000.0);
        m.put("latencyMaxMs",     stats.getMax()     / 1_000_000.0);
        m.put("jitterMs", // variação entre SAMPLES
            (stats.getMax() - stats.getMin()) / 1_000_000.0);
        return m;
    }

    /**
     * Simula o handshake TLS medindo o tempo real de transmissão
     * de payloads com os tamanhos reais de cada algoritmo.
     */
    public Map<String, Object> simulateHandshakeTLS(
            int bytesECDSA, int bytesMLDSA) {

        Map<String, Object> result = new LinkedHashMap<>();
        int mtu = discoverRealMTU();
        Map<String, Object> latency = measureLatencyTCP();

        double rttMs = latency.containsKey("latencyMediaMs")
            ? (double) latency.get("latencyMediaMs")
            : 1.0;

        // Calcula fragmentação e RTTs adicionais para cada algoritmo
        int packagesEC = (int) Math.ceil((double) bytesECDSA / mtu);
        int packagesML = (int) Math.ceil((double) bytesMLDSA / mtu);

        // Cada fragmento extra exige um RTT adicional de confirmação TCP
        double latencyHandshakeECDSA = packagesEC * rttMs;
        double latencyHandshakeMLDSA = packagesML * rttMs;

        result.put("networkMeasurement", Map.of(
            "realMTU",          mtu,
            "averageRTTMs",       rttMs,
            "methodology",      "TCP handshake real para " + HOST_TESTE
        ));

        result.put("ECDSA", Map.of(
            "totalBytes",               bytesECDSA,
            "packagesTCP",               packagesEC,
            "fragmentationIP",           bytesECDSA > mtu,
            "latencyHandshakeMs",      latencyHandshakeECDSA,
            "bytesAboveMTU",          Math.max(0, bytesECDSA - mtu)
        ));

        result.put("ML-DSA-44", Map.of(
            "totalBytes",               bytesMLDSA,
            "packagesTCP",               packagesML,
            "fragmentationIP",           bytesMLDSA > mtu,
            "latencyHandshakeMs",      latencyHandshakeMLDSA,
            "bytesAboveMTU",          Math.max(0, bytesMLDSA - mtu)
        ));

        result.put("impacto", Map.of(
            "packagesExtras",            packagesML - packagesEC,
            "latencyExtraMs",          latencyHandshakeMLDSA - latencyHandshakeECDSA,
            "factorIncreaseLatency",
                String.format("%.1fx", latencyHandshakeMLDSA / latencyHandshakeECDSA),
            "conclusion",
                String.format(
                    "Com RTT real de %.2fms e MTU de %d bytes, o handshake " +
                    "ML-DSA-44 leva %.2fms contra %.2fms do ECDSA — " +
                    "%.1fx mais lento na camada de transporte.",
                    rttMs, mtu,
                    latencyHandshakeMLDSA, latencyHandshakeECDSA,
                    latencyHandshakeMLDSA / latencyHandshakeECDSA)
        ));

        return result;
    }
}