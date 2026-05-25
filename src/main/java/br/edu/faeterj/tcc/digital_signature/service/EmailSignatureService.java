package br.edu.faeterj.tcc.digital_signature.service;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.core.io.ByteArrayResource;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import br.edu.faeterj.tcc.digital_signature.domain.DocumentEntity;
import br.edu.faeterj.tcc.digital_signature.domain.SignatureEntity;
import br.edu.faeterj.tcc.digital_signature.repository.SignatureRepository;
import jakarta.mail.internet.MimeMessage;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class EmailSignatureService {

    private final JavaMailSender        mailSender;
    private final SignatureRepository   signatureRepository;
    private final NetworkMetricsService networkMetrics;

    public Map<String, Object> enviarDocumentoAssinado(
            Long signatureId, String receiver) throws Exception {

        SignatureEntity sig = signatureRepository.findById(signatureId)
            .orElseThrow(() -> new EntityNotFoundException(
                "Assinatura não encontrada: " + signatureId));

        DocumentEntity doc   = sig.getDocument();
        String         alg   = sig.getTypeAlgorithm();

        // Métricas de rede antes do envio
        Map<String, Object> metricas = networkMetrics.measureRealTransmission(
            doc.getContent(),
            sig.getSignatureBytes(),
            sig.getPublicKeyBytes());

        // Monta o email
        MimeMessage    message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

        helper.setTo(receiver);
        helper.setSubject("[PQC-TCC] Documento assinado com " + alg);
        helper.setText(montarCorpo(sig), true);

        // Anexo 1 — documento original
        helper.addAttachment(
            doc.getName(),
            new ByteArrayResource(doc.getContent()),
            doc.getType());

        // Anexo 2 — certificado de assinatura em JSON
        String certificado = montarCertificado(sig);
        helper.addAttachment(
            "certificado-" + alg + ".json",
            new ByteArrayResource(certificado.getBytes(StandardCharsets.UTF_8)),
            "application/json");

        // Mede tempo real de transmissão SMTP
        // ← Wireshark captura exatamente esse tráfego
        long inicio = System.nanoTime();
        mailSender.send(message);
        double tempoEnvioMs = (System.nanoTime() - inicio) / 1_000_000.0;

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("emailEnviado",          true);
        response.put("destinatario",          receiver);
        response.put("algoritmo",             alg);
        response.put("tempoEnvioSMTPms",      tempoEnvioMs);
        response.put("metricasRede",          metricas);
        response.put("wiresharkInstrucao", Map.of(
            "filtroCaptura",  "tcp port 587",
            "filtroExibicao", "tcp.port == 587",
            "oQueObservar",
                alg.equals("ML-DSA-44")
                    ? "Observe 3 frames TCP para o Client Key Exchange — fragmentação confirmada"
                    : "Observe 1 frame TCP para o Client Key Exchange — sem fragmentação"
        ));
        return response;
    }

    private String montarCertificado(SignatureEntity sig) {
        return String.format("""
            {
              "signatureId": %d,
              "algoritmo": "%s",
              "dataAssinatura": "%s",
              "documentoNome": "%s",
              "chavePublicaBase64": "%s",
              "assinaturaBase64": "%s",
              "valida": %b,
              "chavePublicaBytes": %d,
              "assinaturaBytes": %d
            }""",
            sig.getId(),
            sig.getTypeAlgorithm(),
            sig.getSignatureDate(),
            sig.getDocument().getName(),
            Base64.getEncoder().encodeToString(sig.getPublicKeyBytes()),
            Base64.getEncoder().encodeToString(sig.getSignatureBytes()),
            sig.isValid(),
            sig.getPublicKeyBytes().length,
            sig.getSignatureBytes().length);
    }

    private String montarCorpo(SignatureEntity sig) {
        return String.format("""
            <h2>Documento assinado digitalmente</h2>
            <table border="1" cellpadding="8">
              <tr><td><strong>Algoritmo</strong></td><td>%s</td></tr>
              <tr><td><strong>Data da assinatura</strong></td><td>%s</td></tr>
              <tr><td><strong>Chave pública</strong></td><td>%d bytes</td></tr>
              <tr><td><strong>Assinatura</strong></td><td>%d bytes</td></tr>
              <tr><td><strong>Assinatura válida</strong></td><td>%b</td></tr>
            </table>
            <p><em>TCC — Criptografia Pós-Quântica — FAETERJ</em></p>
            """,
            sig.getTypeAlgorithm(),
            sig.getSignatureDate(),
            sig.getPublicKeyBytes().length,
            sig.getSignatureBytes().length,
            sig.isValid());
    }
}