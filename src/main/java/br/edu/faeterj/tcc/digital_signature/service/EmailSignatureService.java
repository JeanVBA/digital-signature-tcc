package br.edu.faeterj.tcc.digital_signature.service;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.core.io.ByteArrayResource;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import br.edu.faeterj.tcc.digital_signature.domain.DocumentEntity;
import br.edu.faeterj.tcc.digital_signature.domain.SignatureEntity;
import br.edu.faeterj.tcc.digital_signature.repository.DocumentRepository;
import jakarta.mail.internet.MimeMessage;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class EmailSignatureService {

    private final JavaMailSender      mailSender;
    private final DocumentRepository  documentRepository;

    public Map<String, Object> sendDocumentById(
            Long documentId, String receiver) throws Exception {

        // 1. Busca documento com assinaturas
        DocumentEntity doc = documentRepository
            .findById(documentId)
            .orElseThrow(() -> new EntityNotFoundException(
                "Documento não encontrado: " + documentId));

        List<SignatureEntity> signatures = doc.getSignatures();
        if (signatures == null || signatures.isEmpty()) {
            throw new IllegalStateException(
                "Documento " + documentId + " não possui assinaturas.");
        }

        // 2. Verifica tamanho antes de tentar enviar
        long bytesDoc  = doc.getContent().length;
        long bytesSigs = signatures.stream()
            .mapToLong(s -> s.getSignatureBytes().length
                          + s.getPublicKeyBytes().length)
            .sum();
        long estimated = (long)((bytesDoc + bytesSigs) * 1.33) + 10_000;

        if (estimated > 25_000_000L) {
            return Map.of(
                "emailEnviado",     false,
                "motivo",           "Tamanho estimado excede 25MB (limite Gmail)",
                "estimatedBytes",  estimated,
                "totalAssinaturas", signatures.size()
                );
        }

        // 3. Monta o e-mail
        MimeMessage       msg    = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(
            msg, true, "UTF-8");

        helper.setTo(receiver);
        helper.setSubject("[PQC-TCC] " + doc.getName()
            + " — " + signatures.size() + " assinatura(s)");
        helper.setText(montarCorpo(doc, signatures), true);

        // Anexo 1 — o documento original
        helper.addAttachment(
            doc.getName(),
            new ByteArrayResource(doc.getContent()),
            doc.getType());

        // Anexo 2 — certificado JSON com todas as assinaturas
        helper.addAttachment(
            "certificado-assinaturas.json",
            new ByteArrayResource(
                montarCertificado(doc, signatures)
                    .getBytes(StandardCharsets.UTF_8)),
            "application/json");

        // 4. Envia e mede o tempo
        long   inicio       = System.nanoTime();
        mailSender.send(msg);
        double tempoEnvioMs = (System.nanoTime() - inicio) / 1_000_000.0;

        // 5. Monta resposta
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("emailEnviado",      true);
        response.put("destinatario",      receiver);
        response.put("documentoId",       doc.getId());
        response.put("documentoNome",     doc.getName());
        response.put("totalAssinaturas",  signatures.size());
        response.put("estimatedBytes",   estimated);
        response.put("tempoEnvioSMTPms",  tempoEnvioMs);
        response.put("algoritmos", signatures.stream()
            .map(SignatureEntity::getTypeAlgorithm)
            .distinct()
            .collect(Collectors.toList()));
        return response;
    }

    // ── Corpo HTML ───────────────────────────────────────────────
    private String montarCorpo(
            DocumentEntity doc,
            List<SignatureEntity> signatures) {

        // Agrupa por algoritmo para o resumo
        Map<String, Long> porAlg = signatures.stream()
            .collect(Collectors.groupingBy(
                SignatureEntity::getTypeAlgorithm,
                Collectors.counting()));

        StringBuilder resumo = new StringBuilder();
        porAlg.forEach((alg, total) -> {
            SignatureEntity ex = signatures.stream()
                .filter(s -> s.getTypeAlgorithm().equals(alg))
                .findFirst().orElseThrow();
            resumo.append(String.format("""
                <tr>
                  <td>%s</td><td>%d</td>
                  <td>%d bytes</td><td>%d bytes</td>
                </tr>
                """,
                alg, total,
                ex.getPublicKeyBytes().length,
                ex.getSignatureBytes().length));
        });

        // Preview das primeiras 5
        StringBuilder preview = new StringBuilder();
        signatures.stream().limit(5).forEach(sig ->
            preview.append(String.format("""
                <tr>
                  <td>%d</td><td>%s</td>
                  <td>%s</td><td>%b</td>
                </tr>
                """,
                sig.getId(),
                sig.getTypeAlgorithm(),
                sig.getSignatureDate(),
                sig.isValid())));

        String aviso = signatures.size() > 5
            ? "<p><em>... e mais " + (signatures.size() - 5)
              + " assinaturas no arquivo JSON anexo.</em></p>"
            : "";

        return String.format("""
            <h2>%s</h2>
            <p><strong>Total de assinaturas:</strong> %d</p>

            <h3>Resumo por Algoritmo</h3>
            <table border="1" cellpadding="6">
              <tr>
                <th>Algoritmo</th><th>Quantidade</th>
                <th>Chave Pública</th><th>Assinatura</th>
              </tr>
              %s
            </table>

            <h3>Primeiras 5 Assinaturas</h3>
            <table border="1" cellpadding="6">
              <tr>
                <th>ID</th><th>Algoritmo</th>
                <th>Data</th><th>Válida</th>
              </tr>
              %s
            </table>
            %s
            <p><em>TCC — Criptografia Pós-Quântica — FAETERJ</em></p>
            """,
            doc.getName(),
            signatures.size(),
            resumo, preview, aviso);
    }

    // ── Certificado JSON ─────────────────────────────────────────
    private String montarCertificado(
            DocumentEntity doc,
            List<SignatureEntity> signatures) {

        StringBuilder sigs = new StringBuilder();
        for (int i = 0; i < signatures.size(); i++) {
            SignatureEntity sig = signatures.get(i);
            if (i > 0) sigs.append(",\n");
            sigs.append(String.format("""
                {
                  "id": %d,
                  "typeAlgorithm": "%s",
                  "signatureDate": "%s",
                  "publicKeyBytes": %d,
                  "signatureBytes": %d,
                  "valid": %b,
                  "hashDocument": "%s"
                }""",
                sig.getId(),
                sig.getTypeAlgorithm(),
                sig.getSignatureDate(),
                sig.getPublicKeyBytes().length,
                sig.getSignatureBytes().length,
                sig.isValid(),
                sig.getHashDocument()));
        }

        return String.format("""
            {
              "documentoId": %d,
              "documentoNome": "%s",
              "totalAssinaturas": %d,
              "assinaturas": [%s]
            }""",
            doc.getId(),
            doc.getName(),
            signatures.size(),
            sigs);
    }
}