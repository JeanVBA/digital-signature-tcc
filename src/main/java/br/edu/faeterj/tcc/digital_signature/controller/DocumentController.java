package br.edu.faeterj.tcc.digital_signature.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import br.edu.faeterj.tcc.digital_signature.domain.DocumentEntity;
import br.edu.faeterj.tcc.digital_signature.domain.SignatureEntity;
import br.edu.faeterj.tcc.digital_signature.service.CryptoSignatureService;
import br.edu.faeterj.tcc.digital_signature.service.ForgeryService;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/crypto")
@RequiredArgsConstructor
public class DocumentController {

        @Autowired
        private CryptoSignatureService cryptoService;

        @Autowired
        private ForgeryService forgeryService;

        @Operation(summary = "Assina um documento PDF ou Word")
        @PostMapping(value = "/sign", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
        public ResponseEntity<?> signDocument(
                        @RequestPart("file") MultipartFile file,
                        @RequestParam(value = "algorithm", defaultValue = "ML-DSA") String algorithm)
                        throws Exception {

                // 1. Busca documento existente pelo nome — ou cria um novo
                String fileName = file.getOriginalFilename();

                DocumentEntity doc = cryptoService.findDocumentByName(fileName)
                                .orElseGet(() -> {
                                        DocumentEntity novo = new DocumentEntity();
                                        novo.setName(fileName);
                                        novo.setType(file.getContentType());
                                        novo.setCreatedAt(LocalDateTime.now());
                                        try {
                                                novo.setContent(file.getBytes());
                                        } catch (IOException e) {
                                                throw new RuntimeException("Erro ao ler bytes do arquivo", e);
                                        }
                                        return cryptoService.documentSave(novo);
                                });

                // 2. Assina e mede o tempo
                long start = System.nanoTime();

                SignatureEntity result = switch (algorithm.toUpperCase()) {
                        case "ML-DSA" -> cryptoService.signWithMLDSA(doc);
                        case "ECDSA" -> cryptoService.signWithECDSA(doc);
                        default -> throw new IllegalArgumentException(
                                        "Algorithm inválido. Use: ECDSA ou ML-DSA");
                };

                long fim = System.nanoTime();

                // 3. Quantas assinaturas o documento tem agora
                int totalAssinaturas = cryptoService.findSignatureByDocumentId(doc.getId()).size();

                Map<String, Object> response = new LinkedHashMap<>();
                response.put("signatureId", result.getId());
                response.put("documentId", doc.getId());
                response.put("archive", fileName);
                response.put("documentoEraExistente", totalAssinaturas > 1);
                response.put("totalAssinaturasNoDocumento", totalAssinaturas);
                response.put("algorithm", result.getTypeAlgorithm());
                response.put("signatureSizeBytes", result.getSignatureBytes().length);
                response.put("publicKeySizeBytes", result.getPublicKeyBytes().length);
                response.put("ipFragmentation", result.getPublicKeyBytes().length
                                + result.getSignatureBytes().length > 1500);
                response.put("isValid", result.isValid());
                response.put("executionTimeMs", (fim - start) / 1_000_000.0);

                return ResponseEntity.ok(response);
        }

        @PostMapping("/nonce-reuse/{signatureId}")
        @Operation(summary = "Demonstra colapso ECDSA por reutilização de nonce", description = "Usa uma assinatura ECDSA real do banco e simula uma segunda "
                        +
                        "assinatura com o mesmo nonce k, demonstrando a extração da " +
                        "chave privada via álgebra linear. Ref: NIST SP 800-90A Rev. 1")
        public ResponseEntity<Map<String, Object>> nonceReuse(
                        @PathVariable Long signatureId,
                        @RequestParam(defaultValue = "Segundo contrato assinado com a mesma chave") String newMessage)
                        throws Exception {

                return ResponseEntity.ok(
                                cryptoService.attackSignatureECDSA(
                                                signatureId, newMessage));
        }

        @GetMapping("/validate/{signatureId}")
        public ResponseEntity<Map<String, Object>> validatedSignature(
                        @PathVariable Long signatureId) throws Exception {

                SignatureEntity sig = cryptoService.findSignatureById(signatureId)
                                .orElseThrow(() -> new EntityNotFoundException(
                                                "Assinatura não encontrada: " + signatureId));

                boolean valida = cryptoService.validateSignature(signatureId);

                Map<String, Object> response = new LinkedHashMap<>();
                response.put("signatureId", signatureId);
                response.put("documentId", sig.getDocument().getId());
                response.put("nameArchive", sig.getDocument().getName());
                response.put("algorithm", sig.getTypeAlgorithm());
                response.put("isValid", valida);

                if (valida) {
                        response.put("status", "ÍNTEGRO");
                        response.put("mensagem",
                                        "Assinatura válida — documento não foi modificado desde a assinatura.");
                } else {
                        response.put("status", "ADULTERADO");
                        response.put("mensagem",
                                        "FALHA DETECTADA: o conteúdo do documento foi modificado após a assinatura.");
                        response.put("detalheTecnico", switch (sig.getTypeAlgorithm()) {
                                case "ECDSA" -> "A coordenada 'r' recalculada na curva elíptica não coincide " +
                                                "com a assinatura armazenada — adulteração detectada.";
                                case "ML-DSA-44" -> "O Bound Check falhou: a norma do vetor polinomial excede o " +
                                                "limite β definido pelo NIST FIPS 204 — adulteração detectada.";
                                default -> "algorithm desconhecido.";
                        });
                }

                return ResponseEntity.ok(response);
        }

        @PostMapping("/falsificate-content/{documentId}")
        public ResponseEntity<Map<String, Object>> falsificateContent(
                        @PathVariable Long documentId) throws Exception {

                Map<String, Object> response = new LinkedHashMap<>();
                response.put("documentId", documentId);

                DocumentEntity doc = cryptoService.findDocumentById(documentId)
                                .orElseThrow(() -> new EntityNotFoundException(
                                                "Documento não encontrado: " + documentId));

                // Guarda o conteúdo original para o relatório
                byte[] originalContent = doc.getContent();

                // Adultera os bytes do documento no banco
                byte[] alteredContent = adulterateBytes(originalContent);
                doc.setContent(alteredContent);
                cryptoService.documentSave(doc);

                response.put("nameArchive", doc.getName());
                response.put("originalSizeBytes", originalContent.length);
                response.put("alteredSizeBytes", alteredContent.length);
                response.put("alteredBytes", countDiferences(originalContent, alteredContent));
                response.put("status", "DOCUMENTO ADULTERADO — chame GET /validate/{signatureId} para detectar.");
                response.put("instruction",
                                "Use o signatureId vinculado a este documento no endpoint /validate para ver a detecção.");

                return ResponseEntity.ok(response);
        }

        // Adultera alguns bytes no meio do conteúdo — simula modificação real
        private byte[] adulterateBytes(byte[] original) {
                byte[] adulterated = Arrays.copyOf(original, original.length);

                // Modifica bytes no meio do documento (evita cabeçalho do PDF)
                int start = adulterated.length / 3;
                for (int i = start; i < start + 20 && i < adulterated.length; i++) {
                        adulterated[i] = (byte) (adulterated[i] ^ 0xFF); // inverte os bits
                }
                return adulterated;
        }

        // Conta quantos bytes foram alterados
        private int countDiferences(byte[] original, byte[] adulterated) {
                int count = 0;
                int limite = Math.min(original.length, adulterated.length);
                for (int i = 0; i < limite; i++) {
                        if (original[i] != adulterated[i])
                                count++;
                }
                return count;
        }

        // ── Tentativa de falsificação ────────────────────────────────────
        @PostMapping("/falsificate-signature/{signatureId}")
        @Operation(summary = "Tenta forjar a assinatura — salva no histórico")
        public ResponseEntity<Map<String, Object>> falsificateSignature(
                        @PathVariable Long signatureId) throws GeneralSecurityException {

                List<Map<String, Object>> attempts = forgeryService.attemptForgery(signatureId);

                long sucess = attempts.stream()
                                .filter(t -> (boolean) t.get("falsificacaoBemSucedida"))
                                .count();

                Map<String, Object> response = new LinkedHashMap<>();
                response.put("signatureId", signatureId);
                response.put("totalAttempts", attempts.size());
                response.put("successiveForgery", sucess);
                response.put("conclusion",
                                sucess == 0
                                                ? "Nenhuma tentativa de falsificação foi bem-sucedida. " +
                                                                "A assinatura permanece criptograficamente segura."
                                                : "ATENÇÃO: falsificação detectada como bem-sucedida.");
                response.put("attempts", attempts);

                return ResponseEntity.ok(response);
        }

        // ── Histórico geral de tentativas ───────────────────────────────
        @GetMapping("/historical-forgeries")
        @Operation(summary = "Lista todas as tentativas de falsificação registradas")
        public ResponseEntity<List<Map<String, Object>>> historicalForgeries() {
                return ResponseEntity.ok(forgeryService.searchHistory());
        }

        // ── Histórico por assinatura ─────────────────────────────────────
        @GetMapping("/historical-forgery/{signatureId}")
        @Operation(summary = "Lista tentativas de falsificação de uma assinatura específica")
        public ResponseEntity<Map<String, Object>> historicalForgeryBySignature(
                        @PathVariable Long signatureId) {
                return ResponseEntity.ok(
                                forgeryService.searchHistoryBySignature(signatureId));
        }

        @GetMapping("/validate-signature/{signatureId}")
        @Operation(summary = "Valida criptograficamente a assinatura armazenada no banco")
        public ResponseEntity<Map<String, Object>> validateSignature(
                        @PathVariable Long signatureId) throws GeneralSecurityException {

                SignatureEntity sig = cryptoService.findSignatureById(signatureId)
                                .orElseThrow(() -> new EntityNotFoundException(
                                                "Assinatura não encontrada: " + signatureId));

                boolean isValid = cryptoService.onlyValidateSignature(signatureId);

                // Quantas tentativas de falsificação já ocorreram nesta assinatura
                long attemptsForgery = forgeryService
                                .searchHistoryBySignature(signatureId)
                                .entrySet().stream()
                                .filter(e -> e.getKey().equals("totalAttempts"))
                                .mapToLong(e -> (int) e.getValue())
                                .sum();

                Map<String, Object> response = new LinkedHashMap<>();
                response.put("signatureId", sig.getId());
                response.put("documentName", sig.getDocument().getName());
                response.put("algorithm", sig.getTypeAlgorithm());
                response.put("signatureDate", sig.getSignatureDate());
                response.put("isValid", isValid);
                response.put("totalForgeryAttempts", attemptsForgery);
                response.put("status", isValid ? "ÍNTEGRA" : "COMPROMETIDA");
                response.put("message", isValid
                                ? "A assinatura criptográfica é válida. Os bytes da assinatura " +
                                                "armazenada correspondem ao documento original."
                                : "FALHA: a assinatura não corresponde ao documento atual.");
                response.put("technicalDetail", switch (sig.getTypeAlgorithm()) {
                        case "ECDSA" ->
                                "Verificação via SHA-256 + curva secp256r1. " +
                                                "A coordenada 'r' foi recalculada e comparada com a assinatura armazenada.";
                        case "ML-DSA-44" ->
                                "Verificação via FIPS 204. O Bound Check confirmou que a norma " +
                                                "do vetor polinomial está dentro do limite β permitido.";
                        default -> "";
                });

                return ResponseEntity.ok(response);
        }
}
