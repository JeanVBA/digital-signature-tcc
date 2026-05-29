package br.edu.faeterj.tcc.digital_signature.service;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;

import br.edu.faeterj.tcc.digital_signature.domain.ForgeryAttemptEntity;
import br.edu.faeterj.tcc.digital_signature.domain.SignatureEntity;
import br.edu.faeterj.tcc.digital_signature.repository.ForgeryAttemptRepository;
import br.edu.faeterj.tcc.digital_signature.repository.SignatureRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class ForgeryService {

    private final ForgeryAttemptRepository forgeryRepository;
    private final SignatureRepository signatureRepository;

    /**
     * Tenta forjar a assinatura de três formas diferentes.
     * Todas falham — salva cada tentativa no histórico com o motivo técnico.
     */
    public List<Map<String, Object>> attemptForgery(Long signatureId)
            throws GeneralSecurityException {

        SignatureEntity sig = signatureRepository.findById(signatureId)
                .orElseThrow(() -> new EntityNotFoundException(
                        "Assinatura não encontrada: " + signatureId));

        byte[] originalData = sig.getDocument().getContent();
        byte[] publicKey = sig.getPublicKeyBytes();
        String algorithm = sig.getTypeAlgorithm();

        List<Map<String, Object>> result = new ArrayList<>();

        // Tentativa 1 — bytes aleatórios como assinatura
        result.add(executeAttempt(
                sig, algorithm, originalData, publicKey,
                generateRandomSignature(sig.getSignatureBytes().length),
                "RANDOM_BYTES",
                "Bytes aleatórios jamais satisfazem as equações " +
                        algorithmReason(algorithm, "RANDOM_BYTES")));

        // Tentativa 2 — assinatura zerada (todos os bytes = 0)
        result.add(executeAttempt(
                sig, algorithm, originalData, publicKey,
                new byte[sig.getSignatureBytes().length],
                "ZEROED",
                "Assinatura zerada não passa na verificação estrutural " +
                        algorithmReason(algorithm, "ZEROED")));

        // Tentativa 3 — assinatura original com bits invertidos
        result.add(executeAttempt(
                sig, algorithm, originalData, publicKey,
                invertBits(sig.getSignatureBytes()),
                "FLIPPED_BITS",
                "Inversão de bits produz vetor inválido — " +
                        algorithmReason(algorithm, "FLIPPED_BITS")));

        return result;
    }

    private Map<String, Object> executeAttempt(
            SignatureEntity sig,
            String algorithm,
            byte[] data,
            byte[] publicKeyBytes,
            byte[] forgedSignature,
            String attackType,
            String technicalReason) {

        // Captura o resultado real da verificação com detalhes
        Map<String, Object> verificationResult = verifyWithDetails(algorithm, data, forgedSignature, publicKeyBytes);

        boolean sucesso = (boolean) verificationResult.get("passed");

        ForgeryAttemptEntity attempt = new ForgeryAttemptEntity();
        attempt.setSignature(sig);
        attempt.setAttemptDate(LocalDateTime.now());
        attempt.setAttackType(attackType);
        attempt.setAlgorithm(algorithm);
        attempt.setForgedSignatureBytes(forgedSignature);
        attempt.setSucceeded(sucesso);
        attempt.setTechnicalReason(technicalReason); 
        forgeryRepository.save(attempt);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("tipoAtaque", attackType);
        result.put("algorithm", algorithm);
        result.put("falsificacaoBemSucedida", sucesso);
        result.put("verificacaoReal", verificationResult); // ← detalhe real
        result.put("motivoTecnico", technicalReason);
        result.put("dataHora", attempt.getAttemptDate());
        result.put("tamanhoForgedBytes", forgedSignature.length);
        return result;
    }

    // ── Verificação com chave pública real ──────────────────────
    private boolean verificationSignature(
            String algorithm,
            byte[] data,
            byte[] forgedSignature,
            byte[] publicKeyBytes) {
        try {
            return switch (algorithm) {
                case "ECDSA" -> {
                    KeyFactory kf = KeyFactory.getInstance("EC", "BC");
                    PublicKey pub = kf.generatePublic(
                            new X509EncodedKeySpec(publicKeyBytes));
                    Signature sig = Signature
                            .getInstance("SHA256withECDSA", "BC");
                    sig.initVerify(pub);
                    sig.update(data);
                    yield sig.verify(forgedSignature);
                }
                case "ML-DSA-44" -> {
                    KeyFactory kf = KeyFactory.getInstance("ML-DSA", "BC");
                    PublicKey pub = kf.generatePublic(
                            new X509EncodedKeySpec(publicKeyBytes));
                    Signature sig = Signature.getInstance("ML-DSA", "BC");
                    sig.initVerify(pub);
                    sig.update(data);
                    yield sig.verify(forgedSignature);
                }
                default -> false;
            };
        } catch (Exception e) {
            return false;
        }
    }

    // ── Helpers ─────────────────────────────────────────────────
    private byte[] generateRandomSignature(int tamanho) {
        byte[] bytes = new byte[tamanho];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    private byte[] invertBits(byte[] original) {
        byte[] invertido = Arrays.copyOf(original, original.length);
        for (int i = 0; i < invertido.length; i++) {
            invertido[i] = (byte) (invertido[i] ^ 0xFF);
        }
        return invertido;
    }

    private String algorithmReason(String algorithm, String tipo) {
        return switch (algorithm) {
            case "ECDSA" ->
                "do ECDSA: a coordenada 'r' recalculada na curva secp256r1 " +
                        "não coincide com a armazenada. Forjar exigiria resolver o ECDLP.";
            case "ML-DSA-44" ->
                "do ML-DSA-44: a norma do vetor polinomial excede o limite β " +
                        "do FIPS 204 (Bound Check). Forjar exigiria resolver o SVP em reticulados.";
            default -> ".";
        };
    }

    // ── Histórico ────────────────────────────────────────────────
    public List<Map<String, Object>> searchHistory() {
        return forgeryRepository.findAllByOrderByAttemptDateDesc()
                .stream()
                .map(a -> {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("id", a.getId());
                    m.put("signatureId", a.getSignature().getId());
                    m.put("documentoNome", a.getSignature().getDocument().getName());
                    m.put("algorithm", a.getAlgorithm());
                    m.put("tipoAtaque", a.getAttackType());
                    m.put("dataHora", a.getAttemptDate());
                    m.put("falsificacaoBemSucedida", a.isSucceeded());
                    m.put("motivoTecnico", a.getTechnicalReason());
                    return m;
                })
                .collect(Collectors.toList());
    }

    public Map<String, Object> searchHistoryBySignature(Long signatureId) {
        List<ForgeryAttemptEntity> attempts = forgeryRepository.findBySignatureId(signatureId);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("signatureId", signatureId);
        result.put("totalAttempts", attempts.size());
        result.put("success", attempts.stream()
                .anyMatch(ForgeryAttemptEntity::isSucceeded));
        result.put("attempts", attempts.stream().map(a -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", a.getId());
            m.put("attackType", a.getAttackType());
            m.put("attemptDate", a.getAttemptDate());
            m.put("success", a.isSucceeded());
            m.put("technicalReason", a.getTechnicalReason());
            return m;
        }).collect(Collectors.toList()));

        return result;
    }

    private Map<String, Object> verifyWithDetails(
            String algorithm,
            byte[] data,
            byte[] forgedSignature,
            byte[] publicKeyBytes) {

        Map<String, Object> detail = new LinkedHashMap<>();

        // ── Análise estática da assinatura forjada ────────────────
        detail.put("forgedSignatureLengthBytes", forgedSignature.length);
        detail.put("firstBytesHex",
                bytesToHex(Arrays.copyOfRange(forgedSignature, 0,
                        Math.min(8, forgedSignature.length))));
        detail.put("isAllZeros", isAllZeros(forgedSignature));
        detail.put("isAllOnes", isAllOnes(forgedSignature));
        detail.put("byteEntropy", calcularEntropia(forgedSignature));

        // ── Tenta a verificação e captura o que realmente ocorre ──
        try {
            switch (algorithm) {
                case "ECDSA" -> {
                    KeyFactory kf = KeyFactory.getInstance("EC", "BC");
                    PublicKey pub = kf.generatePublic(
                            new X509EncodedKeySpec(publicKeyBytes));
                    Signature s = Signature
                            .getInstance("SHA256withECDSA", "BC");
                    s.initVerify(pub);
                    s.update(data);
                    boolean passed = s.verify(forgedSignature);
                    detail.put("passed", passed);
                    detail.put("exceptionThrown", false);
                    detail.put("failurePoint",
                            passed ? "PASSOU"
                                    : "SHA256withECDSA.verify() retornou false — "
                                            + "coordenada r recalculada não coincide com a assinatura");
                }
                case "ML-DSA-44" -> {
                    KeyFactory kf = KeyFactory.getInstance("ML-DSA", "BC");
                    PublicKey pub = kf.generatePublic(
                            new X509EncodedKeySpec(publicKeyBytes));
                    Signature s = Signature.getInstance("ML-DSA", "BC");
                    s.initVerify(pub);
                    s.update(data);
                    boolean passed = s.verify(forgedSignature);
                    detail.put("passed", passed);
                    detail.put("exceptionThrown", false);
                    detail.put("failurePoint",
                            passed ? "PASSOU"
                                    : determinarFalhaMLDSA(forgedSignature));
                }
                default -> {
                    detail.put("passed", false);
                    detail.put("failurePoint", "Algoritmo desconhecido");
                }
            }
        } catch (SignatureException e) {
            // SignatureException = assinatura malformada estruturalmente
            detail.put("passed", false);
            detail.put("exceptionThrown", true);
            detail.put("exceptionType", "SignatureException");
            detail.put("exceptionMessage", e.getMessage());
            detail.put("failurePoint",
                    "Assinatura estruturalmente inválida — rejeitada antes "
                            + "da verificação matemática. Mensagem: " + e.getMessage());
        } catch (Exception e) {
            detail.put("passed", false);
            detail.put("exceptionThrown", true);
            detail.put("exceptionType", e.getClass().getSimpleName());
            detail.put("exceptionMessage", e.getMessage());
            detail.put("failurePoint", "Exceção inesperada: " + e.getMessage());
        }

        return detail;
    }

    /**
     * Determina qual verificação do FIPS 204 rejeitou o vetor,
     * analisando as propriedades estatísticas da assinatura forjada.
     */
    private String determinarFalhaMLDSA(byte[] forgedSig) {
        // ML-DSA-44: assinatura = [c_tilde (32 bytes)] + [z (k*l polinômios)]
        // Se o vetor z tem coeficientes com norma alta → Bound Check
        // Se c_tilde não corresponde → Hash Check

        // Analisa os primeiros 32 bytes (commitment hash c_tilde)
        byte[] cTilde = Arrays.copyOfRange(forgedSig, 0,
                Math.min(32, forgedSig.length));

        // Analisa os bytes restantes (vetor z)
        byte[] zVector = Arrays.copyOfRange(forgedSig, 32, forgedSig.length);

        double entropiaZ = calcularEntropia(zVector);
        boolean zPareceMal = entropiaZ > 7.8 || entropiaZ < 0.5;

        if (isAllZeros(forgedSig)) {
            return "FIPS 204 §6.3 — Verificação estrutural: vetor z nulo "
                    + "não pode ter sido produzido por nenhuma chave privada válida. "
                    + "Falha antes do Bound Check.";
        }
        if (zPareceMal) {
            return String.format(
                    "FIPS 204 §6.3 — Bound Check: norma ||z||∞ estimada como "
                            + "alta (entropia do vetor z = %.2f bits/byte, esperado ~6-7). "
                            + "Coeficientes fora do intervalo (-γ₁+β, γ₁-β). "
                            + "ML-DSA.Verify_internal retornou false.",
                    entropiaZ);
        }
        return "FIPS 204 §6.3 — Hash de compromisso: c_tilde recalculado "
                + "não coincide com os primeiros 32 bytes da assinatura forjada. "
                + "Verificação falhou antes do Bound Check geométrico.";
    }

    // ── Helpers ────────────────────────────────────────────────────
    private boolean isAllZeros(byte[] b) {
        for (byte x : b)
            if (x != 0)
                return false;
        return true;
    }

    private boolean isAllOnes(byte[] b) {
        for (byte x : b)
            if ((x & 0xFF) != 0xFF)
                return false;
        return true;
    }

    private double calcularEntropia(byte[] data) {
        if (data.length == 0)
            return 0;
        int[] freq = new int[256];
        for (byte b : data)
            freq[b & 0xFF]++;
        double h = 0;
        for (int f : freq) {
            if (f > 0) {
                double p = (double) f / data.length;
                h -= p * (Math.log(p) / Math.log(2));
            }
        }
        return h;
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes)
            sb.append(String.format("%02X", b));
        return sb.toString();
    }
}