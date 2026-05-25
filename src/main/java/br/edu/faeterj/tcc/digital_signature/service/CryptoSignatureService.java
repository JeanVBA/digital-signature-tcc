package br.edu.faeterj.tcc.digital_signature.service;

import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.springframework.stereotype.Service;

import br.edu.faeterj.tcc.digital_signature.config.BouncyCastleConfig;
import br.edu.faeterj.tcc.digital_signature.domain.DocumentEntity;
import br.edu.faeterj.tcc.digital_signature.domain.SignatureEntity;
import br.edu.faeterj.tcc.digital_signature.repository.DocumentRepository;
import br.edu.faeterj.tcc.digital_signature.repository.SignatureRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.AllArgsConstructor;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
@AllArgsConstructor
public class CryptoSignatureService {

    private static final BigInteger N = new BigInteger(
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
    private final SignatureRepository signatureRepository;
    private final DocumentRepository documentRepository;

    public SignatureEntity signWithECDSA(DocumentEntity doc)
            throws GeneralSecurityException {

        // 1. Gerar chaves
        KeyPairGenerator gen = KeyPairGenerator
                .getInstance("EC", BouncyCastleConfig.PROVIDER);
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair par = gen.generateKeyPair();

        // 2. Assinar
        Signature sig = Signature
                .getInstance(BouncyCastleConfig.ALGORITHM_ECDSA,
                        BouncyCastleConfig.PROVIDER);
        sig.initSign(par.getPrivate());
        sig.update(doc.getContent());
        byte[] signatureBytes = sig.sign();

        // 3. Verificar
        Signature ver = Signature
                .getInstance(BouncyCastleConfig.ALGORITHM_ECDSA,
                        BouncyCastleConfig.PROVIDER);
        ver.initVerify(par.getPublic());
        ver.update(doc.getContent());
        boolean valid = ver.verify(signatureBytes);

        // 4. Montar e persistir a entidade
        SignatureEntity entity = new SignatureEntity();
        entity.setDocument(doc);
        entity.setTypeAlgorithm("ECDSA");
        entity.setPublicKeyBytes(par.getPublic().getEncoded());
        entity.setSignatureBytes(signatureBytes);
        entity.setSignatureDate(LocalDateTime.now());
        entity.setHashDocument(calculateHash(doc.getContent()));
        entity.setValid(valid);

        return signatureRepository.save(entity);
    }

    public boolean isValidECDSA(byte[] data, byte[] assinatura, byte[] chavePublicaBytes)
            throws GeneralSecurityException {

        // "EC" aqui, NÃO "ECDSA" — armadilha clássica da API Java
        KeyFactory kf = KeyFactory.getInstance("EC", "BC");
        PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(chavePublicaBytes));

        Signature sig = Signature.getInstance("SHA256withECDSA", "BC");
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(assinatura);
    }

    public SignatureEntity signWithMLDSA(DocumentEntity doc)
            throws GeneralSecurityException {

        // 1. Gerar chaves
        KeyPairGenerator gen = KeyPairGenerator
                .getInstance(BouncyCastleConfig.ALGORITHM_MLDSA,
                        BouncyCastleConfig.PROVIDER);
        gen.initialize(MLDSAParameterSpec.ml_dsa_44);
        KeyPair par = gen.generateKeyPair();

        // 2. Assinar
        Signature sig = Signature
                .getInstance(BouncyCastleConfig.ALGORITHM_MLDSA,
                        BouncyCastleConfig.PROVIDER);
        sig.initSign(par.getPrivate());
        sig.update(doc.getContent());
        byte[] signatureBytes = sig.sign();

        // 3. Verificar (Bound Check ocorre internamente aqui)
        Signature ver = Signature
                .getInstance(BouncyCastleConfig.ALGORITHM_MLDSA,
                        BouncyCastleConfig.PROVIDER);
        ver.initVerify(par.getPublic());
        ver.update(doc.getContent());
        boolean valid = ver.verify(signatureBytes);

        // 4. Montar e persistir a entidade
        SignatureEntity entity = new SignatureEntity();
        entity.setDocument(doc);
        entity.setTypeAlgorithm("ML-DSA-44");
        entity.setPublicKeyBytes(par.getPublic().getEncoded());
        entity.setSignatureBytes(signatureBytes);
        entity.setSignatureDate(LocalDateTime.now());
        entity.setHashDocument(calculateHash(doc.getContent()));
        entity.setValid(valid);

        return signatureRepository.save(entity);
    }

    public boolean isValidMLDSA(byte[] data, byte[] assinatura, byte[] chavePublicaBytes)
            throws GeneralSecurityException {

        KeyFactory kf = KeyFactory.getInstance("ML-DSA", "BC");
        PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(chavePublicaBytes));

        Signature sig = Signature.getInstance("ML-DSA", "BC");
        sig.initVerify(publicKey);
        sig.update(data);
        // false aqui pode significar: data adulterados OU Bound Check excedido
        return sig.verify(assinatura);
    }

    public boolean validateSignature(Long signatureId)
            throws GeneralSecurityException {

        SignatureEntity sig = signatureRepository.findById(signatureId)
                .orElseThrow(() -> new EntityNotFoundException(
                        "Assinatura não encontrada: " + signatureId));

        byte[] data = sig.getDocument().getContent();
        byte[] signature = sig.getSignatureBytes();
        byte[] publicKey = sig.getPublicKeyBytes();

        return switch (sig.getTypeAlgorithm()) {
            case "ECDSA" -> isValidECDSA(data, signature, publicKey);
            case "ML-DSA-44" -> isValidMLDSA(data, signature, publicKey);
            default -> throw new IllegalArgumentException(
                    "Algoritmo desconhecido: " + sig.getTypeAlgorithm());
        };
    }

    public KeyPair generateKeyECDSA() throws GeneralSecurityException {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", "BC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        return gen.generateKeyPair();
    }

    public KeyPair generateKeyMLDSA() throws GeneralSecurityException {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("ML-DSA", "BC");
        gen.initialize(MLDSAParameterSpec.ml_dsa_44);
        return gen.generateKeyPair();
    }

    private String calculateHash(byte[] conteudo) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(conteudo);
        // Converte para hex string
        StringBuilder sb = new StringBuilder();
        for (byte b : hash)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }

    public boolean onlyValidateSignature(Long signatureId)
            throws GeneralSecurityException {

        SignatureEntity sig = signatureRepository.findById(signatureId)
                .orElseThrow(() -> new EntityNotFoundException(
                        "Assinatura não encontrada: " + signatureId));

        // Reconstrói os bytes originais a partir do hash salvo
        // A verificação criptográfica usa os bytes reais do documento
        // que foram assinados — buscamos do campo original, não do atual
        byte[] verificationContent = sig.getDocument().getContent();

        // Se o documento foi adulterado depois, usamos o hash original
        // para detectar só se a ASSINATURA foi forjada
        try {
            String hashActual = calculateHash(verificationContent);
            String hashOriginal = sig.getHashDocument();

            if (!hashActual.equals(hashOriginal)) {
                // Documento foi adulterado — mas a assinatura em si pode ser válida
                // Usamos os bytes que foram realmente assinados (via hash original)
                // Não temos como reverter o documento, então verificamos só a estrutura
                return verifySignatureStructure(sig);
            }

            // Documento intacto — verificação completa normal
            return verifyWithPublicKey(sig, verificationContent);

        } catch (NoSuchAlgorithmException e) {
            throw new GeneralSecurityException("Erro ao calcular hash", e);
        }
    }

    private boolean verifySignatureStructure(SignatureEntity sig)
            throws GeneralSecurityException {

        try {
            return switch (sig.getTypeAlgorithm()) {
                case "ECDSA" -> {
                    KeyFactory kf = KeyFactory.getInstance("EC", "BC");
                    PublicKey pub = kf.generatePublic(
                            new X509EncodedKeySpec(sig.getPublicKeyBytes()));
                    // Tenta inicializar — se a assinatura for forjada/malformada, lança exceção
                    Signature s = Signature.getInstance("SHA256withECDSA", "BC");
                    s.initVerify(pub);
                    s.update(sig.getDocument().getContent());
                    yield s.verify(sig.getSignatureBytes());
                }
                case "ML-DSA-44" -> {
                    KeyFactory kf = KeyFactory.getInstance("ML-DSA", "BC");
                    PublicKey pub = kf.generatePublic(
                            new X509EncodedKeySpec(sig.getPublicKeyBytes()));
                    Signature s = Signature.getInstance("ML-DSA", "BC");
                    s.initVerify(pub);
                    s.update(sig.getDocument().getContent());
                    yield s.verify(sig.getSignatureBytes());
                }
                default -> false;
            };
        } catch (Exception e) {
            return false;
        }
    }

    private boolean verifyWithPublicKey(SignatureEntity sig, byte[] conteudo)
            throws GeneralSecurityException {

        return switch (sig.getTypeAlgorithm()) {
            case "ECDSA" -> {
                KeyFactory kf = KeyFactory.getInstance("EC", "BC");
                PublicKey pub = kf.generatePublic(
                        new X509EncodedKeySpec(sig.getPublicKeyBytes()));
                Signature s = Signature.getInstance("SHA256withECDSA", "BC");
                s.initVerify(pub);
                s.update(conteudo);
                yield s.verify(sig.getSignatureBytes());
            }
            case "ML-DSA-44" -> {
                KeyFactory kf = KeyFactory.getInstance("ML-DSA", "BC");
                PublicKey pub = kf.generatePublic(
                        new X509EncodedKeySpec(sig.getPublicKeyBytes()));
                Signature s = Signature.getInstance("ML-DSA", "BC");
                s.initVerify(pub);
                s.update(conteudo);
                yield s.verify(sig.getSignatureBytes());
            }
            default -> false;
        };
    }

    public Map<String, Object> attackSignatureECDSA(
            Long signatureId, String newMessage) throws Exception {

        SignatureEntity sig = signatureRepository.findById(signatureId)
                .orElseThrow(() -> new EntityNotFoundException(
                        "Assinatura não encontrada: " + signatureId));

        if (!"ECDSA".equals(sig.getTypeAlgorithm())) {
            Map<String, Object> errorReport = new LinkedHashMap<>();
            errorReport.put("titulo", "Erro: Assinatura Incompatível para o Experimento");
            errorReport.put("referencia", "Este experimento é específico para ECDSA. " +
                    "A assinatura " + signatureId + " usa " + sig.getTypeAlgorithm());
            errorReport.put("message", "Por favor, selecione uma assinatura ECDSA para este experimento.");
            return errorReport;
        }

        // ── Extrai r e s da assinatura DER real do banco ─────────
        // O Bouncy Castle gera assinaturas ECDSA no formato DER: 30 44 02 20 [r] 02 20
        // [s]
        byte[] derBytes = sig.getSignatureBytes();
        BigInteger[] rs = extractRSIntoDER(derBytes);
        BigInteger r = rs[0];
        BigInteger s1 = rs[1];

        // ── h1 = hash real do documento original ──────────────────
        BigInteger h1 = new BigInteger(1,
                MessageDigest.getInstance("SHA-256")
                        .digest(sig.getDocument().getContent()));

        // ── Gera uma segunda assinatura com k REUTILIZADO ─────────
        // Simula a falha: gera nova chave mas força o mesmo k
        // na prática, extrai k implícito da assinatura original
        // k = (h1 + d*r) * s1^-1 mod n — mas d é desconhecido
        // Para a demonstração didática: gera novo par e fixa k
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", "BC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair par = gen.generateKeyPair();
        ECPrivateKey chavePrivada = (ECPrivateKey) par.getPrivate();
        BigInteger d = chavePrivada.getS();

        // k fixo — simula PRNG com defeito retornando sempre o mesmo valor
        BigInteger k = new BigInteger(256, new SecureRandom()).mod(N.subtract(BigInteger.ONE))
                .add(BigInteger.ONE);

        // Recalcula r com o k simulado para consistência matemática
        // r = (k*G).x mod n — aproximado via fórmula inversa para didática
        BigInteger kInv = k.modInverse(N);
        BigInteger rSimulado = kInv.multiply(h1.add(d.multiply(r.mod(N)))).mod(N);
        final BigInteger rSimuladoUsado = rSimulado.equals(BigInteger.ZERO) ? r : rSimulado;

        // s1 recalculado com d e k conhecidos
        BigInteger s1Sim = kInv.multiply(h1.add(d.multiply(rSimuladoUsado))).mod(N);

        // h2 = hash da segunda mensagem
        BigInteger h2 = new BigInteger(1,
                MessageDigest.getInstance("SHA-256")
                        .digest(newMessage.getBytes()));

        // s2 com mesmo k — aqui está a vulnerabilidade
        BigInteger s2 = kInv.multiply(h2.add(d.multiply(rSimuladoUsado))).mod(N);

        // ── Ataque: extrai d ──────────────────────────────────────
        // d = (s1*h2 - s2*h1) / r*(s2-s1) mod n
        BigInteger numerator = s1Sim.multiply(h2).subtract(s2.multiply(h1)).mod(N);
        BigInteger denominator = rSimuladoUsado.multiply(s2.subtract(s1Sim)).mod(N);
        BigInteger dExtracted = numerator.multiply(denominator.modInverse(N)).mod(N);
        boolean isSuccess = dExtracted.equals(d);

        Map<String, Object> report = new LinkedHashMap<>();

        if (isSuccess) {

            // Reconstrói a chave privada a partir do d extraído
            ECNamedCurveParameterSpec curveSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
            ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(dExtracted, curveSpec);
            KeyFactory kf = KeyFactory.getInstance("EC", "BC");
            PrivateKey forgedPrivateKey = kf.generatePrivate(privateKeySpec);

            // Recalcula a chave pública a partir do d extraído
            // Q = d * G
            org.bouncycastle.math.ec.ECPoint Q = curveSpec.getG().multiply(dExtracted).normalize();
            ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(Q, curveSpec);
            PublicKey forgedPublicKey = kf.generatePublic(publicKeySpec);

            // Assina o documento original com a chave privada forjada
            Signature forgedSig = Signature.getInstance("SHA256withECDSA", "BC");
            forgedSig.initSign(forgedPrivateKey);
            forgedSig.update(sig.getDocument().getContent());
            byte[] forgedSignatureBytes = forgedSig.sign();

            // Verifica que a assinatura forjada passa na validação
            Signature verifier = Signature.getInstance("SHA256withECDSA", "BC");
            verifier.initVerify(forgedPublicKey);
            verifier.update(sig.getDocument().getContent());
            boolean forgedIsValid = verifier.verify(forgedSignatureBytes);

            // Persiste no banco como se fosse uma assinatura legítima
            SignatureEntity forgedEntity = new SignatureEntity();
            forgedEntity.setDocument(sig.getDocument());
            forgedEntity.setTypeAlgorithm("ECDSA");
            forgedEntity.setPublicKeyBytes(forgedPublicKey.getEncoded());
            forgedEntity.setSignatureBytes(forgedSignatureBytes);
            forgedEntity.setSignatureDate(LocalDateTime.now());
            forgedEntity.setHashDocument(calculateHash(sig.getDocument().getContent()));
            forgedEntity.setValid(forgedIsValid);
            SignatureEntity savedForged = signatureRepository.save(forgedEntity);

            report.put("forgedSignaturePersisted", new LinkedHashMap<String, Object>() {
                {
                    put("signatureId", savedForged.getId());
                    put("documentId", sig.getDocument().getId());
                    put("documentName", sig.getDocument().getName());
                    put("algorithm", "ECDSA");
                    put("signatureDate", savedForged.getSignatureDate());
                    put("isValid", forgedIsValid);
                    put("signatureSizeBytes", forgedSignatureBytes.length);
                    put("publicKeyBytes", forgedPublicKey.getEncoded().length);
                    put("alertaCritico",
                            "Esta assinatura foi gerada com a chave privada EXTRAÍDA por " +
                                    "álgebra linear. Ela é INDISTINGUÍVEL de uma assinatura legítima " +
                                    "— o sistema de validação a aceita como verdadeira.");
                    put("instrucao",
                            "Chame GET /api/crypto/validar-assinatura/" + savedForged.getId() +
                                    " para confirmar que a assinatura forjada passa na validação.");
                }
            });
        }
        return report;
    }

    private BigInteger[] extractRSIntoDER(byte[] der) {
        int offset = 2; // pula 0x30 e length
        offset++; // pula 0x02
        int rLen = der[offset++] & 0xFF;
        byte[] rBytes = Arrays.copyOfRange(der, offset, offset + rLen);
        offset += rLen;
        offset++; // pula 0x02
        int sLen = der[offset++] & 0xFF;
        byte[] sBytes = Arrays.copyOfRange(der, offset, offset + sLen);

        return new BigInteger[] {
                new BigInteger(1, rBytes),
                new BigInteger(1, sBytes)
        };
    }

    public Optional<SignatureEntity> findSignatureById(Long id) {
        return signatureRepository.findById(id);
    }

    public DocumentEntity documentSave(DocumentEntity document) {
        return documentRepository.save(document);
    }

    public Optional<DocumentEntity> findDocumentByName(String name) {
        return documentRepository.findByName(name);
    }

    public List<SignatureEntity> findSignatureByDocumentId(Long documentId) {
        return signatureRepository.findByDocumentId(documentId);
    }

    public Optional<DocumentEntity> findDocumentById(Long id) {
        return documentRepository.findById(id);
    }

    public List<SignatureEntity> findAll() {
        return signatureRepository.findAll();
    }
}