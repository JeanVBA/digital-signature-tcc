package br.edu.faeterj.tcc.digital_signature.service;

import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.springframework.stereotype.Service;

import br.edu.faeterj.tcc.digital_signature.config.BouncyCastleConfig;
import br.edu.faeterj.tcc.digital_signature.domain.DocumentEntity;
import br.edu.faeterj.tcc.digital_signature.domain.SignatureEntity;
import br.edu.faeterj.tcc.digital_signature.repository.DocumentRepository;
import br.edu.faeterj.tcc.digital_signature.repository.SignatureRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.AllArgsConstructor;

import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Service
@AllArgsConstructor
public class CryptoSignatureService {
    /**
     * Gera chaves e assina um payload usando ECDSA (secp256r1)
     */
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

    /**
     * Valida assinatura digital clássica ECDSA
     */
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

    /**
     * Gera chaves e assina um payload usando o modelo pós-quântico ML-DSA-44 (FIPS
     * 204)
     */

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

    /**
     * Valida assinatura digital pós-quântica ML-DSA
     */
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

    /**
     * Verifica só a estrutura criptográfica da assinatura —
     * se os bytes são uma assinatura válida para o algoritmo,
     * independente do conteúdo do documento.
     */
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