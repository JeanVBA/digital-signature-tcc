package br.edu.faeterj.tcc.digital_signature.domain;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Table(name = "signatures")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class SignatureEntity {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "document_id", nullable = false)
    private DocumentEntity document;
    
    @Column(nullable = false)
    private String typeAlgorithm; // "ECDSA" ou "ML-DSA-44"
    
    @Column(nullable = false, length = 64)
    private String hashDocument; // SHA-256 do documento, em hex

    @Lob
    @Column(nullable = false)
    private byte[] signatureBytes;
    
    @Lob
    @Column(nullable = false)
    private byte[] publicKeyBytes;
    
    @Column(nullable = false)
    private LocalDateTime signatureDate;
    
    @Column(nullable = false)
    private boolean valid;
}
