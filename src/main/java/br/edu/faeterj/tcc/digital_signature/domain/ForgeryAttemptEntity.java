package br.edu.faeterj.tcc.digital_signature.domain;

import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Lob;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "forgery_attempts")
@Getter 
@Setter 
@NoArgsConstructor 
@AllArgsConstructor
public class ForgeryAttemptEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "signature_id", nullable = false)
    private SignatureEntity signature;

    @Column(nullable = false)
    private LocalDateTime attemptDate;

    @Column(nullable = false)
    private String attackType; // "RANDOM_BYTES", "ZEROED", "FLIPPED_BITS"

    @Column(nullable = false)
    private String algorithm; // algoritmo da assinatura alvo

    @Lob
    @Column(nullable = false)
    private byte[] forgedSignatureBytes; // bytes forjados usados na tentativa

    @Column(nullable = false)
    private boolean succeeded; // sempre false — aqui para fins didáticos

    @Column
    private String technicalReason; // por que falhou matematicamente
}