package br.edu.faeterj.tcc.digital_signature.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import br.edu.faeterj.tcc.digital_signature.domain.ForgeryAttemptEntity;

@Repository
public interface ForgeryAttemptRepository
        extends JpaRepository<ForgeryAttemptEntity, Long> {

    List<ForgeryAttemptEntity> findBySignatureId(Long signatureId);

    List<ForgeryAttemptEntity> findAllByOrderByAttemptDateDesc();
}