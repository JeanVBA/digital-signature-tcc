package br.edu.faeterj.tcc.digital_signature.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import br.edu.faeterj.tcc.digital_signature.domain.SignatureEntity;

@Repository
public interface SignatureRepository
        extends JpaRepository<SignatureEntity, Long> {

    List<SignatureEntity> findByDocumentId(Long documentId);
}