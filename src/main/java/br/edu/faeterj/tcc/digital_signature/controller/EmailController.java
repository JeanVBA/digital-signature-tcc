package br.edu.faeterj.tcc.digital_signature.controller;

import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import br.edu.faeterj.tcc.digital_signature.service.EmailSignatureService;
import io.swagger.v3.oas.annotations.Operation;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/email")
@RequiredArgsConstructor
public class EmailController {

    private final EmailSignatureService emailService;

    @PostMapping("/enviar/{signatureId}")
    @Operation(summary = "Envia documento assinado por email e retorna métricas reais de rede")
    public ResponseEntity<Map<String, Object>> send(
            @PathVariable Long signatureId,
            @RequestParam String receiver) throws Exception {

        return ResponseEntity.ok(
            emailService.enviarDocumentoAssinado(signatureId, receiver));
    }
}
