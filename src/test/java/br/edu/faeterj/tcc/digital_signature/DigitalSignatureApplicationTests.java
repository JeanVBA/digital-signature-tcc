package br.edu.faeterj.tcc.digital_signature;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.security.KeyPair;
import java.security.Security;
import java.security.Signature;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import br.edu.faeterj.tcc.digital_signature.domain.DocumentEntity;
import br.edu.faeterj.tcc.digital_signature.domain.SignatureEntity;
import br.edu.faeterj.tcc.digital_signature.repository.SignatureRepository;
import br.edu.faeterj.tcc.digital_signature.service.CryptoSignatureService;

@SpringBootTest
@ActiveProfiles("test")
@ExtendWith(MockitoExtension.class)
class DigitalSignatureApplicationTests {

	 @Mock
    private SignatureRepository signatureRepository; // Mockito cria um falso

    @InjectMocks
    private CryptoSignatureService service; // injeta o mock acima

    @BeforeEach
    void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void signWithMLDSA_deveRetornarAssinaturaValida() throws Exception {
        // Mockito faz o save() retornar a própria entidade sem tocar no banco
        when(signatureRepository.save(any())).thenAnswer(i -> i.getArgument(0));

        DocumentEntity doc = new DocumentEntity();
        doc.setContent("contrato".getBytes());

        SignatureEntity resultado = service.signWithMLDSA(doc);

        assertTrue(resultado.isValid());
        assertTrue(resultado.getSignatureBytes().length > 2000);
    }

	@Test
	void validarECDSA_dadosAlterados_deveRetornarFalse() throws Exception {
		KeyPair par = service.generateKeyECDSA();
		byte[] original = "contrato original".getBytes();
		byte[] adulterado = "contrato ADULTERADO".getBytes();

		Signature s = Signature.getInstance("SHA256withECDSA", "BC");
		s.initSign(par.getPrivate());
		s.update(original);
		byte[] assinatura = s.sign();

		// valida com dados adulterados — deve ser false
		assertFalse(service.isValidECDSA(
				adulterado, assinatura, par.getPublic().getEncoded()));
	}

	@Test
	void validarMLDSA_dadosAlterados_deveFalharBoundCheck() throws Exception {
		KeyPair par = service.generateKeyMLDSA();
		byte[] original = "contrato original".getBytes();
		byte[] adulterado = "contrato ADULTERADO".getBytes();

		Signature s = Signature.getInstance("ML-DSA", "BC");
		s.initSign(par.getPrivate());
		s.update(original);
		byte[] assinatura = s.sign();

		// Bound Check falha internamente — deve ser false
		assertFalse(service.isValidMLDSA(
				adulterado, assinatura, par.getPublic().getEncoded()));
	}

}
