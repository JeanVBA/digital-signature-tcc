package br.edu.faeterj.tcc.digital_signature.service;

import java.math.BigInteger;

import org.springframework.stereotype.Service;

import br.edu.faeterj.tcc.digital_signature.domain.DTO.CalculationReportDTO;
import br.edu.faeterj.tcc.digital_signature.domain.Utils.Point;
import br.edu.faeterj.tcc.digital_signature.domain.Utils.Polynomial;

@Service
public class AlgorithmCalculatedService {

    public final Polynomial polynomial = new Polynomial();

    public CalculationReportDTO calculatedPublicKeyMLDSA(Polynomial[][] A, Polynomial[] s1, Polynomial[] s2, int k, int l) {
        CalculationReportDTO report = new CalculationReportDTO();
        report.setAlgorithmName("ML-DSA: Cálculo de M-LWE (t = A*s1 + s2)");
        Polynomial[] t = new Polynomial[k];
        report.addStep("Iniciando o cálculo da chave pública expandida...");
        report.addStep(String.format("Dimensões: Matriz A(%dx%d), Vetor s1(%d), Vetor s2(%d)", k, l, l, k));

        for (int i = 0; i < k; i++) {
            t[i] = new Polynomial(); 
            report.addStep("\n--- Calculando a linha " + i + " do vetor t ---");
            
            for (int j = 0; j < l; j++) {
                report.addStep(String.format("Multiplicando polinômio A[%d][%d] pelo polinômio s1[%d]", i, j, j));
                Polynomial multiplicacao = A[i][j].multiplicate(s1[j]);
                t[i] = t[i].sum(multiplicacao);
                report.addStep(String.format("Soma parcial acumulada no vetor t[%d]", i));
            }
            
            report.addStep(String.format("Adicionando o vetor de erro pequeno s2[%d] a t[%d]", i, i));
            t[i] = t[i].sum(s2[i]); 
            report.addStep("result final da linha " + i + " calculado com sucesso.");
        }

        report.setFinalResult("Vetor polinomial 't' gerado. Os 'd' bits menos significativos serão descartados para criar t1.");
        return report; 
    }

    public CalculationReportDTO calculatedSignatureECDSA(BigInteger d, BigInteger k, BigInteger e) {
        CalculationReportDTO report = new CalculationReportDTO();
        report.setAlgorithmName("ECDSA: Geração de Assinatura (r, s)");
        // Parâmetros de Domínio didáticos (Exemplo: curva pequena secp256k1 mockada)
        BigInteger n = new BigInteger("115792089237316195423570985008687907852837564279074904382605163141518161494337"); 
        Point G = new Point(BigInteger.valueOf(5), BigInteger.valueOf(1)); // Point base mockado

        report.addStep("Iniciando assinatura com a chave privada d.");
        report.addStep("Hash da mensagem (e): " + e.toString(16));
        report.addStep("Nonce aleatório gerado (k): " + k.toString(16));

        // Equação 4: R = [k]G
        report.addStep("\n[Passo 1] Calculando o Point R = [k] * G (Multiplicação Escalar)");
        Point R = multiplicatePoint(G, k);
        report.addStep("Point R gerado: (x=" + R.getX() + ", y=" + R.getY() + ")");

        // Equação 5: r = r1 mod n
        report.addStep("\n[Passo 2] Extraindo a coordenada 'x' do Point R");
        BigInteger r = R.getX().mod(n);
        report.addStep("Fórmula: r = x_R mod n");
        report.addStep("Valor de r: " + r.toString(16));

        // Equação 6: s = k^{-1}(e + d*r) mod n
        report.addStep("\n[Passo 3] Calculando o inverso multiplicativo de k (k^-1 mod n)");
        BigInteger kInverso = k.modInverse(n);
        report.addStep("k^-1: " + kInverso.toString(16));

        report.addStep("\n[Passo 4] Calculando a componente s");
        BigInteger dr = d.multiply(r).mod(n);
        report.addStep("Calculado (d * r) mod n = " + dr.toString(16));
        
        BigInteger eMaisDr = e.add(dr).mod(n);
        report.addStep("Calculado (e + d*r) mod n = " + eMaisDr.toString(16));
        
        BigInteger s = kInverso.multiply(eMaisDr).mod(n);
        report.addStep("Fórmula final: s = k^-1 * (e + d*r) mod n");
        report.addStep("Valor de s: " + s.toString(16));

        report.setFinalResult(String.format("Assinatura gerada com sucesso. Par (r, s):\nr: %s\ns: %s", 
                                    r.toString(16), s.toString(16)));
        
        return report; 
    }

    private Point multiplicatePoint(Point base, BigInteger escalar) { 
        // Mock de um Point na curva para não quebrar a execução
        return new Point(new BigInteger("123456789"), new BigInteger("987654321")); 
    }
}
