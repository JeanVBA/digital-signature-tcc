package br.edu.faeterj.tcc.digital_signature.domain.Utils;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Polynomial {
    
    // Parâmetros oficiais do NIST FIPS 204 (ML-DSA)
    static final int q = 8380417;
    static final int n = 256;
    
    int[] coefficients;

    // 1. Construtor padrão (cria polinômio zerado de tamanho 256)
    public Polynomial() {
        this.coefficients = new int[n];
    }

    // 2. Construtor para Mock de dados (preenche o início e deixa o resto zerado)
    public Polynomial(int... mockCoeffs) {
        this.coefficients = new int[n];
        for (int i = 0; i < mockCoeffs.length && i < n; i++) {
            this.coefficients[i] = mockCoeffs[i];
        }
    }

    // Soma polinomial módulo q
    public Polynomial sum(Polynomial outro) {
        Polynomial result = new Polynomial();
        for (int i = 0; i < n; i++) {
            result.coefficients[i] = (this.coefficients[i] + outro.coefficients[i]) % q;
            // Ajusta se ficar negativo
            if (result.coefficients[i] < 0) {
                result.coefficients[i] += q;
            }
        }
        return result;
    }

    // 3. VERDADEIRA Multiplicação Polinomial no Anel R_q = Z_q[X] / (X^n + 1)
    public Polynomial multiplicate(Polynomial other) { 
        Polynomial result = new Polynomial();
        
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < n; j++) {
                int potencia = (i + j) % n;
                long multiplicacao = (long) this.coefficients[i] * other.coefficients[j];
                
                // Redução polinomial: X^n = -1. 
                // Se a soma das potências passar de n-1, o sinal inverte!
                if (i + j >= n) {
                    result.coefficients[potencia] = (int) ((result.coefficients[potencia] - multiplicacao) % q);
                } else {
                    result.coefficients[potencia] = (int) ((result.coefficients[potencia] + multiplicacao) % q);
                }
            }
        }
        
        // Ajusta coeficientes negativos para o módulo q positivo
        for (int i = 0; i < n; i++) {
            if (result.coefficients[i] < 0) {
                result.coefficients[i] += q;
            }
        }
        
        return result;
    }

    @Override
    public String toString() {
        if (coefficients == null || coefficients.length == 0) {
            return "0";
        }

        StringBuilder sb = new StringBuilder();
        boolean isPrimeiroTermo = true;

        for (int i = coefficients.length - 1; i >= 0; i--) {
            int c = coefficients[i];
            
            if (c == 0) continue; 

            if (!isPrimeiroTermo) {
                sb.append(c > 0 ? " + " : " - ");
            } else {
                if (c < 0) sb.append("-");
                isPrimeiroTermo = false;
            }

            int valorAbsoluto = Math.abs(c);
            
            if (valorAbsoluto != 1 || i == 0) {
                sb.append(valorAbsoluto);
            }

            if (i > 0) {
                sb.append("x");
                if (i > 1) {
                    sb.append("^").append(i);
                }
            }
        }

        return isPrimeiroTermo ? "0" : sb.toString();
    }
}