package br.edu.faeterj.tcc.digital_signature.domain.Utils;

public class Polynomial {
    static final int q = 8380417;
    static final int n = 256;
    int[] coefficients = new int[n]; 

    public Polynomial sum(Polynomial outro) {
        Polynomial result = new Polynomial();
        for (int i = 0; i < n; i++) {
            result.coefficients[i] = (this.coefficients[i] + outro.coefficients[i]) % q;
        }
        return result;
    }

    public Polynomial multiplicate(Polynomial other) { 
        return new Polynomial();
    }
}
