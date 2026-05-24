package br.edu.faeterj.tcc.digital_signature.domain.Utils;

import java.math.BigInteger;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Point {

    BigInteger x;
    BigInteger y;

    public Point(BigInteger x, BigInteger y) {
        this.x = x;
        this.y = y;
    }

    public Point() {
        this.x = BigInteger.ONE;
        this.y = BigInteger.ONE;
    }

}
