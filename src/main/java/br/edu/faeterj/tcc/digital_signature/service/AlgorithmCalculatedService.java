package br.edu.faeterj.tcc.digital_signature.service;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.springframework.stereotype.Service;
import br.edu.faeterj.tcc.digital_signature.domain.Utils.Point;
import br.edu.faeterj.tcc.digital_signature.domain.Utils.Polynomial;

@Service
public class AlgorithmCalculatedService {

    // Helper classes Point e Polynomial mantidas conforme o seu código...

    /**
     * Salva o conteúdo HTML gerado em um arquivo físico no disco.
     */
    private String gerarArquivoFisico(String nomeArquivo, String conteudoHtml) {
        try {
            // Salva na raiz do projeto ou na pasta especificada
            Path path = Paths.get(nomeArquivo);
            Files.writeString(path, conteudoHtml);
            return path.toAbsolutePath().toString();
        } catch (IOException e) {
            throw new RuntimeException("Erro ao salvar o arquivo HTML: " + e.getMessage(), e);
        }
    }

    public String calculatedPublicKeyMLDSA(Polynomial[][] A, Polynomial[] s1, Polynomial[] s2, int k, int l) {
        StringBuilder html = new StringBuilder();
        
        // Cabeçalho HTML com MathJax
        html.append("<!DOCTYPE html><html lang='pt-BR'><head><meta charset='UTF-8'>");
        html.append("<title>Relatório Matemático: ML-DSA</title>");
        html.append("<script src='https://polyfill.io/v3/polyfill.min.js?features=es6'></script>");
        html.append("<script id='MathJax-script' async src='https://cdn.jsdelivr.net/npm/mathjax@3/es5/tex-mml-chtml.js'></script>");
        html.append("<style>");
        html.append("body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: #333; line-height: 1.6; max-width: 900px; margin: 40px auto; padding: 20px; }");
        html.append(".step { background: #f8f9fa; padding: 20px; border-left: 5px solid #0d6efd; margin-bottom: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.05); }");
        html.append(".formula { text-align: center; font-size: 1.2em; margin: 15px 0; padding: 10px; background: #fff; border: 1px dashed #ced4da; overflow-x: auto; }");
        html.append("</style></head><body>");

        html.append("<h2>ML-DSA: Cálculo da Chave Pública Expandida (M-LWE)</h2>");
        html.append("<p>A equação estrutural para derivar a chave pública (<strong>t</strong>) é:</p>");
        html.append("<div class='formula'>$$ \\mathbf{t} = \\mathbf{A} \\mathbf{s}_1 + \\mathbf{s}_2 \\pmod q $$</div>");

        html.append("<h3>Passo a Passo da Operação Matricial:</h3>");
        
        Polynomial[] t = new Polynomial[k];
        
        for (int i = 0; i < k; i++) {
            t[i] = new Polynomial(); 
            
            html.append("<div class='step'>");
            html.append("<h4>Calculando a linha ").append(i).append(" do vetor resultante \\(\\mathbf{t}\\)</h4>");
            
            for (int j = 0; j < l; j++) {
                // Aqui os valores REAIS dos polinômios são injetados via toString() do seu objeto Polynomial
                html.append("<p>Multiplicando a matriz pelo vetor secreto no índice [").append(i).append("][").append(j).append("]:</p>");
                html.append("<div class='formula'>$$ \\mathbf{A}[").append(i).append("][").append(j).append("] = ").append(A[i][j].toString()).append(" $$</div>");
                html.append("<div class='formula'>$$ \\mathbf{s}_1[").append(j).append("] = ").append(s1[j].toString()).append(" $$</div>");
                
                Polynomial multiplicacao = A[i][j].multiplicate(s1[j]);
                html.append("<div class='formula'>$$ \\text{Resultado Parcial} = ").append(multiplicacao.toString()).append(" $$</div>");
                
                t[i] = t[i].sum(multiplicacao);
            }
            
            html.append("<p>Somando o polinômio de erro pequeno \\(\\mathbf{s}_2[").append(i).append("]\\):</p>");
            html.append("<div class='formula'>$$ \\mathbf{s}_2[").append(i).append("] = ").append(s2[i].toString()).append(" $$</div>");
            
            t[i] = t[i].sum(s2[i]); 
            
            html.append("<p><strong>Polinômio final da linha ").append(i).append(" (\\(\\mathbf{t}[").append(i).append("]\\)):</strong></p>");
            html.append("<div class='formula'>$$ \\mathbf{t}[").append(i).append("] = ").append(t[i].toString()).append(" $$</div>");
            html.append("</div>");
        }

        html.append("</body></html>");
        
        // Salva o arquivo no disco e retorna o caminho absoluto onde foi salvo
        return gerarArquivoFisico("relatorio_ml_dsa_calculo.html", html.toString()); 
    }

    public String calculatedSignatureECDSA(BigInteger d, BigInteger k, BigInteger e) {
        BigInteger n = new BigInteger("115792089237316195423570985008687907852837564279074904382605163141518161494337"); 
        Point G = new Point(BigInteger.valueOf(5), BigInteger.valueOf(1));

        Point R = multiplicatePoint(G, k);
        BigInteger r = R.getX().mod(n);
        BigInteger kInverso = k.modInverse(n);
        BigInteger dr = d.multiply(r).mod(n);
        BigInteger eMaisDr = e.add(dr).mod(n);
        BigInteger s = kInverso.multiply(eMaisDr).mod(n);

        StringBuilder html = new StringBuilder();
        
        html.append("<!DOCTYPE html><html lang='pt-BR'><head><meta charset='UTF-8'>");
        html.append("<title>Relatório Matemático: ECDSA</title>");
        html.append("<script src='https://polyfill.io/v3/polyfill.min.js?features=es6'></script>");
        html.append("<script id='MathJax-script' async src='https://cdn.jsdelivr.net/npm/mathjax@3/es5/tex-mml-chtml.js'></script>");
        html.append("<style>");
        html.append("body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: #333; line-height: 1.6; max-width: 900px; margin: 40px auto; padding: 20px; }");
        html.append(".step { background: #f8f9fa; padding: 20px; border-left: 5px solid #198754; margin-bottom: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.05); }");
        html.append(".formula { text-align: center; font-size: 1.2em; margin: 15px 0; padding: 10px; background: #fff; border: 1px dashed #ced4da; overflow-x: auto; }");
        html.append(".hex { font-family: monospace; color: #d63384; word-break: break-all; background: #fff; padding: 2px 5px; border: 1px solid #dee2e6; }");
        html.append("</style></head><body>");

        html.append("<h2>ECDSA: Geração de Assinatura Digital (r, s)</h2>");
        
        html.append("<div class='step'><h3>1. Parâmetros e Variáveis de Entrada</h3>");
        html.append("<p>Ordem da Curva \\( (n) \\): <span class='hex'>").append(n.toString(16)).append("</span></p>");
        html.append("<p>Hash da Mensagem \\( (e) \\): <span class='hex'>").append(e.toString(16)).append("</span></p>");
        html.append("<p>Chave Privada \\( (d) \\): <span class='hex'>").append(d.toString(16)).append("</span></p>");
        html.append("<p>Nonce Efêmero \\( (k) \\): <span class='hex'>").append(k.toString(16)).append("</span></p>");
        html.append("</div>");

        html.append("<div class='step'><h3>2. Calculando o Ponto R na Curva</h3>");
        html.append("<p><strong>Valores aplicados:</strong></p>");
        // CORREÇÃO AQUI: Usando \mathtt{} do LaTeX para a formatação monospace ao invés de span HTML!
        html.append("<div class='formula'>$$ R = \\mathtt{").append(k.toString(16)).append("} \\times G $$</div>");
        html.append("<p><strong>Ponto Resultante (R):</strong> (x = <span class='hex'>").append(R.getX().toString(16)).append("</span>, y = <span class='hex'>").append(R.getY().toString(16)).append("</span>)</p>");
        html.append("</div>");

        html.append("<div class='step'><h3>3. Extraindo a coordenada 'r'</h3>");
        html.append("<p><strong>Valores aplicados:</strong></p>");
        html.append("<div class='formula'>$$ r = \\mathtt{").append(R.getX().toString(16)).append("} \\pmod{\\mathtt{").append(n.toString(16)).append("}} $$</div>");
        html.append("<p><strong>Resultado \\( r \\):</strong> <span class='hex'>").append(r.toString(16)).append("</span></p>");
        html.append("</div>");

        html.append("<div class='step'><h3>4. Calculando a componente 's'</h3>");
        html.append("<p>Cálculos intermediários:</p>");
        html.append("<ul>");
        html.append("<li>Inverso de k \\( (k^{-1} \\pmod n) \\): <span class='hex'>").append(kInverso.toString(16)).append("</span></li>");
        html.append("<li>Multiplicação \\( (d \\cdot r \\pmod n) \\): <span class='hex'>").append(dr.toString(16)).append("</span></li>");
        html.append("<li>Soma das chaves e do hash \\( (e + d \\cdot r \\pmod n) \\): <span class='hex'>").append(eMaisDr.toString(16)).append("</span></li>");
        html.append("</ul>");
        
        html.append("<p><strong>Valores aplicados:</strong></p>");
        html.append("<div class='formula'>$$ s = \\mathtt{").append(kInverso.toString(16)).append("} \\cdot (\\mathtt{").append(e.toString(16)).append("} + \\mathtt{").append(dr.toString(16)).append("}) \\pmod{\\mathtt{").append(n.toString(16)).append("}} $$</div>");
        html.append("<p><strong>Resultado final \\( s \\):</strong> <span class='hex'>").append(s.toString(16)).append("</span></p>");
        html.append("</div>");

        html.append("</body></html>");
        
        // Salva o arquivo no disco e retorna o caminho absoluto onde foi salvo
        return gerarArquivoFisico("relatorio_ecdsa_calculo.html", html.toString()); 
    }

    private Point multiplicatePoint(Point base, BigInteger escalar) { 
        return new Point(new BigInteger("123456789"), new BigInteger("987654321")); 
    }
}