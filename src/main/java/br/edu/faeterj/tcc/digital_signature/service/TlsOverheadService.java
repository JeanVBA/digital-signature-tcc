package br.edu.faeterj.tcc.digital_signature.service;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Comparator;
import java.util.IntSummaryStatistics;

import org.springframework.stereotype.Service;

import br.edu.faeterj.tcc.digital_signature.domain.DocumentEntity;
import br.edu.faeterj.tcc.digital_signature.domain.SignatureEntity;
import br.edu.faeterj.tcc.digital_signature.repository.DocumentRepository;
import br.edu.faeterj.tcc.digital_signature.repository.SignatureRepository;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class TlsOverheadService {

  private final SignatureRepository signatureRepository;
  private final DocumentRepository documentRepository;
  private final NetworkMeasurementService networkService;

  public Map<String, Object> calculatedRealMetrics() {
    List<SignatureEntity> allSignatures = signatureRepository.findAll();
    if (allSignatures.isEmpty()) {
      return Map.of("erro", "Nenhuma assinatura encontrada.");
    }

    int mtuReal = networkService.discoverRealMTU();
    Map<String, Object> latencia = networkService.measureLatencyTCP();
    double rttMs = latencia.containsKey("latenciaMediaMs")
        ? (double) latencia.get("latenciaMediaMs")
        : 1.0;
    int latenciaPorPacoteMicros = (int) (rttMs * 1000);

    Map<String, List<SignatureEntity>> porAlgoritmo = allSignatures.stream()
        .collect(Collectors.groupingBy(SignatureEntity::getTypeAlgorithm));

    Map<String, Object> result = new LinkedHashMap<>();

    result.put("condicoesDeRede", Map.of(
        "mtuReal", mtuReal,
        "rttMedioMs", rttMs,
        "latenciaPorPacoteMicros", latenciaPorPacoteMicros,
        "hostMedido", latencia.getOrDefault("hostMedido", "N/A"),
        "amostras", latencia.getOrDefault("amostras", 0),
        "jitterMs", latencia.getOrDefault("jitterMs", 0.0)));

    porAlgoritmo.forEach((algoritmo, lista) -> result.put(algoritmo,
        calculatedMetricsByGroup(algoritmo, lista, mtuReal, latenciaPorPacoteMicros)));

    if (porAlgoritmo.containsKey("ECDSA") && porAlgoritmo.containsKey("ML-DSA-44")) {
      result.put("comparative", calculatedComparative(
          porAlgoritmo.get("ECDSA"),
          porAlgoritmo.get("ML-DSA-44"),
          mtuReal, rttMs));
    }

    result.put("porDocumento", calculatedPerDocument(allSignatures, mtuReal, rttMs));
    result.put("totalDocuments", documentRepository.count());
    result.put("totalSignatures", allSignatures.size());
    return result;
  }

  private Map<String, Object> calculatedMetricsByGroup(
      String algorithm, List<SignatureEntity> lista,
      int mtu, int latenciaPorPacoteMicros) {

    IntSummaryStatistics statsSig = lista.stream()
        .collect(Collectors.summarizingInt(s -> s.getSignatureBytes().length));
    IntSummaryStatistics statsKey = lista.stream()
        .collect(Collectors.summarizingInt(s -> s.getPublicKeyBytes().length));

    int mediaTotal = (int) (statsSig.getAverage() + statsKey.getAverage());
    int maxTotal = statsSig.getMax() + statsKey.getMax();
    int minTotal = statsSig.getMin() + statsKey.getMin();
    int pacotes = calculatedPackets(mediaTotal, mtu);

    long comFragmentacao = lista.stream()
        .filter(s -> s.getPublicKeyBytes().length + s.getSignatureBytes().length > mtu)
        .count();

    boolean tamanhoFixo = maxTotal == minTotal;

    Map<String, Object> m = new LinkedHashMap<>();
    m.put("algorithm", algorithm);
    m.put("totalSignatures", lista.size());
    m.put("averageSignatureBytes", (int) statsSig.getAverage());
    m.put("averagePublicKeyBytes", (int) statsKey.getAverage());
    m.put("averageTotalHandshakeBytes", mediaTotal);
    m.put("maxTotalHandshakeBytes", maxTotal);
    m.put("minTotalHandshakeBytes", minTotal);
    m.put("mtuUsado", mtu);
    m.put("averagePacketsNeeded", pacotes);
    m.put("tamanhoFixoPorAlgoritmo", tamanhoFixo);
    m.put("percentageWithFragmentation",
        String.format("%.2f%%", (comFragmentacao * 100.0) / lista.size()));

    if (tamanhoFixo) {
      m.put("notaFragmentacao",
          comFragmentacao == lista.size()
              ? String.format("100%% das assinaturas fragmentam — tamanho fixo (%d bytes) sempre excede o MTU real de %d bytes.", maxTotal, mtu)
              : String.format("0%% das assinaturas fragmentam — tamanho fixo (%d bytes) está abaixo do MTU real de %d bytes.", maxTotal, mtu));
    }

    m.put("extraLatencyAverageMicros", Math.max(0, pacotes - 1) * latenciaPorPacoteMicros);
    m.put("latenciaBaseadaEmMedicaoReal", true);

    return m;
  }

  private Map<String, Object> calculatedComparative(
      List<SignatureEntity> listaEc, List<SignatureEntity> listaMl,
      int mtu, double rttMs) {

    double mediaEc = listaEc.stream()
        .mapToInt(s -> s.getPublicKeyBytes().length + s.getSignatureBytes().length)
        .average().orElse(1);
    double mediaMl = listaMl.stream()
        .mapToInt(s -> s.getPublicKeyBytes().length + s.getSignatureBytes().length)
        .average().orElse(0);

    int pacotesEc = calculatedPackets((int) mediaEc, mtu);
    int pacotesMl = calculatedPackets((int) mediaMl, mtu);

    double latenciaEcMs = pacotesEc * rttMs;
    double latenciaMlMs = pacotesMl * rttMs;

    Map<String, Object> c = new LinkedHashMap<>();
    c.put("averageOverheadECDSABytes", (int) mediaEc);
    c.put("averageOverheadMLDSABytes", (int) mediaMl);
    c.put("differenceAverageBytes", (int) (mediaMl - mediaEc));
    c.put("increaseFactorOverhead", String.format("%.2fx", mediaMl / mediaEc));
    c.put("extraPacketsAverageMLDSA", pacotesMl - pacotesEc);
    c.put("latenciaHandshakeECDSAms", latenciaEcMs);
    c.put("latenciaHandshakeMLDSAms", latenciaMlMs);
    c.put("latenciaExtraRealMs", latenciaMlMs - latenciaEcMs);
    c.put("fatorAumentoLatencia", String.format("%.1fx", latenciaMlMs / latenciaEcMs));
    c.put("mtuUsadoNaAnalise", mtu);
    c.put("rttUsadoMs", rttMs);
    c.put("conclusion", String.format(
        "Com MTU real de %d bytes e RTT médio de %.2fms, o handshake ML-DSA-44 exige %d pacote(s) TCP contra %d do ECDSA, resultando em %.2fms de latência extra por conexão (%.1fx mais lento).",
        mtu, rttMs, pacotesMl, pacotesEc, latenciaMlMs - latenciaEcMs, latenciaMlMs / latenciaEcMs));
    return c;
  }

  private int calculatedPackets(int totalBytes, int mtu) {
    return (int) Math.ceil((double) totalBytes / mtu);
  }

  private List<Map<String, Object>> calculatedPerDocument(List<SignatureEntity> all, int mtu, double rttMs) {
    Map<Long, List<SignatureEntity>> perDoc = all.stream()
        .collect(Collectors.groupingBy(s -> s.getDocument().getId()));

    return perDoc.entrySet().stream().map(entry -> {
        List<SignatureEntity> sigs = entry.getValue();
        DocumentEntity doc = sigs.get(0).getDocument();

        Map<String, List<SignatureEntity>> porAlg = sigs.stream()
            .collect(Collectors.groupingBy(SignatureEntity::getTypeAlgorithm));

        Map<String, Object> docData = new LinkedHashMap<>();
        docData.put("documentId", doc.getId());
        docData.put("fileName", doc.getName());
        docData.put("fileType", doc.getType());
        docData.put("fileSizeBytes", doc.getContent().length);
        docData.put("totalSignatures", sigs.size());

        Map<String, Object> porAlgMetrics = new LinkedHashMap<>();
        porAlg.forEach((alg, algSigs) -> {
            SignatureEntity exemplo = algSigs.get(0);
            int unitSigBytes = exemplo.getSignatureBytes().length;
            int unitKeyBytes = exemplo.getPublicKeyBytes().length;
            int unitHandshake = unitSigBytes + unitKeyBytes;
            int unitPackages = (int) Math.ceil((double) unitHandshake / mtu);
            double unitLat = Math.max(0, unitPackages - 1) * rttMs;

            int acumSigBytes = algSigs.stream().mapToInt(s -> s.getSignatureBytes().length).sum();
            int acumKeyBytes = algSigs.stream().mapToInt(s -> s.getPublicKeyBytes().length).sum();
            int acumHandshake = acumSigBytes + acumKeyBytes;

            int sumRealPackages = unitPackages * algSigs.size();
            double acumLatReal = unitLat * algSigs.size();

            int emailUnitBytes = (int) Math.ceil(unitHandshake * 4.0 / 3);
            int emailAcumBytes = (int) Math.ceil(acumHandshake * 4.0 / 3);

            Map<String, Object> m = new LinkedHashMap<>();
            m.put("totalSignatures", algSigs.size());
            m.put("handshake_unitario", Map.of(
                "description", "Custo de UM handshake TLS com este algoritmo",
                "signatureBytes", unitSigBytes,
                "publicKeyBytes", unitKeyBytes,
                "totalBytes", unitHandshake,
                "packagesTCP", unitPackages,
                "fragmentationIP", unitHandshake > mtu,
                "latencyExtraMs", unitLat,
                "emailBase64Bytes", emailUnitBytes
            ));

            m.put("handshake_acumulado", Map.of(
                "description", algSigs.size() + " handshakes sequenciais (todas as assinaturas)",
                "totalSignatureBytes", acumSigBytes,
                "totalPublicKeyBytes", acumKeyBytes,
                "totalHandshakeBytes", acumHandshake,
                "packagesTotalTCP", sumRealPackages,
                "latencyExtraMsTotal", acumLatReal,
                "emailBase64Bytes", emailAcumBytes,
                "nota", "Cada handshake ocorre separadamente — " + unitPackages + " pacote(s) × " + algSigs.size() + " assinaturas"
            ));

            porAlgMetrics.put(alg, m);
        });

        docData.put("porAlgoritmo", porAlgMetrics);

        int docBytes = doc.getContent().length;
        int allSigBytes = sigs.stream()
            .mapToInt(s -> s.getSignatureBytes().length + s.getPublicKeyBytes().length)
            .sum();
        int emailCompleto = (int) Math.ceil((docBytes + allSigBytes) * 4.0 / 3);
        int packageMail = (int) Math.ceil((double) emailCompleto / mtu);
        double latMail = Math.max(0, packageMail - 1) * rttMs;

        docData.put("envio_email_completo", Map.of(
            "description", "Documento + todas as assinaturas em um único e-mail",
            "fileSizeBytes", docBytes,
            "allSignaturesBytes", allSigBytes,
            "totalEmailBase64Bytes", emailCompleto,
            "packagesTCP", packageMail,
            "latencyExtraMs", latMail
        ));

        return docData;
    })
    .sorted(Comparator.comparingLong(m -> (Long) m.get("documentId")))
    .collect(Collectors.toList());
  }

  public String generatedHtmlGrafics(Map<String, Object> dados) {
    String json;
    try {
      json = new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(dados);
    } catch (Exception e) {
      json = "{}";
    }

    String html = """
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
          <meta charset="UTF-8"/>
          <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
          <title>PQC — Análise de Overhead de Rede</title>
          <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
          <style>
            @import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=DM+Sans:wght@300;400;500;600&display=swap');
            :root {
              --bg:#0a0e1a; --bg2:#111827; --bg3:#1a2235; --border:#1f2d45;
              --ecdsa:#00d4aa; --ecdsa-dim:rgba(0,212,170,0.12);
              --mldsa:#f97316; --mldsa-dim:rgba(249,115,22,0.12);
              --text:#e2e8f0; --muted:#64748b; --accent:#3b82f6;
            }
            *{box-sizing:border-box;margin:0;padding:0;}
            body{background:var(--bg);color:var(--text);font-family:'DM Sans',sans-serif;padding:2rem;}
            h1{font-family:'Space Mono',monospace;font-size:clamp(1.3rem,3vw,1.9rem);line-height:1.2;}
            h1 span{color:var(--accent);}
            h2{font-family:'Space Mono',monospace;font-size:0.85rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:2rem 0 1rem;}
            h3{font-family:'Space Mono',monospace;font-size:0.75rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin-bottom:.75rem;display:flex;align-items:center;gap:8px;}
            h3::before{content:'';display:inline-block;width:7px;height:7px;border-radius:2px;background:var(--accent);}
            header{display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:1rem;margin-bottom:2rem;}
            .badge-live{display:inline-flex;align-items:center;gap:6px;background:var(--bg3);border:1px solid var(--border);border-radius:999px;padding:5px 12px;font-size:.75rem;font-family:'Space Mono',monospace;color:var(--muted);}
            .dot{width:7px;height:7px;border-radius:50%;background:var(--ecdsa);animation:pulse 1.8s ease-in-out infinite;}
            @keyframes pulse{0%,100%{opacity:1;transform:scale(1);}50%{opacity:.4;transform:scale(.7);}}
            
            .kpi-container-title { font-family:'Space Mono',monospace; font-size:0.8rem; color:var(--accent); margin-bottom:0.5rem; text-transform:uppercase;}
            .kpi-section { background: rgba(31,45,69,0.2); border: 1px dashed var(--border); border-radius:14px; padding:1rem; margin-bottom:1.5rem; }
            .kpi-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:.85rem;}
            .kpi{background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:1rem 1.25rem;position:relative;overflow:hidden;}
            .kpi::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;}
            .kpi.net::before{background:var(--accent);} .kpi.ec::before{background:var(--ecdsa);} .kpi.ml::before{background:var(--mldsa);} .kpi.cmp::before{background:#a855f7;}
            .kpi label{font-size:.68rem;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);font-family:'Space Mono',monospace;}
            .kpi .val{font-size:1.4rem;font-weight:600;line-height:1.2;margin-top:4px;word-break:break-all;}
            .kpi.ec .val{color:var(--ecdsa);} .kpi.ml .val{color:var(--mldsa);} .kpi.net .val{color:var(--accent);} .kpi.cmp .val{color:#a855f7;}
            .kpi .sub{font-size:.7rem;color:var(--muted);margin-top:2px;}
            
            .charts-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(450px,1fr));gap:1.1rem;margin-bottom:1.1rem;}
            .chart-card{background:var(--bg2);border:1px solid var(--border);border-radius:14px;padding:1.35rem;}
            .chart-card.full{grid-column:1/-1;}
            .banner{background:rgba(249,115,22,.08);border:1px solid rgba(249,115,22,.3);border-radius:10px;padding:.85rem 1.25rem;display:flex;align-items:center;gap:10px;margin-bottom:1.1rem;font-size:.85rem;color:#fed7aa;}
            
            .doc-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:1rem;margin-bottom:1.5rem;}
            .doc-card{background:var(--bg2);border:1px solid var(--border);border-radius:14px;padding:1.25rem;}
            .doc-name{font-family:'Space Mono',monospace;font-size:.85rem;color:var(--text);margin-bottom:.75rem;word-break:break-all;border-bottom:1px solid var(--border);padding-bottom:4px;}
            .doc-row{display:flex;justify-content:space-between;font-size:.78rem;padding:5px 0;border-bottom:1px solid var(--border);}
            .doc-row:last-child{border-bottom:none;}
            .doc-row span:first-child{color:var(--muted);}
            .doc-row span:last-child{font-family:'Space Mono',monospace;font-size:.75rem;}
            .alg-tag{display:inline-block;font-size:.65rem;padding:2px 7px;border-radius:4px;font-family:'Space Mono',monospace;margin-bottom:6px;font-weight:bold;}
            .alg-tag.ec{background:var(--ecdsa-dim);color:var(--ecdsa);border:1px solid var(--ecdsa);}
            .alg-tag.ml{background:var(--mldsa-dim);color:var(--mldsa);border:1px solid var(--mldsa);}
            .frag-warn{color:#f97316;font-size:.7rem;margin-top:4px;font-family:'Space Mono',monospace;}
            
            table{width:100%;border-collapse:collapse;font-size:.8rem;margin-top:.5rem;}
            th{text-align:left;padding:10px;background:var(--bg3);color:var(--muted);font-family:'Space Mono',monospace;font-size:.7rem;text-transform:uppercase;letter-spacing:.05em;border:1px solid var(--border);}
            td{padding:10px;border:1px solid var(--border);color:var(--text);vertical-align:middle;}
            .tval{font-family:'Space Mono',monospace;font-size:.75rem;}
            footer{margin-top:2rem;padding-top:1rem;border-top:1px solid var(--border);font-size:.72rem;color:var(--muted);font-family:'Space Mono',monospace;display:flex;justify-content:space-between;flex-wrap:wrap;gap:6px;}
            #error-msg{display:none;background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);border-radius:10px;padding:1.5rem;color:#fca5a5;font-family:'Space Mono',monospace;font-size:.85rem;margin-bottom:1rem;}
          </style>
        </head>
        <body>
        <div id="error-msg"></div>
        <div id="app">
          <header>
            <div>
              <h1>PQC <span>//</span> Análise de Custo Real de Rede</h1>
              <p style="color:var(--muted);font-size:.875rem;margin-top:6px">Mapeamento de Sobrecarga: ECDSA vs ML-DSA-44</p>
            </div>
            <div class="badge-live"><div class="dot"></div><span id="lbl-total">Carregando métricas...</span></div>
          </header>

          <h2>Painel Executivo — Cards Principais (Métricas Reais)</h2>
          
          <div class="kpi-section">
            <div class="kpi-container-title">📡 Condições Atuais da Infraestrutura de Rede</div>
            <div class="kpi-grid" id="net-kpis"></div>
          </div>

          <div class="kpi-section">
            <div class="kpi-container-title">🔒 Algoritmo Legado: ECDSA (secp256r1)</div>
            <div class="kpi-grid" id="ecdsa-kpis"></div>
          </div>

          <div class="kpi-section">
            <div class="kpi-container-title">🚀 Algoritmo Pós-Quântico: ML-DSA-44 (NIST SP 800-204)</div>
            <div class="kpi-grid" id="mldsa-kpis"></div>
          </div>

          <div class="kpi-section">
            <div class="kpi-container-title">📊 Análise Comparativa da Transição Estática</div>
            <div class="kpi-grid" id="comp-kpis"></div>
          </div>

          <div class="banner" id="banner-frag" style="display:none">
            ⚠️ <span id="banner-txt"></span>
          </div>

          <h2>Gráficos de Escalonamento e Comparação Avançada</h2>
          <div class="charts-grid">
            <div class="chart-card full">
              <h3>Análise Criptográfica de Envio de E-mail Completo (Tamanho Total por Documento)</h3>
              <canvas id="c-email-completo"></canvas>
            </div>
            <div class="chart-card full">
              <h3>Mapeamento de Radar Espacial — Envio do E-mail Completo (Tamanho Real Base64 vs Pacotes TCP)</h3>
              <canvas id="c-radar-pqc"></canvas>
            </div>
          </div>

          <h2>Por Documento — Impacto Individual na Rede</h2>
          <div class="doc-grid" id="doc-grid"></div>

          <h2>Tabela Consolidada — Handshake Acumulado por Documento</h2>
          <div class="chart-card full" style="margin-bottom:1.5rem;overflow-x:auto">
            <table id="tabela-consolidada"></table>
          </div>

          <footer>
            <span>FAETERJ — TCC Criptografia Pós-Quântica</span>
            <span id="lbl-ts"></span>
          </footer>
        </div>

        <script>
        function kb(b){return b>=1024?(b/1024).toFixed(2)+' KB':b+' B';}
        function fmt(v){return typeof v==='number'?v.toLocaleString('pt-BR'):v;}

        function render(D) {
          if (!D || D.erro) {
            document.getElementById('error-msg').style.display = 'block';
            document.getElementById('error-msg').textContent = D ? D.erro : 'Dados inválidos.';
            return;
          }

          const net = D['condicoesDeRede'] || {};
          const ec = D['ECDSA'] || {};
          const ml = D['ML-DSA-44'] || {};
          const comp = D['comparative'] || {};
          const docs = D['porDocumento'] || [];

          document.getElementById('lbl-total').textContent = `${D.totalSignatures || 0} assinaturas / ${D.totalDocuments || 0} documentos`;
          document.getElementById('lbl-ts').textContent = 'Gerado em: ' + new Date().toLocaleString('pt-BR');

          // 1. RENDERIZAR CARD PRINCIPAL: CONDIÇÃO DE REDE
          document.getElementById('net-kpis').innerHTML = `
            <div class="kpi net"><label>Host Medido</label><div class="val">${net.hostMedido || 'N/A'}</div><div class="sub">Destino ICMP/TCP</div></div>
            <div class="kpi net"><label>MTU Real da Rede</label><div class="val">${net.mtuReal || 1500} bytes</div><div class="sub">Tamanho máximo do pacote</div></div>
            <div class="kpi net"><label>RTT Médio</label><div class="val">${net.rttMedioMs || 0} ms</div><div class="sub">Tempo de ida e volta</div></div>
            <div class="kpi net"><label>Jitter de Rede</label><div class="val">${Number(net.jitterMs || 0).toFixed(2)} ms</div><div class="sub">Variação estatística da latência</div></div>
          `;

          // 2. RENDERIZAR CARD PRINCIPAL: ECDSA
          document.getElementById('ecdsa-kpis').innerHTML = `
            <div class="kpi ec"><label>Média Chave Pública</label><div class="val">${kb(ec.averagePublicKeyBytes || 0)}</div><div class="sub">Bytes de chave pública</div></div>
            <div class="kpi ec"><label>Média Assinatura</label><div class="val">${kb(ec.averageSignatureBytes || 0)}</div><div class="sub">Bytes de assinatura estrutural</div></div>
            <div class="kpi ec"><label>Total Handshake TLS</label><div class="val">${kb(ec.averageTotalHandshakeBytes || 0)}</div><div class="sub">Média combinada por sessão</div></div>
            <div class="kpi ec"><label>Pacotes TCP Médios</label><div class="val">${ec.averagePacketsNeeded || 0} pkt</div><div class="sub">Sem fragmentação IP detectada</div></div>
          `;

          // 3. RENDERIZAR CARD PRINCIPAL: ML-DSA-44
          document.getElementById('mldsa-kpis').innerHTML = `
            <div class="kpi ml"><label>Média Chave Pública</label><div class="val">${kb(ml.averagePublicKeyBytes || 0)}</div><div class="sub">Bytes de chave pós-quântica</div></div>
            <div class="kpi ml"><label>Média Assinatura</label><div class="val">${kb(ml.averageSignatureBytes || 0)}</div><div class="sub">Bytes de assinatura estrutural</div></div>
            <div class="kpi ml"><label>Total Handshake TLS</label><div class="val">${kb(ml.averageTotalHandshakeBytes || 0)}</div><div class="sub">Média combinada por sessão</div></div>
            <div class="kpi ml"><label>Pacotes TCP Médios</label><div class="val">${ml.averagePacketsNeeded || 0} pkt</div><div class="sub">Fragmentação ativa em ${ml.percentageWithFragmentation || '0%'}</div></div>
          `;

          // 4. RENDERIZAR CARD PRINCIPAL: COMPARATIVO
          document.getElementById('comp-kpis').innerHTML = `
            <div class="kpi cmp"><label>Diferença Líquida</label><div class="val">+ ${kb(comp.differenceAverageBytes || 0)}</div><div class="sub">Overhead adicionado à camada</div></div>
            <div class="kpi cmp"><label>Fator de Ampliação</label><div class="val">${comp.increaseFactorOverhead || '1x'}</div><div class="sub">Multiplicação de volume físico</div></div>
            <div class="kpi cmp"><label>Pacotes Extras Necessários</label><div class="val">+ ${comp.extraPacketsAverageMLDSA || 0} TCP pkts</div><div class="sub">Por processo de handshake</div></div>
            <div class="kpi cmp"><label>Latência Extra Real</label><div class="val">${comp.latenciaExtraRealMs || 0} ms</div><div class="sub">Atraso induzido por fragmentos</div></div>
          `;

          // BANNER NOTA DE FRAGMENTAÇÃO
          if (ml.averageTotalHandshakeBytes > net.mtuReal) {
            document.getElementById('banner-frag').style.display = 'flex';
            document.getElementById('banner-txt').textContent = ml.notaFragmentacao || 'Aviso de fragmentação IP.';
          }

          // 5. POR DOCUMENTO — IMPACTO INDIVIDUAL (CORRIGIDO E SEGURO CONTRA CHAVES AUSENTES)
          const gridDocs = document.getElementById('doc-grid');
          gridDocs.innerHTML = '';
          
          docs.forEach(d => {
            let algosHtml = '';
            if (d.porAlgoritmo) {
              Object.entries(d.porAlgoritmo).forEach(([algName, algObj]) => {
                const isEc = algName === 'ECDSA';
                const cls = isEc ? 'ec' : 'ml';
                const unit = algObj.handshake_unitario || {};
                const acum = algObj.handshake_acumulado || {};

                algosHtml += `
                  <div style="margin-top: 0.85rem; padding-top: 0.5rem; border-top: 1px dashed var(--border);">
                    <span class="alg-tag ${cls}">${algName} (×${algObj.totalSignatures || 1})</span>
                    <div class="doc-row"><span>Handshake Unitário</span><span class="tval">${kb(unit.totalBytes || 0)}</span></div>
                    <div class="doc-row"><span>Pacotes TCP Unitário</span><span class="tval">${unit.packagesTCP || 0} pkt</span></div>
                    <div class="doc-row"><span>Total Handshake (${algObj.totalSignatures})</span><span class="tval">${kb(acum.totalHandshakeBytes || 0)}</span></div>
                    <div class="doc-row"><span>Acumulado no E-mail (B64)</span><span class="tval">${kb(acum.emailBase64Bytes || 0)}</span></div>
                    <div class="doc-row"><span>Latência Extra Total</span><span class="tval">${Number(acum.latencyExtraMsTotal || 0).toFixed(2)} ms</span></div>
                    ${unit.fragmentationIP ? `<div class="frag-warn">⚠ Fragmenta IP: Excede o MTU da rede</div>` : ''}
                  </div>
                `;
              });
            }

            const mailCompleto = d.envio_email_completo || {};

            gridDocs.innerHTML += `
              <div class="doc-card">
                <div class="doc-name">📄 ${d.fileName}</div>
                <div class="doc-row"><span>Tamanho Físico</span><span class="tval">${kb(d.fileSizeBytes || 0)}</span></div>
                <div class="doc-row"><span>Total Assinaturas</span><span class="tval">${d.totalSignatures || 0}</span></div>
                <div class="doc-row"><span>Mime Type</span><span class="tval" style="font-size:10px;">${d.fileType || 'N/A'}</span></div>
                <div class="doc-row" style="color:var(--accent); font-weight:500;"><span>E-mail Completo (Doc+Sigs B64)</span><span class="tval">${kb(mailCompleto.totalEmailBase64Bytes || 0)}</span></div>
                <div class="doc-row"><span>Pacotes TCP E-mail</span><span class="tval">${mailCompleto.packagesTCP || 0} pkt</span></div>
                <div class="doc-row"><span>Latência Extra E-mail</span><span class="tval">${Number(mailCompleto.latencyExtraMs || 0).toFixed(2)} ms</span></div>
                ${algosHtml}
              </div>
            `;
          });

          // 6. TABELA CONSOLIDADA: HANDSHAKE ACUMULADO POR DOCUMENTO
          let thHtml = `
            <tr>
              <th>ID</th>
              <th>Nome do Documento</th>
              <th>Algoritmo</th>
              <th>Assinaturas</th>
              <th>Chaves Acum.</th>
              <th>Assinaturas Acum.</th>
              <th>Total Handshake Acum.</th>
              <th>Pacotes TCP Totais</th>
              <th>E-mail Base64 Acum.</th>
              <th>Latência Extra Total</th>
            </tr>
          `;
          
          docs.forEach(d => {
            if (d.porAlgoritmo) {
              const totalAlgs = Object.keys(d.porAlgoritmo).length;
              Object.entries(d.porAlgoritmo).forEach(([algName, algObj], idx) => {
                const acum = algObj.handshake_acumulado || {};
                thHtml += `
                  <tr>
                    ${idx === 0 ? `<td rowspan="${totalAlgs}" class="tval">${d.documentId}</td>` : ''}
                    ${idx === 0 ? `<td rowspan="${totalAlgs}" style="font-weight:500;">${d.fileName}</td>` : ''}
                    <td><span class="alg-tag ${algName === 'ECDSA' ? 'ec' : 'ml'}">${algName}</span></td>
                    <td class="tval">${algObj.totalSignatures || 0}</td>
                    <td class="tval">${kb(acum.totalPublicKeyBytes || 0)}</td>
                    <td class="tval">${kb(acum.totalSignatureBytes || 0)}</td>
                    <td class="tval" style="font-weight:bold;">${kb(acum.totalHandshakeBytes || 0)}</td>
                    <td class="tval">${acum.packagesTotalTCP || 0} pkt</td>
                    <td class="tval">${kb(acum.emailBase64Bytes || 0)}</td>
                    <td class="tval" style="color:#f97316;">${Number(acum.latencyExtraMsTotal || 0).toFixed(2)} ms</td>
                  </tr>
                `;
              });
            }
          });
          document.getElementById('tabela-consolidada').innerHTML = thHtml;

          // 7. GRÁFICOS CHART.JS
          // Gráfico 1: Envio de E-mail Completo por Documento
          const labelsDocs = docs.map(d => d.fileName);
          const dataEmailCompleto = docs.map(d => d.envio_email_completo ? d.envio_email_completo.totalEmailBase64Bytes : 0);
          const dataDocPuro = docs.map(d => d.fileSizeBytes || 0);

          new Chart(document.getElementById('c-email-completo'), {
            type: 'bar',
            data: {
              labels: labelsDocs,
              datasets: [
                { label: 'Tamanho Físico Base do Documento (Bytes)', data: dataDocPuro, backgroundColor: 'rgba(59, 130, 246, 0.2)', borderColor: '#3b82f6', borderWidth: 2, borderRadius: 4 },
                { label: 'Tamanho Total com Envio Completo (Base64 + Assinaturas)', data: dataEmailCompleto, backgroundColor: 'rgba(168, 85, 247, 0.2)', borderColor: '#a855f7', borderWidth: 2, borderRadius: 4 }
              ]
            },
            options: {
              responsive: true,
              scales: {
                y: { beginAtZero: true, grid: { color: '#1f2d45' }, ticks: { callback: v => kb(v) } },
                x: { grid: { display: false }, ticks: { color: '#94a3b8' } }
              },
              plugins: { legend: { labels: { color: '#e2e8f0' } } }
            }
          });

          // Gráfico 2: RADAR — "envio_email_completo por algoritmo + por documento"
          // Como o envio do e-mail completo mapeia o impacto sistêmico consolidado, vamos cruzar as métricas de transporte.
          const radarLabels = docs.map(d => d.fileName);
          const radarDataBytes = docs.map(d => d.envio_email_completo ? d.envio_email_completo.totalEmailBase64Bytes : 0);
          const radarDataPkts = docs.map(d => d.envio_email_completo ? d.envio_email_completo.packagesTCP * 1000 : 0); // Fator de escala para visualização no radar
          const radarDataLat = docs.map(d => d.envio_email_completo ? d.envio_email_completo.latencyExtraMs * 1000 : 0);

          new Chart(document.getElementById('c-radar-pqc'), {
            type: 'radar',
            data: {
              labels: radarLabels,
              datasets: [
                {
                  label: 'Volume Físico no E-mail (Bytes)',
                  data: radarDataBytes,
                  backgroundColor: 'rgba(0, 212, 170, 0.1)',
                  borderColor: '#00d4aa',
                  pointBackgroundColor: '#00d4aa',
                  borderWidth: 2
                },
                {
                  label: 'Mapeamento de Pacotes TCP (Escala ×1000)',
                  data: radarDataPkts,
                  backgroundColor: 'rgba(249, 115, 22, 0.1)',
                  borderColor: '#f97316',
                  pointBackgroundColor: '#f97316',
                  borderWidth: 2
                },
                {
                  label: 'Latência Extra Estimada (Escala µs)',
                  data: radarDataLat,
                  backgroundColor: 'rgba(168, 85, 247, 0.1)',
                  borderColor: '#a855f7',
                  pointBackgroundColor: '#a855f7',
                  borderWidth: 2
                }
              ]
            },
            options: {
              responsive: true,
              scales: {
                r: {
                  grid: { color: '#1f2d45' },
                  angleLines: { color: '#1f2d45' },
                  ticks: { display: false },
                  pointLabels: { color: '#94a3b8', font: { size: 11, family: 'Space Mono' } }
                }
              },
              plugins: {
                legend: { labels: { color: '#e2e8f0' } },
                tooltip: {
                  callbacks: {
                    label: function(context) {
                      const idx = context.dataIndex;
                      const origDoc = docs[idx] || {};
                      const ecM = origDoc.envio_email_completo || {};
                      if (context.datasetIndex === 0) return ` Tamanho Total: ${kb(ecM.totalEmailBase64Bytes || 0)}`;
                      if (context.datasetIndex === 1) return ` Pacotes TCP: ${ecM.packagesTCP || 0} pkts`;
                      return ` Latência: ${Number(ecM.latencyExtraMs || 0).toFixed(2)} ms`;
                    }
                  }
                }
              }
            }
          });
        }

        try {
          const DADOS_BACKEND = $$DADOS_JSON$$;
          render(DADOS_BACKEND);
        } catch(err) {
          const el = document.getElementById('error-msg');
          el.style.display = 'block';
          el.textContent = 'Erro crítico ao injetar JSON do endpoint Java: ' + err.message;
        }
        </script>
        </body>
        </html>
        """.replace("$$DADOS_JSON$$", json);

    try {
      Path path = Paths.get("dashboard_pqc_redes.html");
      Files.writeString(path, html, StandardCharsets.UTF_8);
      return "Arquivo gerado com sucesso em: " + path.toAbsolutePath().toString();
    } catch (Exception e) {
      throw new RuntimeException("Erro ao criar o arquivo físico HTML: " + e.getMessage(), e);
    }
  }
}