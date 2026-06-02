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

  private static final int INIT_CWND = 10; 
  private static final int TCP_IP_HEADER_OVERHEAD = 40;

  private int simulateTcpFlights(long totalBytes, int mtu) {
      int mss = mtu - TCP_IP_HEADER_OVERHEAD;
      if (mss <= 0) mss = 1460; 
      
      long totalPackets = (long) Math.ceil((double) totalBytes / mss);
      if (totalPackets <= 0) return 0;

      long packetsSent = 0;
      long currentCwnd = INIT_CWND;
      int flights = 0;

      while (packetsSent < totalPackets) {
          flights++;
          long packetsInFlight = Math.min(currentCwnd, totalPackets - packetsSent);
          packetsSent += packetsInFlight;
          currentCwnd *= 2; 
      }
      return flights;
  }

  private int calculateTcpPackets(long totalBytes, int mtu) {
      int mss = mtu - TCP_IP_HEADER_OVERHEAD;
      if (mss <= 0) mss = 1460;
      return (int) Math.ceil((double) totalBytes / mss);
  }

  public Map<String, Object> calculatedRealMetrics() {
    List<SignatureEntity> allSignatures = signatureRepository.findAll();
    if (allSignatures.isEmpty()) {
        return Map.of("erro", "Nenhuma assinatura encontrada.");
    }

    int mtuReal = networkService.discoverRealMTU();
    Map<String, Object> latObj = networkService.measureLatencyTCP();

    double rttMs = latObj.containsKey("latencyMediaMs")
        ? ((Number) latObj.get("latencyMediaMs")).doubleValue()
        : 80.0;

    boolean fallback = Boolean.TRUE.equals(latObj.get("fallback"));

    Map<String, List<SignatureEntity>> porAlgoritmo = allSignatures.stream()
        .collect(Collectors.groupingBy(SignatureEntity::getTypeAlgorithm));

    Map<String, Object> result = new LinkedHashMap<>();

    result.put("condicoesDeRede", new LinkedHashMap<String, Object>() {{
        put("host",                   latObj.getOrDefault("host", "N/A"));
        put("mtuReal",                mtuReal);
        put("rttMedioMs",             rttMs);
        put("rttMinMs",               latObj.getOrDefault("latencyMinMs", rttMs));
        put("rttMaxMs",               latObj.getOrDefault("latencyMaxMs", rttMs));
        put("jitterMs",               latObj.getOrDefault("jitterMs", 0.0));
        put("amostras",               latObj.getOrDefault("amostras", 0));
        put("fallback",               fallback);
        put("latenciaPorPacoteMicros",(int)(rttMs * 1000));
        put("amostrasbrutas",         latObj.getOrDefault("amostrasbrutas", List.of()));
    }});

    porAlgoritmo.forEach((algoritmo, lista) -> result.put(algoritmo,
        calculatedMetricsByGroup(algoritmo, lista, mtuReal, rttMs)));

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
      String algorithm, List<SignatureEntity> lista, int mtu, double rttMs) {

    IntSummaryStatistics statsSig = lista.stream()
        .collect(Collectors.summarizingInt(s -> s.getSignatureBytes().length));
    IntSummaryStatistics statsKey = lista.stream()
        .collect(Collectors.summarizingInt(s -> s.getPublicKeyBytes().length));

    int mediaTotal = (int) (statsSig.getAverage() + statsKey.getAverage());
    int maxTotal = statsSig.getMax() + statsKey.getMax();
    int minTotal = statsSig.getMin() + statsKey.getMin();
    
    int pacotes = calculateTcpPackets(mediaTotal, mtu);
    int flights = simulateTcpFlights(mediaTotal, mtu);

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
    m.put("mtuUsado", mtu);
    m.put("averagePacketsNeeded", pacotes);
    m.put("percentageWithFragmentation",
        String.format("%.2f%%", (comFragmentacao * 100.0) / lista.size()));

    long extraLatencyMicros = (long) (Math.max(0, flights - 1) * rttMs * 1000);
    m.put("extraLatencyAverageMicros", extraLatencyMicros);

    return m;
  }

  private Map<String, Object> calculatedComparative(
      List<SignatureEntity> listaEc, List<SignatureEntity> listaMl, int mtu, double rttMs) {

    double mediaEc = listaEc.stream()
        .mapToInt(s -> s.getPublicKeyBytes().length + s.getSignatureBytes().length).average().orElse(1);
    double mediaMl = listaMl.stream()
        .mapToInt(s -> s.getPublicKeyBytes().length + s.getSignatureBytes().length).average().orElse(0);

    int pacotesEc = calculateTcpPackets((int) mediaEc, mtu);
    int pacotesMl = calculateTcpPackets((int) mediaMl, mtu);

    int flightsEc = simulateTcpFlights((int) mediaEc, mtu);
    int flightsMl = simulateTcpFlights((int) mediaMl, mtu);

    double latenciaEcMs = flightsEc * rttMs;
    double latenciaMlMs = flightsMl * rttMs;

    int mss = mtu - TCP_IP_HEADER_OVERHEAD;
    if (mss <= 0) mss = 1460;
    int capacidadeVoo1Bytes = INIT_CWND * mss;
    
    int maxSigsEcdsaVoo1 = capacidadeVoo1Bytes / (int) mediaEc;
    int maxSigsMldsaVoo1 = capacidadeVoo1Bytes / (int) mediaMl;

    Map<String, Object> c = new LinkedHashMap<>();
    c.put("averageOverheadECDSABytes", (int) mediaEc);
    c.put("averageOverheadMLDSABytes", (int) mediaMl);
    c.put("differenceAverageBytes", (int) (mediaMl - mediaEc));
    c.put("increaseFactorOverhead", String.format("%.2fx", mediaMl / mediaEc));
    c.put("extraPacketsAverageMLDSA", pacotesMl - pacotesEc);
    c.put("latenciaHandshakeECDSAms", latenciaEcMs);
    c.put("latenciaHandshakeMLDSAms", latenciaMlMs);
    
    c.put("analiseSaturacaoJanela", Map.of(
        "capacidadePrimeiroVooBytes", capacidadeVoo1Bytes,
        "limiteAssinaturasVooUnicoECDSA", maxSigsEcdsaVoo1,
        "limiteAssinaturasVooUnicoMLDSA", maxSigsMldsaVoo1,
        "pontoGargaloMLDSA", maxSigsMldsaVoo1 + 1,
        "pontoGargaloECDSA", maxSigsEcdsaVoo1 + 1
    ));

    return c;
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
            
            int acumSigBytes = algSigs.stream().mapToInt(s -> s.getSignatureBytes().length).sum();
            int acumKeyBytes = algSigs.stream().mapToInt(s -> s.getPublicKeyBytes().length).sum();
            int acumHandshake = acumSigBytes + acumKeyBytes;

            Map<String, Object> m = new LinkedHashMap<>();
            m.put("totalSignatures", algSigs.size());
            m.put("handshake_unitario", Map.of(
                "totalBytes", unitHandshake,
                "packagesTCP", calculateTcpPackets(unitHandshake, mtu),
                "voosNecessarios", simulateTcpFlights(unitHandshake, mtu),
                "latencyExtraMs", simulateTcpFlights(unitHandshake, mtu) * rttMs
            ));
            m.put("handshake_acumulado", Map.of(
                "totalHandshakeBytes", acumHandshake,
                "emailBase64Bytes", (int) Math.ceil(acumHandshake * 4.0 / 3)
            ));
            porAlgMetrics.put(alg, m);
        });

        docData.put("porAlgoritmo", porAlgMetrics);

        // --- CÁLCULO E2E (END-TO-END) ---
        int docBytes = doc.getContent().length;
        int allSigBytes = sigs.stream()
            .mapToInt(s -> s.getSignatureBytes().length + s.getPublicKeyBytes().length).sum();
        
        int emailCompletoBytes = (int) Math.ceil((docBytes + allSigBytes) * 4.0 / 3);
        int packageMail = calculateTcpPackets(emailCompletoBytes, mtu);
        int emailFlights = simulateTcpFlights(emailCompletoBytes, mtu);
        double latMail = emailFlights * rttMs;

        docData.put("processo_e2e", Map.of(
            "totalEmailBase64Bytes", emailCompletoBytes,
            "packagesTCP", packageMail,
            "totalVoosE2E", emailFlights,
            "tempoTotalE2EMs", latMail
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
            header{display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:1rem;margin-bottom:2rem;}
            
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
            
            .doc-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:1rem;margin-bottom:1.5rem;}
            .doc-card{background:var(--bg2);border:1px solid var(--border);border-radius:14px;padding:1.25rem; display:flex; flex-direction:column;}
            .doc-name{font-family:'Space Mono',monospace;font-size:1rem;color:var(--text);margin-bottom:.75rem;word-break:break-all;border-bottom:1px solid var(--border);padding-bottom:6px; font-weight:bold;}
            .doc-row{display:flex;justify-content:space-between;font-size:.78rem;padding:6px 0;border-bottom:1px solid rgba(31,45,69,0.5);}
            .doc-row:last-child{border-bottom:none;}
            .doc-row span:first-child{color:var(--muted);}
            .doc-row span:last-child{font-family:'Space Mono',monospace;font-size:.75rem; font-weight:bold;}
            
            .e2e-box { background: rgba(168, 85, 247, 0.08); border: 1px solid rgba(168, 85, 247, 0.3); border-radius: 8px; padding: 12px; margin-top: 15px;}
            .e2e-title { color: #d8b4fe; font-family: 'Space Mono', monospace; font-size: 0.75rem; text-transform: uppercase; margin-bottom: 8px; font-weight: bold; }
            .e2e-val { color: #fff; font-size: 1.1rem; font-weight: 600; display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;}
            .e2e-sub { color: #a855f7; font-size: 0.75rem; }
            
            .alg-tag{display:inline-block;font-size:.65rem;padding:3px 8px;border-radius:4px;font-family:'Space Mono',monospace;margin-bottom:8px;font-weight:bold; margin-top:12px;}
            .alg-tag.ec{background:var(--ecdsa-dim);color:var(--ecdsa);border:1px solid var(--ecdsa);}
            .alg-tag.ml{background:var(--mldsa-dim);color:var(--mldsa);border:1px solid var(--mldsa);}
            
            table{width:100%;border-collapse:collapse;font-size:.8rem;margin-top:.5rem;}
            th{text-align:left;padding:10px;background:var(--bg3);color:var(--muted);font-family:'Space Mono',monospace;font-size:.7rem;text-transform:uppercase;letter-spacing:.05em;border:1px solid var(--border);}
            td{padding:10px;border:1px solid var(--border);color:var(--text);vertical-align:middle;}
            #error-msg{display:none;background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);border-radius:10px;padding:1.5rem;color:#fca5a5;font-family:'Space Mono',monospace;font-size:.85rem;margin-bottom:1rem;}
          </style>
        </head>
        <body>
        <div id="error-msg"></div>
        <div id="app">
          <header>
            <div>
              <h1>PQC <span>//</span> Análise End-to-End de Rede</h1>
              <p style="color:var(--muted);font-size:.875rem;margin-top:6px">Mapeamento Dinâmico de Lotes: ECDSA vs ML-DSA-44</p>
            </div>
          </header>

          <div class="kpi-section">
            <div class="kpi-container-title">📊 Saturação de Janela (RFC 6928) - Limite de Lote Unitário</div>
            <div class="kpi-grid" id="comp-kpis"></div>
          </div>

          <h2>Análise de Transferência em Lote (End-to-End) por Documento</h2>
          <div class="doc-grid" id="doc-grid"></div>

          <h2>Tabela Consolidada — Processos E2E</h2>
          <div class="chart-card full" style="margin-bottom:1.5rem;overflow-x:auto">
            <table id="tabela-consolidada"></table>
          </div>
        </div>

        <script>
        function kb(b){return b>=1024*1024 ? (b/(1024*1024)).toFixed(2)+' MB' : (b>=1024?(b/1024).toFixed(2)+' KB':b+' B');}

        function render(D) {
          if (!D || D.erro) {
            document.getElementById('error-msg').style.display = 'block';
            document.getElementById('error-msg').textContent = D ? D.erro : 'Dados inválidos.';
            return;
          }

          const comp = D['comparative'] || {};
          const docs = D['porDocumento'] || [];
          const sat = comp.analiseSaturacaoJanela || {};

          document.getElementById('comp-kpis').innerHTML = `
            <div class="kpi ml" style="border-color:#f97316;">
              <label style="color:#f97316;">Suporta 1 Voo (ML-DSA)</label>
              <div class="val" style="color:#f97316;">${sat.limiteAssinaturasVooUnicoMLDSA || 3} sigs</div>
              <div class="sub">Acumulados antes de travar rede</div>
            </div>
            
            <div class="kpi ec" style="border-color:#00d4aa;">
              <label style="color:#00d4aa;">Suporta 1 Voo (ECDSA)</label>
              <div class="val" style="color:#00d4aa;">${sat.limiteAssinaturasVooUnicoECDSA || 90} sigs</div>
              <div class="sub">Acumulados antes de travar rede</div>
            </div>
            
            <div class="kpi net">
              <label>Capacidade do 1º Voo</label>
              <div class="val">${kb(sat.capacidadePrimeiroVooBytes || 14600)}</div>
              <div class="sub">Initcwnd = 10 MSS</div>
            </div>
          `;

          const gridDocs = document.getElementById('doc-grid');
          gridDocs.innerHTML = '';
          
          docs.forEach(d => {
            let algosHtml = '';
            if (d.porAlgoritmo) {
              Object.entries(d.porAlgoritmo).forEach(([algName, algObj]) => {
                const isEc = algName === 'ECDSA';
                const cls = isEc ? 'ec' : 'ml';
                const unit = algObj.handshake_unitario || {};
                
                algosHtml += `
                  <span class="alg-tag ${cls}">${algName} (Lote: ${algObj.totalSignatures} sigs)</span>
                  <div class="doc-row"><span>Custo de 1 Assinatura</span><span>${kb(unit.totalBytes)} (${unit.voosNecessarios} voo)</span></div>
                `;
              });
            }

            const e2e = d.processo_e2e || {};

            gridDocs.innerHTML += `
              <div class="doc-card">
                <div class="doc-name">📄 ${d.fileName}</div>
                <div class="doc-row"><span>Tamanho PDF Puro</span><span>${kb(d.fileSizeBytes)}</span></div>
                <div class="doc-row"><span>Total de Assinaturas</span><span>${d.totalSignatures}</span></div>
                
                ${algosHtml}

                <div class="e2e-box">
                  <div class="e2e-title">🚀 Processo End-to-End Acumulado</div>
                  <div class="doc-row" style="border-bottom:none; padding-top:0;">
                    <span style="color:#e9d5ff;">Volume Total (PDF + Sigs Base64)</span>
                    <span style="color:#fff;">${kb(e2e.totalEmailBase64Bytes)}</span>
                  </div>
                  <div class="doc-row" style="border-bottom:none;">
                    <span style="color:#e9d5ff;">Total de Pacotes Físicos TCP</span>
                    <span style="color:#fff;">${e2e.packagesTCP} pkt</span>
                  </div>
                  
                  <div style="margin-top:10px; padding-top:10px; border-top:1px solid rgba(168,85,247,0.3);">
                    <div class="e2e-val">
                      <span style="font-size:0.8rem; color:#d8b4fe;">✈️ Voos TCP Acumulados</span>
                      <span>${e2e.totalVoosE2E} voos</span>
                    </div>
                    <div class="e2e-val">
                      <span style="font-size:0.8rem; color:#d8b4fe;">⏱️ Tempo Total E2E</span>
                      <span style="color:#fca5a5;">${Number(e2e.tempoTotalE2EMs).toFixed(2)} ms</span>
                    </div>
                  </div>
                </div>
              </div>
            `;
          });

          let thHtml = `
            <tr>
              <th>Documento</th>
              <th>Algoritmo</th>
              <th>Assinaturas</th>
              <th>Volume E2E (Base64)</th>
              <th>Pacotes TCP Totais</th>
              <th>Voos Acumulados (Slow Start)</th>
              <th>Tempo Total E2E</th>
            </tr>
          `;
          
          docs.forEach(d => {
            if (d.porAlgoritmo) {
              const e2e = d.processo_e2e || {};
              Object.entries(d.porAlgoritmo).forEach(([algName, algObj], idx) => {
                thHtml += `
                  <tr>
                    <td style="font-weight:bold; font-family:'Space Mono',monospace;">${d.fileName}</td>
                    <td><span class="alg-tag ${algName === 'ECDSA' ? 'ec' : 'ml'}" style="margin:0;">${algName}</span></td>
                    <td style="font-family:'Space Mono',monospace;">${algObj.totalSignatures}</td>
                    <td style="font-family:'Space Mono',monospace;">${kb(e2e.totalEmailBase64Bytes)}</td>
                    <td style="font-family:'Space Mono',monospace;">${e2e.packagesTCP} pkt</td>
                    <td style="font-weight:bold; font-family:'Space Mono',monospace; color:#a855f7;">${e2e.totalVoosE2E} voos</td>
                    <td style="font-weight:bold; font-family:'Space Mono',monospace; color:#fca5a5;">${Number(e2e.tempoTotalE2EMs).toFixed(2)} ms</td>
                  </tr>
                `;
              });
            }
          });
          document.getElementById('tabela-consolidada').innerHTML = thHtml;
        }

        try {
          const DADOS_BACKEND = $$DADOS_JSON$$;
          render(DADOS_BACKEND);
        } catch(err) {
          const el = document.getElementById('error-msg');
          el.style.display = 'block';
          el.textContent = 'Erro crítico ao injetar JSON: ' + err.message;
        }
        </script>
        </body>
        </html>
        """.replace("$$DADOS_JSON$$", json);

    try {
      java.nio.file.Path path = java.nio.file.Paths.get("dashboard_pqc_redes.html");
      java.nio.file.Files.writeString(path, html, java.nio.charset.StandardCharsets.UTF_8);
      return "Arquivo HTML E2E gerado com sucesso em: " + path.toAbsolutePath().toString();
    } catch (Exception e) {
      throw new RuntimeException("Erro ao criar o arquivo: " + e.getMessage(), e);
    }
  }
}