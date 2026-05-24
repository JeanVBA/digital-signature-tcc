package br.edu.faeterj.tcc.digital_signature.service;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
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

  // Remove as constantes fixas:
  // private static final int MTU = 1500;
  // private static final int LATENCY_BY_MICROSCRAPING = 500;

  private final SignatureRepository signatureRepository;
  private final DocumentRepository documentRepository;
  private final NetworkMeasurementService networkService;

  public Map<String, Object> calculatedRealMetrics() {

    List<SignatureEntity> allSignatures = signatureRepository.findAll();
    if (allSignatures.isEmpty()) {
      return Map.of("erro", "Nenhuma assinatura encontrada.");
    }

    // ── Medições reais de rede ──────────────────────────────
    int mtuReal = networkService.discoverRealMTU();
    Map<String, Object> latencia = networkService.measureLatencyTCP();
    double rttMs = latencia.containsKey("latenciaMediaMs")
        ? (double) latencia.get("latenciaMediaMs")
        : 1.0;
    int latenciaPorPacoteMicros = (int) (rttMs * 1000); // converte ms → µs

    // ── Agrupa e calcula com MTU e latência reais ───────────
    Map<String, List<SignatureEntity>> porAlgoritmo = allSignatures.stream()
        .collect(Collectors.groupingBy(SignatureEntity::getTypeAlgorithm));

    Map<String, Object> result = new LinkedHashMap<>();

    // Expõe as condições reais de rede usadas nos cálculos
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
        .filter(s -> s.getPublicKeyBytes().length
            + s.getSignatureBytes().length > mtu)
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
    m.put("mtuUsado", mtu); // real, não fixo
    m.put("averagePacketsNeeded", pacotes);
    m.put("tamanhoFixoPorAlgoritmo", tamanhoFixo);
    m.put("percentageWithFragmentation",
        String.format("%.2f%%", (comFragmentacao * 100.0) / lista.size()));

    if (tamanhoFixo) {
      m.put("notaFragmentacao",
          comFragmentacao == lista.size()
              ? String.format("100%% das assinaturas fragmentam — tamanho fixo " +
                  "(%d bytes) sempre excede o MTU real de %d bytes.", maxTotal, mtu)
              : String.format("0%% das assinaturas fragmentam — tamanho fixo " +
                  "(%d bytes) está abaixo do MTU real de %d bytes.", maxTotal, mtu));
    }

    // Latência calculada com RTT real medido
    m.put("extraLatencyAverageMicros",
        Math.max(0, pacotes - 1) * latenciaPorPacoteMicros);
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
    c.put("increaseFactorOverhead",
        String.format("%.2fx", mediaMl / mediaEc));
    c.put("extraPacketsAverageMLDSA", pacotesMl - pacotesEc);
    c.put("latenciaHandshakeECDSAms", latenciaEcMs);
    c.put("latenciaHandshakeMLDSAms", latenciaMlMs);
    c.put("latenciaExtraRealMs", latenciaMlMs - latenciaEcMs);
    c.put("fatorAumentoLatencia",
        String.format("%.1fx", latenciaMlMs / latenciaEcMs));
    c.put("mtuUsadoNaAnalise", mtu);
    c.put("rttUsadoMs", rttMs);
    c.put("conclusion", String.format(
        "Com MTU real de %d bytes e RTT médio de %.2fms, o handshake " +
            "ML-DSA-44 exige %d pacote(s) TCP contra %d do ECDSA, " +
            "resultando em %.2fms de latência extra por conexão (%.1fx mais lento).",
        mtu, rttMs, pacotesMl, pacotesEc,
        latenciaMlMs - latenciaEcMs,
        latenciaMlMs / latenciaEcMs));
    return c;
  }

  public Map<String, Object> calculatedMetricsByDocument(Long documentId) {

    List<SignatureEntity> assinaturas = signatureRepository.findByDocumentId(documentId);

    if (assinaturas.isEmpty()) {
      return Map.of("erro",
          "Documento " + documentId + " não possui assinaturas.");
    }

    // Mede MTU real — consistente com o endpoint principal
    int mtu = networkService.discoverRealMTU();

    DocumentEntity doc = assinaturas.get(0).getDocument();

    Map<String, Object> result = new LinkedHashMap<>();
    result.put("documentId", documentId);
    result.put("fileName", doc.getName());
    result.put("fileType", doc.getType());
    result.put("fileSizeBytes", doc.getContent().length);
    result.put("mtuUsado", mtu); // real, não fixo

    List<Map<String, Object>> detalhesPorAssinatura = assinaturas.stream()
        .map(s -> detailSignature(s, mtu)) // passa o MTU real
        .collect(Collectors.toList());

    result.put("signatures", detalhesPorAssinatura);

    Map<String, List<SignatureEntity>> algorithmType = assinaturas.stream()
        .collect(Collectors.groupingBy(SignatureEntity::getTypeAlgorithm));

    if (algorithmType.containsKey("ECDSA")
        && algorithmType.containsKey("ML-DSA-44")) {

      SignatureEntity ec = algorithmType.get("ECDSA").get(0);
      SignatureEntity ml = algorithmType.get("ML-DSA-44").get(0);

      int totalEc = ec.getPublicKeyBytes().length + ec.getSignatureBytes().length;
      int totalMl = ml.getPublicKeyBytes().length + ml.getSignatureBytes().length;

      result.put("comparativeThisDocument", Map.of(
          "overheadECDSABytes", totalEc,
          "overheadMLDSABytes", totalMl,
          "diferenceBytes", totalMl - totalEc,
          "factor", String.format("%.2fx", (double) totalMl / totalEc),
          "fragmentationECDSA", totalEc > mtu,
          "fragmentationMLDSA", totalMl > mtu,
          "mtuUsado", mtu));
    }

    return result;
  }

  public List<Map<String, Object>> rankingOverheadByDocument() {

    // Mede uma vez e reutiliza para todos os documentos do ranking
    int mtu = networkService.discoverRealMTU();

    return signatureRepository.findAll().stream()
        .collect(Collectors.groupingBy(s -> s.getDocument().getId()))
        .entrySet().stream()
        .map(entry -> {
          List<SignatureEntity> sigs = entry.getValue();
          DocumentEntity doc = sigs.get(0).getDocument();

          int maiorOverhead = sigs.stream()
              .mapToInt(s -> s.getPublicKeyBytes().length
                  + s.getSignatureBytes().length)
              .max().orElse(0);

          int pacotes = calculatedPackets(maiorOverhead, mtu);

          Map<String, Object> item = new LinkedHashMap<>();
          item.put("documentId", doc.getId());
          item.put("fileName", doc.getName());
          item.put("fileSizeBytes", doc.getContent().length);
          item.put("maxOverheadBytes", maiorOverhead);
          item.put("mtuUsado", mtu);
          item.put("fragmentationIP", maiorOverhead > mtu);
          item.put("packetsNeeded", pacotes);
          item.put("totalSignatures", sigs.size());
          item.put("algorithms", sigs.stream()
              .map(SignatureEntity::getTypeAlgorithm)
              .distinct()
              .collect(Collectors.toList()));
          return item;
        })
        .sorted(Comparator.comparingInt(m -> -((int) m.get("maxOverheadBytes"))))
        .collect(Collectors.toList());
  }

  // detailSignature agora recebe o MTU como parâmetro
  private Map<String, Object> detailSignature(SignatureEntity s, int mtu) {
    int totalBytes = s.getPublicKeyBytes().length + s.getSignatureBytes().length;
    int packets = calculatedPackets(totalBytes, mtu);

    Map<String, Object> d = new LinkedHashMap<>();
    d.put("signatureId", s.getId());
    d.put("algorithm", s.getTypeAlgorithm());
    d.put("publicKeyBytes", s.getPublicKeyBytes().length);
    d.put("signatureBytes", s.getSignatureBytes().length);
    d.put("totalHandshakeBytes", totalBytes);
    d.put("mtuUsado", mtu);
    d.put("packetsNeeded", packets);
    d.put("fragmentationIP", totalBytes > mtu);
    d.put("extraLatencyMicros", Math.max(0, packets - 1) * (double) networkService.measureLatencyTCP().get("latencyMediaMs"));
    d.put("signatureValid", s.isValid());
    d.put("signatureDate", s.getSignatureDate());
    return d;
  }

  private int calculatedPackets(int totalBytes, int mtu) {
    return (int) Math.ceil((double) totalBytes / mtu);
  }

  public String generatedHtmlGrafics(Map<String, Object> dados) {
    // Serializa os dados para JSON (Jackson já está no classpath do Spring)
    String json;
    try {
      json = new com.fasterxml.jackson.databind.ObjectMapper()
          .writeValueAsString(dados);
    } catch (Exception e) {
      json = "{}";
    }

    return """
                <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
          <meta charset="UTF-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1.0" />
          <title>PQC — Análise de Overhead de Rede</title>
          <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
          <style>
            @import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=DM+Sans:wght@300;400;500;600&display=swap');

            :root {
              --bg:        #0a0e1a;
              --bg2:       #111827;
              --bg3:       #1a2235;
              --border:    #1f2d45;
              --ecdsa:     #00d4aa;
              --ecdsa-dim: rgba(0,212,170,0.12);
              --mldsa:     #f97316;
              --mldsa-dim: rgba(249,115,22,0.12);
              --text:      #e2e8f0;
              --muted:     #64748b;
              --accent:    #3b82f6;
            }

            * { box-sizing: border-box; margin: 0; padding: 0; }

            body {
              background: var(--bg);
              color: var(--text);
              font-family: 'DM Sans', sans-serif;
              min-height: 100vh;
              padding: 2rem;
            }

            /* ── Header ── */
            header {
              display: flex;
              align-items: flex-start;
              justify-content: space-between;
              margin-bottom: 2.5rem;
              flex-wrap: wrap;
              gap: 1rem;
            }
            .header-left h1 {
              font-family: 'Space Mono', monospace;
              font-size: clamp(1.4rem, 3vw, 2rem);
              letter-spacing: -0.03em;
              line-height: 1.2;
            }
            .header-left h1 span { color: var(--accent); }
            .header-left p {
              color: var(--muted);
              font-size: 0.875rem;
              margin-top: 6px;
            }
            .status-badge {
              display: inline-flex;
              align-items: center;
              gap: 6px;
              background: var(--bg3);
              border: 1px solid var(--border);
              border-radius: 999px;
              padding: 6px 14px;
              font-size: 0.78rem;
              font-family: 'Space Mono', monospace;
              color: var(--muted);
            }
            .dot-live {
              width: 7px; height: 7px;
              border-radius: 50%;
              background: var(--ecdsa);
              animation: pulse 1.8s ease-in-out infinite;
            }
            @keyframes pulse {
              0%,100% { opacity: 1; transform: scale(1); }
              50%      { opacity: 0.4; transform: scale(0.7); }
            }

            /* ── KPI Cards ── */
            .kpi-grid {
              display: grid;
              grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
              gap: 1rem;
              margin-bottom: 2rem;
            }
            .kpi {
              background: var(--bg2);
              border: 1px solid var(--border);
              border-radius: 12px;
              padding: 1.25rem 1.5rem;
              position: relative;
              overflow: hidden;
            }
            .kpi::before {
              content: '';
              position: absolute;
              top: 0; left: 0; right: 0;
              height: 2px;
            }
            .kpi.ec::before  { background: var(--ecdsa); }
            .kpi.ml::before  { background: var(--mldsa); }
            .kpi.cmp::before { background: var(--accent); }
            .kpi label {
              font-size: 0.72rem;
              text-transform: uppercase;
              letter-spacing: 0.08em;
              color: var(--muted);
              font-family: 'Space Mono', monospace;
            }
            .kpi .val {
              font-size: 1.9rem;
              font-weight: 600;
              line-height: 1.2;
              margin-top: 4px;
            }
            .kpi.ec .val  { color: var(--ecdsa); }
            .kpi.ml .val  { color: var(--mldsa); }
            .kpi.cmp .val { color: var(--accent); }
            .kpi .sub {
              font-size: 0.75rem;
              color: var(--muted);
              margin-top: 2px;
            }

            /* ── Chart grid ── */
            .charts-grid {
              display: grid;
              grid-template-columns: repeat(auto-fit, minmax(380px, 1fr));
              gap: 1.25rem;
              margin-bottom: 1.25rem;
            }
            .chart-card {
              background: var(--bg2);
              border: 1px solid var(--border);
              border-radius: 16px;
              padding: 1.5rem;
            }
            .chart-card.full { grid-column: 1 / -1; }
            .chart-title {
              font-family: 'Space Mono', monospace;
              font-size: 0.8rem;
              text-transform: uppercase;
              letter-spacing: 0.06em;
              color: var(--muted);
              margin-bottom: 1.25rem;
              display: flex;
              align-items: center;
              gap: 8px;
            }
            .chart-title::before {
              content: '';
              display: inline-block;
              width: 8px; height: 8px;
              border-radius: 2px;
              background: var(--accent);
            }
            .chart-wrap { position: relative; }

            /* ── Fragmentação banner ── */
            .frag-banner {
              background: rgba(249,115,22,0.08);
              border: 1px solid rgba(249,115,22,0.3);
              border-radius: 12px;
              padding: 1rem 1.5rem;
              display: flex;
              align-items: center;
              gap: 12px;
              margin-bottom: 1.25rem;
              font-size: 0.875rem;
              color: #fed7aa;
            }
            .frag-icon { font-size: 1.4rem; flex-shrink: 0; }

            /* ── Footer ── */
            footer {
              margin-top: 2.5rem;
              padding-top: 1.25rem;
              border-top: 1px solid var(--border);
              display: flex;
              justify-content: space-between;
              flex-wrap: wrap;
              gap: 8px;
              font-size: 0.75rem;
              color: var(--muted);
              font-family: 'Space Mono', monospace;
            }

            /* ── Loading ── */
            #loading {
              position: fixed; inset: 0;
              background: var(--bg);
              display: flex;
              flex-direction: column;
              align-items: center;
              justify-content: center;
              gap: 1rem;
              z-index: 100;
            }
            .spinner {
              width: 40px; height: 40px;
              border: 3px solid var(--border);
              border-top-color: var(--accent);
              border-radius: 50%;
              animation: spin 0.8s linear infinite;
            }
            @keyframes spin { to { transform: rotate(360deg); } }
            #loading p { color: var(--muted); font-family: 'Space Mono', monospace; font-size: 0.8rem; }

            /* ── Error ── */
            #error-msg {
              display: none;
              background: rgba(239,68,68,0.1);
              border: 1px solid rgba(239,68,68,0.3);
              border-radius: 12px;
              padding: 1.5rem;
              color: #fca5a5;
              font-family: 'Space Mono', monospace;
              font-size: 0.85rem;
            }
          </style>
        </head>
        <body>

        <div id="loading">
          <div class="spinner"></div>
          <p>Carregando dados do banco...</p>
        </div>

        <div id="error-msg"></div>

        <div id="app" style="display:none">

          <header>
            <div class="header-left">
              <h1>PQC <span>//</span> Análise de Overhead de Rede</h1>
              <p>ECDSA secp256r1 vs ML-DSA-44 (NIST FIPS 204) — dados reais do banco</p>
            </div>
            <div class="status-badge">
              <div class="dot-live"></div>
              <span id="lbl-total">— assinaturas</span>
            </div>
          </header>

          <!-- KPI Cards -->
          <div class="kpi-grid" id="kpi-grid"></div>

          <!-- Aviso de fragmentação -->
          <div class="frag-banner" id="frag-banner" style="display:none">
            <span class="frag-icon">⚠️</span>
            <span id="frag-text"></span>
          </div>

          <!-- Gráficos -->
          <div class="charts-grid">
            <div class="chart-card">
              <div class="chart-title">Tamanho da Assinatura (bytes)</div>
              <div class="chart-wrap"><canvas id="chart-sig"></canvas></div>
            </div>
            <div class="chart-card">
              <div class="chart-title">Tamanho da Chave Pública (bytes)</div>
              <div class="chart-wrap"><canvas id="chart-key"></canvas></div>
            </div>
            <div class="chart-card">
              <div class="chart-title">Total Handshake TLS (bytes)</div>
              <div class="chart-wrap"><canvas id="chart-total"></canvas></div>
            </div>
            <div class="chart-card">
              <div class="chart-title">Pacotes TCP Necessários</div>
              <div class="chart-wrap"><canvas id="chart-pkts"></canvas></div>
            </div>
            <div class="chart-card full">
              <div class="chart-title">Comparativo Geral — todas as métricas normalizadas</div>
              <div class="chart-wrap"><canvas id="chart-radar"></canvas></div>
            </div>
            <div class="chart-card full">
              <div class="chart-title">Latência Extra Estimada por Fragmentação (µs)</div>
              <div class="chart-wrap"><canvas id="chart-lat"></canvas></div>
            </div>
          </div>

          <footer>
            <span>FAETERJ — TCC Criptografia Pós-Quântica</span>
            <span id="lbl-ts"></span>
          </footer>
        </div>

        <script>
        // ── Configuração ────────────────────────────────────────────────
        const API_URL = '/api/metrics/overhead-tls'; // mesmo endpoint já existente
        const MTU     = 1500;

        const COR_EC = '#00d4aa';
        const COR_ML = '#f97316';
        const COR_EC_DIM = 'rgba(0,212,170,0.15)';
        const COR_ML_DIM = 'rgba(249,115,22,0.15)';

        Chart.defaults.color          = '#64748b';
        Chart.defaults.borderColor    = '#1f2d45';
        Chart.defaults.font.family    = "'DM Sans', sans-serif";

        // ── Helpers ─────────────────────────────────────────────────────
        function n(v) { return typeof v === 'number' ? v : 0; }

        function barChart(id, labels, ecVal, mlVal, unit = '') {
          return new Chart(document.getElementById(id), {
            type: 'bar',
            data: {
              labels,
              datasets: [
                {
                  label: 'ECDSA',
                  data: [ecVal],
                  backgroundColor: COR_EC_DIM,
                  borderColor: COR_EC,
                  borderWidth: 2,
                  borderRadius: 6,
                },
                {
                  label: 'ML-DSA-44',
                  data: [mlVal],
                  backgroundColor: COR_ML_DIM,
                  borderColor: COR_ML,
                  borderWidth: 2,
                  borderRadius: 6,
                }
              ]
            },
            options: {
              responsive: true,
              plugins: {
                legend: { position: 'top' },
                tooltip: {
                  callbacks: {
                    label: ctx => ` ${ctx.dataset.label}: ${ctx.parsed.y.toLocaleString('pt-BR')} ${unit}`
                  }
                }
              },
              scales: {
                y: {
                  beginAtZero: true,
                  grid: { color: '#1f2d45' },
                  ticks: {
                    callback: v => v.toLocaleString('pt-BR') + (unit ? ' ' + unit : '')
                  }
                },
                x: { grid: { display: false } }
              }
            }
          });
        }

        // ── Render ───────────────────────────────────────────────────────
        function render(dados) {
          const ec  = dados['ECDSA']      || dados['ECDSA_secp256r1']    || {};
          const ml  = dados['ML-DSA-44']  || dados['ML_DSA_44']          || {};
          const cmp = dados['comparativo'] || dados['impactoDeRede']      || {};
          const total = n(dados['totalAssinaturasNoBanco']);

          // ── Label total
          document.getElementById('lbl-total').textContent =
            `${total} assinatura${total !== 1 ? 's' : ''} no banco`;
          document.getElementById('lbl-ts').textContent =
            'Gerado em ' + new Date().toLocaleString('pt-BR');

          // ── KPI Cards
          const ecTotal = n(ec.mediaTotalHandshakeBytes);
          const mlTotal = n(ml.mediaTotalHandshakeBytes);
          const fator   = cmp.fatorAumentoOverhead || (ecTotal ? `${(mlTotal/ecTotal).toFixed(1)}x` : '—');

          const kpis = [
            { cls:'ec',  label:'ECDSA — Handshake', val: ecTotal.toLocaleString('pt-BR'), sub:'bytes (média)' },
            { cls:'ml',  label:'ML-DSA-44 — Handshake', val: mlTotal.toLocaleString('pt-BR'), sub:'bytes (média)' },
            { cls:'ec',  label:'ECDSA — Pacotes TCP', val: n(ec.mediaPacketesNecessarios), sub:`MTU = ${MTU} bytes` },
            { cls:'ml',  label:'ML-DSA-44 — Pacotes TCP', val: n(ml.mediaPacketesNecessarios), sub:`MTU = ${MTU} bytes` },
            { cls:'cmp', label:'Fator de Aumento', val: fator, sub:'overhead ML-DSA vs ECDSA' },
            { cls:'cmp', label:'Bytes Extras / Handshake', val: n(cmp.diferencaMediaBytes || (mlTotal - ecTotal)).toLocaleString('pt-BR'), sub:'diferença média real' },
          ];

          const kpiGrid = document.getElementById('kpi-grid');
          kpis.forEach(k => {
            kpiGrid.innerHTML += `
              <div class="kpi ${k.cls}">
                <label>${k.label}</label>
                <div class="val">${k.val}</div>
                <div class="sub">${k.sub}</div>
              </div>`;
          });

          // ── Banner fragmentação
          if (ml.fragmentacaoIP || mlTotal > MTU) {
            const banner = document.getElementById('frag-banner');
            banner.style.display = 'flex';
            document.getElementById('frag-text').textContent =
              `ML-DSA-44 ultrapassa o MTU padrão de ${MTU} bytes (total médio: ${mlTotal.toLocaleString('pt-BR')} bytes), ` +
              `forçando fragmentação em ${n(ml.mediaPacketesNecessarios)} pacotes TCP por handshake e adicionando ` +
              `~${n(ml.latenciaExtraMediaMicros)} µs de latência estimada por conexão.`;
          }

          // ── Gráfico 1 — Assinatura
          barChart('chart-sig', ['Tamanho da Assinatura'],
            n(ec.mediaAssinaturaBytes), n(ml.mediaAssinaturaBytes), 'bytes');

          // ── Gráfico 2 — Chave Pública
          barChart('chart-key', ['Chave Pública'],
            n(ec.mediaChavePublicaBytes), n(ml.mediaChavePublicaBytes), 'bytes');

          // ── Gráfico 3 — Total Handshake
          new Chart(document.getElementById('chart-total'), {
            type: 'bar',
            data: {
              labels: ['Total Handshake TLS'],
              datasets: [
                { label: 'ECDSA',      data: [ecTotal], backgroundColor: COR_EC_DIM, borderColor: COR_EC, borderWidth: 2, borderRadius: 6 },
                { label: 'ML-DSA-44',  data: [mlTotal], backgroundColor: COR_ML_DIM, borderColor: COR_ML, borderWidth: 2, borderRadius: 6 },
                { label: 'Limite MTU', data: [MTU],      backgroundColor: 'transparent', borderColor: '#ef4444', borderWidth: 1.5,
                  borderDash: [6,4], type: 'line', pointRadius: 0 }
              ]
            },
            options: {
              responsive: true,
              plugins: {
                legend: { position: 'top' },
                tooltip: { callbacks: { label: ctx => ` ${ctx.dataset.label}: ${ctx.parsed.y?.toLocaleString('pt-BR')} bytes` } }
              },
              scales: {
                y: { beginAtZero: true, grid: { color: '#1f2d45' }, ticks: { callback: v => v.toLocaleString('pt-BR') + ' B' } },
                x: { grid: { display: false } }
              }
            }
          });

          // ── Gráfico 4 — Pacotes TCP
          barChart('chart-pkts', ['Pacotes TCP'],
            n(ec.mediaPacketesNecessarios), n(ml.mediaPacketesNecessarios), 'pkt');

          // ── Gráfico 5 — Radar comparativo (normalizado 0–100)
          const maxSig   = Math.max(n(ec.mediaAssinaturaBytes),    n(ml.mediaAssinaturaBytes),    1);
          const maxChave = Math.max(n(ec.mediaChavePublicaBytes),  n(ml.mediaChavePublicaBytes),  1);
          const maxTotal = Math.max(ecTotal, mlTotal, 1);
          const maxPkts  = Math.max(n(ec.mediaPacketesNecessarios),n(ml.mediaPacketesNecessarios),1);
          const maxLat   = Math.max(n(ec.latenciaExtraMediaMicros),n(ml.latenciaExtraMediaMicros),1);

          new Chart(document.getElementById('chart-radar'), {
            type: 'radar',
            data: {
              labels: ['Assinatura', 'Chave Pública', 'Total Handshake', 'Pacotes TCP', 'Latência Extra'],
              datasets: [
                {
                  label: 'ECDSA',
                  data: [
                    (n(ec.mediaAssinaturaBytes)    / maxSig)   * 100,
                    (n(ec.mediaChavePublicaBytes)  / maxChave) * 100,
                    (ecTotal                       / maxTotal)  * 100,
                    (n(ec.mediaPacketesNecessarios)/ maxPkts)   * 100,
                    (n(ec.latenciaExtraMediaMicros)/ maxLat)    * 100,
                  ],
                  backgroundColor: COR_EC_DIM,
                  borderColor: COR_EC,
                  borderWidth: 2,
                  pointBackgroundColor: COR_EC,
                },
                {
                  label: 'ML-DSA-44',
                  data: [
                    (n(ml.mediaAssinaturaBytes)    / maxSig)   * 100,
                    (n(ml.mediaChavePublicaBytes)  / maxChave) * 100,
                    (mlTotal                       / maxTotal)  * 100,
                    (n(ml.mediaPacketesNecessarios)/ maxPkts)   * 100,
                    (n(ml.latenciaExtraMediaMicros)/ maxLat)    * 100,
                  ],
                  backgroundColor: COR_ML_DIM,
                  borderColor: COR_ML,
                  borderWidth: 2,
                  pointBackgroundColor: COR_ML,
                }
              ]
            },
            options: {
              responsive: true,
              plugins: { legend: { position: 'top' } },
              scales: {
                r: {
                  min: 0, max: 100,
                  grid:      { color: '#1f2d45' },
                  angleLines: { color: '#1f2d45' },
                  ticks: { display: false },
                  pointLabels: { color: '#94a3b8', font: { size: 12 } }
                }
              }
            }
          });

          // ── Gráfico 6 — Latência
          new Chart(document.getElementById('chart-lat'), {
            type: 'bar',
            data: {
              labels: ['ECDSA', 'ML-DSA-44'],
              datasets: [{
                label: 'Latência extra estimada (µs)',
                data: [
                  n(ec.latenciaExtraMediaMicros),
                  n(ml.latenciaExtraMediaMicros)
                ],
                backgroundColor: [COR_EC_DIM, COR_ML_DIM],
                borderColor:     [COR_EC,     COR_ML],
                borderWidth: 2,
                borderRadius: 8,
              }]
            },
            options: {
              indexAxis: 'y',
              responsive: true,
              plugins: {
                legend: { display: false },
                tooltip: { callbacks: { label: ctx => ` ${ctx.parsed.x.toLocaleString('pt-BR')} µs` } }
              },
              scales: {
                x: { beginAtZero: true, grid: { color: '#1f2d45' }, ticks: { callback: v => v + ' µs' } },
                y: { grid: { display: false } }
              }
            }
          });
        }

        // ── Fetch ────────────────────────────────────────────────────────
        fetch(API_URL)
          .then(r => {
            if (!r.ok) throw new Error(`HTTP ${r.status}`);
            return r.json();
          })
          .then(dados => {
            document.getElementById('loading').style.display = 'none';
            document.getElementById('app').style.display     = 'block';
            render(dados);
          })
          .catch(err => {
            document.getElementById('loading').style.display = 'none';
            const el = document.getElementById('error-msg');
            el.style.display = 'block';
            el.textContent =
              `Erro ao buscar dados do backend: ${err.message}\n` +
              `Verifique se a API está rodando em ${API_URL}`;
          });
        </script>
        </body>
        </html>
                """
        .formatted(json);
  }
}