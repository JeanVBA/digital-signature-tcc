Development setup (PostgreSQL via Docker)

1. Start the database and app with a single command (recommended):

```bash
cp .env.example .env
./scripts/dev-up.sh
```

Run in foreground (useful to see logs directly and keep process attached to terminal):

```bash
FOREGROUND=true ./scripts/dev-up.sh
```

By default when `FOREGROUND=true` the script will attempt to stop any background instance that is using the server port (default `8080`) before starting in foreground. You can disable this behavior with:

```bash
AUTO_KILL_BG=false FOREGROUND=true ./scripts/dev-up.sh
```

This script will:
- prefer Docker when the daemon is available, otherwise use Podman (and start the user podman socket);
- bring up the Postgres service (with a configurable host port via `HOST_POSTGRES_PORT`);
- wait until Postgres responds to `pg_isready`;
- start the Spring Boot app in background and write logs to `run.log`.

If you prefer to run the pieces manually:

2. Copy the environment file and start Postgres:

```bash
cp .env.example .env
docker compose up -d
```

3. Verify the DB is healthy:

```bash
docker compose ps
# or
docker compose exec db pg_isready -U ${POSTGRES_USER}
```

4. Run the application (it reads DB settings from env or the `application.properties` defaults):

```bash
# recommended: use the helper that loads .env automatically
./scripts/run-local.sh
```

4. Tests run with an embedded H2 database (no Docker required):

```bash
./mvnw -q clean test
```

## Swagger / OpenAPI

Com o SpringDoc instalado, a documentação dos endpoints está disponível em:

```text
http://localhost:8080/swagger-ui/index.html
```

O JSON do OpenAPI fica em:

```text
http://localhost:8080/v3/api-docs
```

Notes:
- Production databases should be provisioned separately and credentials stored in a secret manager or environment variables.
- The app's `application.properties` reads `SPRING_DATASOURCE_*` env vars if present.

Inicialização do banco de dados
-------------------------------

Este projeto inclui um serviço auxiliar `db-init` no `docker-compose.yml` que verifica a disponibilidade do container Postgres e cria o banco definido em `POSTGRES_DB` caso ele não exista. Use estes passos na primeira vez que subir o ambiente ou quando o banco estiver faltando:

1. Copie o arquivo de ambiente e suba o serviço do banco:

```bash
cp .env.example .env
docker compose up -d db
```

2. Execute o init que cria o banco apenas se estiver ausente:

```bash
docker compose run --rm db-init
```

3. Verifique que o banco foi criado:

```bash
docker compose exec db psql -U ${POSTGRES_USER} -c '\l'
```

Notas sobre volume e scripts de inicialização:
- O serviço `db-init` é idempotente e não remove dados — ele apenas cria o banco se faltar.
- Alternativamente, se você quiser que scripts SQL sejam executados apenas na primeira inicialização do volume, coloque-os em `docker-initdb.d/` e monte esse diretório em `/docker-entrypoint-initdb.d` no serviço `db` (observe que esses scripts só são executados quando o volume do Postgres é criado pela primeira vez).
- Se o volume já existir e você quiser reaplicar a inicialização automática, remova o volume e recrie os containers (ATENÇÃO: isso apagará dados do banco):

```bash
docker compose down -v
docker compose up -d
```

Se preferir que eu aplique a opção alternativa com `docker-initdb.d` ou documente exemplos de scripts SQL, me avise.
