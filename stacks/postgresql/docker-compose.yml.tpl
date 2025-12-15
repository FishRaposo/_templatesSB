# Docker Compose for {{PROJECT_NAME}} PostgreSQL Stack
# Generated: {{DATE}}

version: '3.8'

services:
  # PostgreSQL Database
  postgres:
    image: postgres:16-alpine
    container_name: {{PROJECT_NAME}}_postgres
    restart: unless-stopped
    environment:
      POSTGRES_DB: ${DB_NAME:-{{PROJECT_NAME}}}
      POSTGRES_USER: ${DB_USER:-postgres}
      POSTGRES_PASSWORD: ${DB_PASSWORD:-changeme}
      POSTGRES_INITDB_ARGS: "--encoding=UTF-8 --locale=en_US.UTF-8"
    ports:
      - "${DB_PORT:-5432}:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./init:/docker-entrypoint-initdb.d
      - ./postgresql.conf:/etc/postgresql/postgresql.conf
    command: postgres -c config_file=/etc/postgresql/postgresql.conf
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${DB_USER:-postgres}"]
      interval: 10s
      timeout: 5s
      retries: 5

  # PgBouncer Connection Pooler
  pgbouncer:
    image: edoburu/pgbouncer:latest
    container_name: {{PROJECT_NAME}}_pgbouncer
    restart: unless-stopped
    environment:
      DATABASE_URL: "postgres://${DB_USER:-postgres}:${DB_PASSWORD:-changeme}@postgres:5432/${DB_NAME:-{{PROJECT_NAME}}}"
      POOL_MODE: transaction
      MAX_CLIENT_CONN: 1000
      DEFAULT_POOL_SIZE: 25
    ports:
      - "6432:6432"
    depends_on:
      postgres:
        condition: service_healthy

  # pgAdmin Web Interface
  pgadmin:
    image: dpage/pgadmin4:latest
    container_name: {{PROJECT_NAME}}_pgadmin
    restart: unless-stopped
    environment:
      PGADMIN_DEFAULT_EMAIL: ${PGADMIN_EMAIL:-admin@example.com}
      PGADMIN_DEFAULT_PASSWORD: ${PGADMIN_PASSWORD:-admin}
      PGADMIN_CONFIG_SERVER_MODE: 'False'
      PGADMIN_CONFIG_MASTER_PASSWORD_REQUIRED: 'False'
    ports:
      - "${PGADMIN_PORT:-5050}:80"
    volumes:
      - pgadmin_data:/var/lib/pgadmin
    depends_on:
      - postgres

  # PostgreSQL Backup Service
  postgres_backup:
    image: prodrigestivill/postgres-backup-local:16
    container_name: {{PROJECT_NAME}}_backup
    restart: unless-stopped
    environment:
      POSTGRES_HOST: postgres
      POSTGRES_DB: ${DB_NAME:-{{PROJECT_NAME}}}
      POSTGRES_USER: ${DB_USER:-postgres}
      POSTGRES_PASSWORD: ${DB_PASSWORD:-changeme}
      SCHEDULE: "@daily"
      BACKUP_KEEP_DAYS: 7
      BACKUP_KEEP_WEEKS: 4
      BACKUP_KEEP_MONTHS: 6
    volumes:
      - ./backups:/backups
    depends_on:
      postgres:
        condition: service_healthy

volumes:
  postgres_data:
    driver: local
  pgadmin_data:
    driver: local

networks:
  default:
    name: {{PROJECT_NAME}}_network
