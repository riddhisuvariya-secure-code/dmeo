module github.com/example/sbom-go-service

go 1.20

require (
    github.com/labstack/echo/v4 v4.11.1
    github.com/spf13/viper v1.17.0
    github.com/jmoiron/sqlx v1.3.5
    github.com/lib/pq v1.10.9
    golang.org/x/crypto v0.21.0
)

require (
    github.com/stretchr/testify v1.8.4 // indirect
)

replace github.com/lib/pq => github.com/lib/pq v1.10.9
