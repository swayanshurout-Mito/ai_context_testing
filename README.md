# Clean Architecture Template

This template is built using Clean Architecture principles and leverages the `josysy-commons` packages. It also includes Prizma for database interaction.

## Project Structure

.
├── ...
├── test                    # Test files (alternatively `spec` or `tests`)
│   ├── benchmarks          # Load and stress tests
│   ├── integration         # End-to-end, integration tests (alternatively `e2e`)
│   └── unit                # Unit tests
└── ...

Project Template/
├─ .circleci/                 # CircleCI Configuration
│   └─ config.yml             # CircleCI Configuration File
├─ config/                    # Environment Configuration Files
│   ├─ production.yml         # Production Environment Configuration
│   ├─ staging.yml            # Staging Environment Configuration
│   └─ ...                    # Other Environment Configuration Files
├─ src/                       # Source Code
│   ├─ core/                  # Core Layer
│   │   ├─ dtos/              # Data Transfer Objects
│   │   └─ entity/            # Business Entities and Rules
│   ├─ applications/          # Application Layer
│   │   └─ ...                # Use Cases and Orchestrators
│   ├─ adapters/              # Adapters Layer
│   │   ├─ controllers/       # Controllers for REST Endpoints
│   │   ├─ persistence/       # Persistence Layer
│   │   │   ├─ prisma/        # Prisma ORM
│   │   │   │   ├─ dao/       # Data Access Objects for Prisma
│   │   │   │   ├─ models/    # Models and Schemas
│   │   │   │   │   ├─ mysql/ # MySQL Models and Schemas
│   │   │   │   │   └─ mongo/ # MongoDB Models and Schemas
│   │   │   ├─ services/      # Services for Prisma
│   │   │   └─ repositories/  # Repositories (Gateway to ORM/ODM)
│   │   └─ web/               # External API Gateway
├─ node_modules/              # Node.js Modules
├─ package.json               # Node.js Package File
├─ tsconfig.json              # TypeScript Configuration File
└─ README.md                  # Project Documentation



The project is organized into different folders, each serving a specific purpose:

### `.circleci`
- Contains the CircleCI configuration files.
  - `config.yml`: Configuration files for different environments (e.g., Production, Staging).

### `src`
- The main source code directory.

#### `core`
- The innermost layer of Clean Architecture, free from external dependencies.
  - `dtos`: Contains Data Transfer Objects (DTOs) for data exchange.
  - `entity`: Holds all business rules and entities.

#### `applications`
- This layer contains all use cases and is responsible for orchestrating business logic.

#### `adapters`
- This layer acts as an intermediary between the core business and external interfaces.
  - `controllers`: Contains all controllers that handle REST endpoints.

  - `persistence`: Manages gateways, ORM, and ODM interactions.
    - `Prisma`: Contains Prisma ORM related files.
      - `DAO`: Houses all Data Access Objects for Prisma.
      - `models`: Contains both Mongo and MySQL models and schema definitions.
        - `MySQL`: Holds MySQL schema definitions.
        - `Mongo`: Contains MongoDB schema definitions.
    - `service`: Contains services related to Prisma.

  - `repositories`: Manages all repositories, serving as gateways between the ORM/ODM and the application layer.

  - `web`: Acts as a gateway to interact with external APIs.

- **`src/main.ts`**: The entry point of the application.

## Prisma Schema

- **`src/adapters/persistence/prisma/models/`**: Contains Prisma schema files for different database systems.
  - **`src/adapters/persistence/prisma/models/mongo`**: Prisma schema for MongoDB.
    - **`src/adapters/persistence/prisma/models/mongo/schema.prisma`**: The Prisma schema for MongoDB.
  - **`src/adapters/persistence/prisma/models/mysql`**: Prisma schema for MySQL.
    - **`src/adapters/persistence/prisma/models/mysql/schema.prisma`**: The Prisma schema for MySQL.

## Available Scripts

The project's `package.json` includes the following scripts:

- `start`: Launches the application using `ts-node`.
- `build`: Compiles TypeScript files into JavaScript.
- `lint`: Lints the code using ESLint.
- `test`: Executes tests using Jest.

You can modify or add scripts to cater to your development workflow.

## Getting Started

1. Clone the repository using `git clone`.
2. Install dependencies using `npm install`.
3. Configure your database connections as needed in Prisma schema files, check env.example file to create .env file.
4. Utilize the provided scripts for starting, building, testing, and linting

## Installation

```bash
$ npm install
```
#### Generate MySQL Client

```bash
$ npm run prisma:generate:mysql_client
```
#### Generate Mongo Client

```bash
$ npm run prisma:generate:mongo_client
```

#### Generate Mongo Client & Mysql Client together

```bash
npm run prisma:generate:db_clients
```
## Running the app

```bash
# development
$ npm run start

# watch mode
$ npm run start:dev

# production mode
$ npm run start:prod
```

## Test

```bash
# unit tests
$ npm run test

# e2e tests
$ npm run test:e2e

# test coverage
$ npm run test:cov
```

## Stay in touch

- Author -  [Avinash](https://github.com/avinash-iitb)


