# Steps for deployment on the local machine

## Services:
- java_project_ecom
  -- Git: https://github.com/pumbatimon473/java_project_ecom
- java_ecom_auth_service
  -- Git: https://github.com/pumbatimon473/java_ecom_auth_service
- java_ecom_cart_service
  -- Git: https://github.com/pumbatimon473/java_ecom_cart_service
- java_ecom_notification_service
  -- Git: https://github.com/pumbatimon473/java_ecom_notification_service

## Pre-requisites:
- Java 17 or above is required
- MySQL DB must be installed and have the following db schemas created:
	- ecom_auth_service
	- ecom
- Use Docker images for Elasticsearch, Mongo, Redis, Kafka

### Elasticsearch: docker-compose.yml
```yaml
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.9
    container_name: elasticsearch
    environment:
      - discovery.type=single-node
      - ES_JAVA_OPTS=-Xms512m -Xmx512m   # Reduce heap to 512MB
    ports:
      - "9200:9200"
    mem_limit: 1g  # Optional hard limit
```
### Mongo:
docker run --name mongo -p 27017:27017 -d mongo

### Redis:
docker run --name redis -p 6379:6379 -d redis

### Kafka: docker-compose.yml
```yaml
services:
  zookeeper:
    image: zookeeper  # confluentinc/cp-zookeeper:7.4.4
    environment:
      ZOOKEEPER_CLIENT_PORT: 2181
      ZOOKEEPER_TICK_TIME: 2000
    ports:
      - 22181:2181
  
  kafka:
    image: apache/kafka:latest  # bitnami/kafka:latest  # confluentinc/cp-kafka:7.4.4
    depends_on:
      - zookeeper
    ports:
      - 29092:29092
    environment:
      KAFKA_PROCESS_ROLES: controller,broker
      KAFKA_LISTENERS: PLAINTEXT://0.0.0.0:9092,CONTROLLER://0.0.0.0:9093,PLAINTEXT_HOST://0.0.0.0:29092
      KAFKA_CONTROLLER_LISTENER_NAMES: CONTROLLER
      KAFKA_CONTROLLER_QUORUM_VOTERS: 1@localhost:9093
      KAFKA_LISTENER_SECURITY_PROTOCOL_MAP: CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT,PLAINTEXT_HOST:PLAINTEXT
      
      KAFKA_BROKER_ID: 1
      KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://kafka:9092,PLAINTEXT_HOST://localhost:29092
      # KAFKA_LISTENER_SECURITY_PROTOCOL_MAP: PLAINTEXT:PLAINTEXT,PLAINTEXT_HOST:PLAINTEXT
      KAFKA_INTER_BROKER_LISTENER_NAME: PLAINTEXT
      KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1
```
- MongoDB must have the following database created beforehand
    - Database: ecom_cart_service
    - Collection: cart


### 1. Ensure the following environment variables are configured before running the services

#### 1.1 java_ecom_auth_service:

- AUTH_SERVICE_DB_URL	= jdbc:mysql://localhost:3306/ecom_auth_service
- AUTH_SERVICE_DB_USERNAME = admin
- AUTH_SERVICE_DB_PASSWORD = root
- PASS_MIN_LEN = 4
- PASS_MAX_LEN = 12
- PASS_LOWER = false
- PASS_UPPER = false
- PASS_SPECIAL = false
- PASS_DIGIT = false

#### 1.2 java_project_ecom:

- ECOM_DB_URL	= jdbc:mysql://localhost:3306/ecom
- ECOM_DB_USERNAME = admin
- ECOM_DB_PASSWORD = root
- ECOM_APP_BASE_URL =	http://localhost:8080 (NOTE: A public app URL is required for the payment callbacks to work)
- STRIPE_TEST_SECRET_KEY = <your_stripe_secret_key>
- RAZORPAY_TEST_KEY_ID = <your_razorpay_key_id>
- RAZORPAY_TEST_KEY_SECRET = <your_razorpay_secret>
- AUTH_SERVICE_URL = http://localhost:8090
- KAFKA_SERVER = localhost:29092
- ECOM_ES_HOST_AND_PORT = localhost:9200

> NOTE: You can obtain a public URL through Ngrok
CMD:
ngrok http http://localhost:8080

#### 1.3 java_ecom_cart_service:

- MONGO_HOST = localhost
- MONGO_PORT = 27017
- MONGO_DB_NAME = ecom_cart_service
- ECOM_APP_URL = http://localhost:8080
- AUTH_SERVICE_HOST = http://localhost:8090
- REDIS_HOST = localhost
- REDIS_PORT = 6379

#### 1.4 java_ecom_notification_service

- SPRING_MAIL_HOST = smtp.gmail.com
- SPRING_MAIL_PORT = 587
- SPRING_MAIL_USERNAME = <your_gamil_id>
- SPRING_MAIL_APP_PASSWORD = <your_gmail_app_password>
- KAFKA_SERVER = localhost:29092

> NOTE:
Generating App Password: https://support.google.com/accounts/answer/185833

# Project Setup
- Once the "auth_service" runs,
	- It creates an admin user with id 1 with standard roles: ADMIN, SELLER
		- You can fetch the basic details of the user through the endpoint: /api/users/basic-info/:id
		- The default password is 1234
	- It also registers the following OAuth clients:
		- "ecom-app": (GrantType: password)
		- "postman": (GrantType: authorization_code)
		> client secret is "secret"
- You can populate dummy product details by running the test "FakeStoreApiClientTest" available in "java_project_ecom"
	- It tries to fetch the product data from the fakestore api.

